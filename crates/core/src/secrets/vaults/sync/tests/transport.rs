//! Fake transport that holds the synced folder in memory, and its tests.

use std::collections::BTreeMap;
use std::sync::Mutex;

use uuid::Uuid;

use super::state_file::{VAULT, WRITER};
use crate::secrets::vaults::Error;
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::state_file::{StateFile, StateHash};
use crate::secrets::vaults::sync::transport::{FileName, ReadResult, SyncTransport};

/// File of the fake synced folder.
#[derive(Clone, Debug)]
enum FakeFile {
    Local(Vec<u8>),
    /// File that exists and is not local yet.
    Remote,
}

/// Synced folder in memory. Files are held by vault id, replica, and file
/// name. The folder can be made unavailable, and writes can be made to fail.
#[derive(Debug, Default)]
pub(super) struct FakeTransport {
    inner: Mutex<FakeFolder>,
}

#[derive(Debug, Default)]
struct FakeFolder {
    files: BTreeMap<(Uuid, ReplicaId, String), FakeFile>,
    unavailable: bool,
    failing_writes: bool,
    /// Count of reads of local files.
    reads: usize,
}

impl FakeTransport {
    fn folder(&self) -> std::sync::MutexGuard<'_, FakeFolder> {
        self.inner.lock().unwrap()
    }

    /// Put `bytes` at `name` in the directory of `replica`, with any name.
    pub(super) fn put(&self, vault_id: Uuid, replica: ReplicaId, name: &str, bytes: &[u8]) {
        self.folder().files.insert(
            (vault_id, replica, name.to_string()),
            FakeFile::Local(bytes.to_vec()),
        );
    }

    /// Put the state file `bytes` in the directory of `replica`, named by
    /// the hash of its bytes. Returns the hash.
    pub(super) fn put_state(&self, vault_id: Uuid, replica: ReplicaId, bytes: &[u8]) -> StateHash {
        let hash = StateHash::of(bytes);
        self.put(vault_id, replica, &StateFile::name(vault_id, hash), bytes);
        hash
    }

    /// Mark the file `name` of `replica` as not local yet.
    pub(super) fn put_remote(&self, vault_id: Uuid, replica: ReplicaId, name: &str) {
        self.folder()
            .files
            .insert((vault_id, replica, name.to_string()), FakeFile::Remote);
    }

    /// Make every call fail, as a folder that is missing or unreachable.
    pub(super) fn set_unavailable(&self, unavailable: bool) {
        self.folder().unavailable = unavailable;
    }

    /// Make every write and delete fail.
    pub(super) fn set_failing_writes(&self, failing: bool) {
        self.folder().failing_writes = failing;
    }

    /// Count of reads that returned a local file.
    pub(super) fn reads(&self) -> usize {
        self.folder().reads
    }

    /// File names in the directory of `replica`.
    pub(super) fn names(&self, vault_id: Uuid, replica: ReplicaId) -> Vec<String> {
        self.folder()
            .files
            .keys()
            .filter(|(v, r, _)| *v == vault_id && *r == replica)
            .map(|(_, _, name)| name.clone())
            .collect()
    }

    fn check_available(folder: &FakeFolder) -> Result<(), Error> {
        if folder.unavailable {
            return Err(Error::SyncTransportError(
                "folder is unavailable".to_string(),
            ));
        }
        Ok(())
    }

    fn check_writable(folder: &FakeFolder) -> Result<(), Error> {
        Self::check_available(folder)?;
        if folder.failing_writes {
            return Err(Error::SyncTransportError("write failed".to_string()));
        }
        Ok(())
    }
}

impl SyncTransport for FakeTransport {
    fn list_replicas(&self, vault_id: Uuid) -> Result<Vec<ReplicaId>, Error> {
        let folder = self.folder();
        Self::check_available(&folder)?;
        let mut replicas: Vec<ReplicaId> = folder
            .files
            .keys()
            .filter(|(v, _, _)| *v == vault_id)
            .map(|(_, replica, _)| *replica)
            .collect();
        replicas.dedup();
        Ok(replicas)
    }

    fn list_states(&self, vault_id: Uuid, replica: ReplicaId) -> Result<Vec<StateHash>, Error> {
        let folder = self.folder();
        Self::check_available(&folder)?;
        Ok(folder
            .files
            .keys()
            .filter(|(v, r, _)| *v == vault_id && *r == replica)
            .filter_map(|(_, _, name)| FileName::parse_state(vault_id, name))
            .collect())
    }

    fn read(
        &self,
        vault_id: Uuid,
        replica: ReplicaId,
        name: FileName,
    ) -> Result<ReadResult, Error> {
        let mut folder = self.folder();
        Self::check_available(&folder)?;
        let key = (vault_id, replica, name.file_name(vault_id));
        let result = match folder.files.get(&key) {
            None => ReadResult::Missing,
            Some(FakeFile::Remote) => ReadResult::Remote,
            Some(FakeFile::Local(bytes)) => ReadResult::Local(bytes.clone()),
        };
        if matches!(result, ReadResult::Local(_)) {
            folder.reads += 1;
        }
        Ok(result)
    }

    fn write_own(
        &self,
        vault_id: Uuid,
        replica: ReplicaId,
        name: FileName,
        data: &[u8],
    ) -> Result<(), Error> {
        let mut folder = self.folder();
        Self::check_writable(&folder)?;
        let key = (vault_id, replica, name.file_name(vault_id));
        folder.files.insert(key, FakeFile::Local(data.to_vec()));
        Ok(())
    }

    fn delete_own(&self, vault_id: Uuid, replica: ReplicaId, name: FileName) -> Result<(), Error> {
        let mut folder = self.folder();
        Self::check_writable(&folder)?;
        folder
            .files
            .remove(&(vault_id, replica, name.file_name(vault_id)));
        Ok(())
    }
}

#[test]
fn fake_reads_only_exact_state_file_names() {
    let transport = FakeTransport::default();
    let hash = transport.put_state(VAULT, WRITER, b"state");
    let name = StateFile::name(VAULT, hash);
    // Conflict copies in iCloud, Dropbox, and Syncthing naming, another
    // vault id, and an uppercase hash.
    let stem = name.strip_suffix(".apstate").unwrap();
    let other_vault = StateFile::name(Uuid::from_u128(0x200), hash);
    let upper = format!(
        "{}.{}.apstate",
        stem.split('.').next().unwrap(),
        hash.to_string().to_uppercase()
    );
    for planted in [
        format!("{stem} 2.apstate"),
        format!("{stem} (conflicted copy).apstate"),
        format!("{stem}.sync-conflict-20261103-120000-ABCDEFG.apstate"),
        format!("{name}.tmp"),
        other_vault,
        upper,
    ] {
        transport.put(VAULT, WRITER, &planted, b"planted");
    }

    assert_eq!(transport.list_states(VAULT, WRITER).unwrap(), vec![hash]);
    assert_eq!(
        transport
            .read(VAULT, WRITER, FileName::State(hash))
            .unwrap(),
        ReadResult::Local(b"state".to_vec())
    );
    let absent = StateHash::of(b"absent");
    assert_eq!(
        transport
            .read(VAULT, WRITER, FileName::State(absent))
            .unwrap(),
        ReadResult::Missing
    );
}

#[test]
fn fake_returns_remote_for_file_not_yet_local() {
    let transport = FakeTransport::default();
    let hash = StateHash::of(b"state");
    transport.put_remote(VAULT, WRITER, &StateFile::name(VAULT, hash));

    assert_eq!(transport.list_states(VAULT, WRITER).unwrap(), vec![hash]);
    assert_eq!(
        transport
            .read(VAULT, WRITER, FileName::State(hash))
            .unwrap(),
        ReadResult::Remote
    );
    assert_eq!(transport.reads(), 0);
}

#[test]
fn fake_writes_and_deletes_own_files_and_fails_while_unavailable() {
    let transport = FakeTransport::default();
    let hash = StateHash::of(b"state");
    let name = FileName::State(hash);
    transport.write_own(VAULT, WRITER, name, b"state").unwrap();
    assert_eq!(transport.list_replicas(VAULT).unwrap(), vec![WRITER]);
    assert_eq!(transport.names(VAULT, WRITER), vec![name.file_name(VAULT)]);

    transport.set_failing_writes(true);
    assert!(transport.delete_own(VAULT, WRITER, name).is_err());
    assert!(
        transport
            .write_own(VAULT, WRITER, FileName::Key, b"{}")
            .is_err()
    );
    assert!(transport.list_states(VAULT, WRITER).is_ok());
    transport.set_failing_writes(false);

    transport.set_unavailable(true);
    assert!(transport.list_replicas(VAULT).is_err());
    assert!(transport.list_states(VAULT, WRITER).is_err());
    assert!(transport.read(VAULT, WRITER, name).is_err());
    transport.set_unavailable(false);

    transport.delete_own(VAULT, WRITER, name).unwrap();
    assert!(transport.names(VAULT, WRITER).is_empty());
}
