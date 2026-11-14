//! Fake transport that holds the synced folder in memory, and its tests.

mod cases;

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use jiff::Timestamp;
use uuid::Uuid;

use super::state_file::{VAULT, WRITER};
use crate::secrets::vaults::Error;
use crate::secrets::vaults::files::FileHash;
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::state_file::{StateFile, StateHash};
use crate::secrets::vaults::sync::transport::{
    FileName, PairingEntry, ReadResult, RequestId, SyncTransport, WatchHandle,
};

/// File of the fake synced folder.
#[derive(Clone, Debug)]
enum FakeFile {
    Local(Vec<u8>),
    /// File that exists and is not local yet, with the bytes it holds once
    /// a download completes, if any.
    Remote(Option<Vec<u8>>),
}

/// Pairing request of the fake synced folder.
#[derive(Clone, Debug)]
struct FakePairing {
    bytes: Vec<u8>,
    modified: Timestamp,
    /// Size listed for the request, the byte count unless set.
    size: u64,
}

/// Watch callback of the fake synced folder, fired by a test.
struct FakeWatch {
    id: u64,
    /// Vault of the watch, or `None` for the pairing directory.
    vault_id: Option<Uuid>,
    notify: Arc<Mutex<Box<dyn Fn() + Send>>>,
}

impl fmt::Debug for FakeWatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeWatch")
            .field("id", &self.id)
            .field("vault_id", &self.vault_id)
            .finish_non_exhaustive()
    }
}

/// Function a test runs after each read of a local state file or `key.json`.
#[derive(Clone)]
struct ReadHook(Arc<dyn Fn() + Send + Sync>);

impl fmt::Debug for ReadHook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadHook").finish_non_exhaustive()
    }
}

/// Function a test runs before each write or delete of a vault directory,
/// with the vault id.
#[derive(Clone)]
struct WriteHook(Arc<dyn Fn(Uuid) + Send + Sync>);

impl fmt::Debug for WriteHook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriteHook").finish_non_exhaustive()
    }
}

/// Synced folder in memory. Files are held by vault id, replica, and file
/// name. The folder can be made unavailable, and writes can be made to fail.
#[derive(Debug, Default)]
pub(super) struct FakeTransport {
    inner: Arc<Mutex<FakeFolder>>,
}

#[derive(Debug, Default)]
struct FakeFolder {
    files: BTreeMap<(Uuid, ReplicaId, String), FakeFile>,
    /// File blobs by vault id and name.
    blobs: BTreeMap<(Uuid, FileHash), FakeFile>,
    /// Whether every blob write fails, while other writes succeed.
    failing_blob_writes: bool,
    /// Names of the successful writes of blobs and replica files, in write
    /// order. A blob is `blobs/{blob}`.
    write_log: Vec<String>,
    /// Blobs of the `request_blob_download` calls, in call order.
    blob_downloads: Vec<(Uuid, FileHash)>,
    /// `meta.json` of each vault directory.
    meta: BTreeMap<Uuid, Vec<u8>>,
    pairings: BTreeMap<RequestId, FakePairing>,
    /// Modification time of the pairing requests written next.
    now: Timestamp,
    unavailable: bool,
    failing_writes: bool,
    /// Whether listing the replica directories fails.
    unlistable_replicas: bool,
    /// Replica directories whose listing fails.
    unlistable: Vec<ReplicaId>,
    /// Count of reads of local files.
    reads: usize,
    /// Count of reads of local pairing requests.
    pairing_reads: usize,
    /// Count of successful writes.
    writes: usize,
    /// Count of successful writes and deletes of pairing requests.
    pairing_writes: usize,
    /// Vaults of the `request_download` calls, in call order.
    downloads: Vec<Uuid>,
    watches: Vec<FakeWatch>,
    next_watch: u64,
    read_hook: Option<ReadHook>,
    write_hook: Option<WriteHook>,
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

    /// Remove the file `name` from the directory of `replica`, as another Mac
    /// deletes it.
    pub(super) fn remove(&self, vault_id: Uuid, replica: ReplicaId, name: &str) {
        self.folder()
            .files
            .remove(&(vault_id, replica, name.to_string()));
    }

    /// Mark the file `name` of `replica` as not local yet.
    pub(super) fn put_remote(&self, vault_id: Uuid, replica: ReplicaId, name: &str) {
        self.folder().files.insert(
            (vault_id, replica, name.to_string()),
            FakeFile::Remote(None),
        );
    }

    /// Put the file `name` of `replica` as not local yet, holding `bytes`
    /// once [`Self::complete_downloads`] runs.
    pub(super) fn put_remote_with(
        &self,
        vault_id: Uuid,
        replica: ReplicaId,
        name: &str,
        bytes: &[u8],
    ) {
        self.folder().files.insert(
            (vault_id, replica, name.to_string()),
            FakeFile::Remote(Some(bytes.to_vec())),
        );
    }

    /// Make local each file under vault `vault_id` put with
    /// [`Self::put_remote_with`], as a finished download. Returns the number
    /// of files made local.
    pub(super) fn complete_downloads(&self, vault_id: Uuid) -> usize {
        let mut folder = self.folder();
        let folder = &mut *folder;
        let files = folder
            .files
            .iter_mut()
            .filter(|((v, _, _), _)| *v == vault_id)
            .map(|(_, file)| file);
        let blobs = folder
            .blobs
            .iter_mut()
            .filter(|((v, _), _)| *v == vault_id)
            .map(|(_, file)| file);
        let mut completed = 0;
        for file in files.chain(blobs) {
            if let FakeFile::Remote(Some(bytes)) = file {
                *file = FakeFile::Local(std::mem::take(bytes));
                completed += 1;
            }
        }
        completed
    }

    /// Put `bytes` as blob `blob` of vault `vault_id`, with any bytes.
    pub(super) fn put_blob(&self, vault_id: Uuid, blob: FileHash, bytes: &[u8]) {
        self.folder()
            .blobs
            .insert((vault_id, blob), FakeFile::Local(bytes.to_vec()));
    }

    /// Put blob `blob` of vault `vault_id` as not local yet, holding `bytes`
    /// once [`Self::complete_downloads`] runs, if set.
    pub(super) fn put_blob_remote(&self, vault_id: Uuid, blob: FileHash, bytes: Option<&[u8]>) {
        self.folder().blobs.insert(
            (vault_id, blob),
            FakeFile::Remote(bytes.map(<[u8]>::to_vec)),
        );
    }

    /// Bytes of blob `blob` of vault `vault_id`, local or not yet local.
    pub(super) fn blob(&self, vault_id: Uuid, blob: FileHash) -> Option<Vec<u8>> {
        match self.folder().blobs.get(&(vault_id, blob))? {
            FakeFile::Local(bytes) => Some(bytes.clone()),
            FakeFile::Remote(bytes) => bytes.clone(),
        }
    }

    /// Blobs of vault `vault_id`, local or not.
    pub(super) fn blob_names(&self, vault_id: Uuid) -> Vec<FileHash> {
        self.folder()
            .blobs
            .keys()
            .filter(|(v, _)| *v == vault_id)
            .map(|(_, blob)| *blob)
            .collect()
    }

    /// Remove blob `blob` of vault `vault_id`, as a folder that lost it.
    pub(super) fn remove_blob(&self, vault_id: Uuid, blob: FileHash) {
        self.folder().blobs.remove(&(vault_id, blob));
    }

    /// Make every blob write fail, while other writes succeed.
    pub(super) fn set_failing_blob_writes(&self, failing: bool) {
        self.folder().failing_blob_writes = failing;
    }

    /// Names of the successful writes of blobs and replica files, in write
    /// order. A blob is `blobs/{blob}`.
    pub(super) fn write_log(&self) -> Vec<String> {
        self.folder().write_log.clone()
    }

    /// Blobs of the `request_blob_download` calls, in call order.
    pub(super) fn blob_download_requests(&self) -> Vec<(Uuid, FileHash)> {
        self.folder().blob_downloads.clone()
    }

    /// Vaults of the `request_download` calls, in call order.
    pub(super) fn download_requests(&self) -> Vec<Uuid> {
        self.folder().downloads.clone()
    }

    /// Put `bytes` as `meta.json` of the directory of vault `vault_id`.
    pub(super) fn put_meta(&self, vault_id: Uuid, bytes: &[u8]) {
        self.folder().meta.insert(vault_id, bytes.to_vec());
    }

    /// `meta.json` of the directory of vault `vault_id`, if any.
    pub(super) fn meta(&self, vault_id: Uuid) -> Option<Vec<u8>> {
        self.folder().meta.get(&vault_id).cloned()
    }

    /// Remove `meta.json` of the directory of vault `vault_id`, as a folder
    /// that has not received it yet.
    pub(super) fn remove_meta(&self, vault_id: Uuid) {
        self.folder().meta.remove(&vault_id);
    }

    /// Put the pairing request `bytes` at `request`, modified at the time of
    /// [`Self::set_now`].
    pub(super) fn put_pairing(&self, request: RequestId, bytes: &[u8]) {
        let mut folder = self.folder();
        let pairing = FakePairing {
            bytes: bytes.to_vec(),
            modified: folder.now,
            size: bytes.len() as u64,
        };
        folder.pairings.insert(request, pairing);
    }

    /// Bytes of the pairing request `request`, if any.
    pub(super) fn pairing(&self, request: RequestId) -> Option<Vec<u8>> {
        self.folder()
            .pairings
            .get(&request)
            .map(|pairing| pairing.bytes.clone())
    }

    /// Set the modification time of the pairing requests written next.
    pub(super) fn set_now(&self, now: Timestamp) {
        self.folder().now = now;
    }

    /// Set the modification time listed for the pairing request `request`.
    pub(super) fn set_pairing_modified(&self, request: RequestId, modified: Timestamp) {
        if let Some(pairing) = self.folder().pairings.get_mut(&request) {
            pairing.modified = modified;
        }
    }

    /// Set the size listed for the pairing request `request`, whatever its
    /// bytes.
    pub(super) fn set_pairing_size(&self, request: RequestId, size: u64) {
        if let Some(pairing) = self.folder().pairings.get_mut(&request) {
            pairing.size = size;
        }
    }

    /// Make every call fail, as a folder that is missing or unreachable.
    pub(super) fn set_unavailable(&self, unavailable: bool) {
        self.folder().unavailable = unavailable;
    }

    /// Make every write and delete fail.
    pub(super) fn set_failing_writes(&self, failing: bool) {
        self.folder().failing_writes = failing;
    }

    /// Make the listing of the replica directories fail.
    pub(super) fn set_unlistable_replicas(&self, unlistable: bool) {
        self.folder().unlistable_replicas = unlistable;
    }

    /// Make the listing of the directory of `replica` fail.
    pub(super) fn set_unlistable(&self, replica: ReplicaId, unlistable: bool) {
        let mut folder = self.folder();
        folder.unlistable.retain(|r| *r != replica);
        if unlistable {
            folder.unlistable.push(replica);
        }
    }

    /// Count of reads that returned a local file.
    pub(super) fn reads(&self) -> usize {
        self.folder().reads
    }

    /// Run `hook` after each read that returns a local file of a replica
    /// directory, with the folder unlocked.
    pub(super) fn on_read(&self, hook: impl Fn() + Send + Sync + 'static) {
        self.folder().read_hook = Some(ReadHook(Arc::new(hook)));
    }

    /// Run `hook` with the vault id before each write or delete of a vault
    /// directory, with the folder unlocked. Pairing requests do not run it.
    pub(super) fn on_write(&self, hook: impl Fn(Uuid) + Send + Sync + 'static) {
        self.folder().write_hook = Some(WriteHook(Arc::new(hook)));
    }

    /// Run the write hook for vault `vault_id`, if any.
    fn run_write_hook(&self, vault_id: Uuid) {
        let hook = self.folder().write_hook.clone();
        if let Some(WriteHook(hook)) = hook {
            hook(vault_id);
        }
    }

    /// Count of reads that returned a local pairing request.
    pub(super) fn pairing_reads(&self) -> usize {
        self.folder().pairing_reads
    }

    /// Count of writes and deletes of pairing requests that succeeded.
    pub(super) fn pairing_writes(&self) -> usize {
        self.folder().pairing_writes
    }

    /// Count of writes that succeeded.
    pub(super) fn writes(&self) -> usize {
        self.folder().writes
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

    /// Call each watch of vault `vault_id`, as a change under the vault.
    /// Returns the number of watches called.
    pub(super) fn fire_watch(&self, vault_id: Uuid) -> usize {
        self.fire(Some(vault_id))
    }

    /// Call each watch of the pairing directory. Returns the number of
    /// watches called.
    pub(super) fn fire_pairing_watch(&self) -> usize {
        self.fire(None)
    }

    /// Number of watches that have not ended.
    pub(super) fn watch_count(&self) -> usize {
        self.folder().watches.len()
    }

    /// Call each watch of `vault_id`, with the folder unlocked, so a
    /// callback can call the transport.
    fn fire(&self, vault_id: Option<Uuid>) -> usize {
        let notifies: Vec<_> = self
            .folder()
            .watches
            .iter()
            .filter(|watch| watch.vault_id == vault_id)
            .map(|watch| watch.notify.clone())
            .collect();
        for notify in &notifies {
            (notify.lock().unwrap())();
        }
        notifies.len()
    }

    /// Add a watch of `vault_id` that ends when its handle drops.
    fn add_watch(&self, vault_id: Option<Uuid>, notify: Box<dyn Fn() + Send>) -> WatchHandle {
        let mut folder = self.folder();
        folder.next_watch += 1;
        let id = folder.next_watch;
        folder.watches.push(FakeWatch {
            id,
            vault_id,
            notify: Arc::new(Mutex::new(notify)),
        });
        let inner = self.inner.clone();
        WatchHandle::new(move || {
            inner.lock().unwrap().watches.retain(|watch| watch.id != id);
        })
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
        if folder.unlistable_replicas {
            return Err(Error::SyncTransportError("listing failed".to_string()));
        }
        let mut replicas: Vec<ReplicaId> = folder
            .files
            .keys()
            .filter(|(v, _, _)| *v == vault_id)
            .map(|(_, replica, _)| *replica)
            .collect();
        replicas.dedup();
        Ok(replicas)
    }

    fn list_vaults(&self) -> Result<Vec<Uuid>, Error> {
        let folder = self.folder();
        Self::check_available(&folder)?;
        let mut vaults: Vec<Uuid> = folder
            .files
            .keys()
            .map(|(vault_id, _, _)| *vault_id)
            .chain(folder.meta.keys().copied())
            .collect();
        vaults.sort();
        vaults.dedup();
        Ok(vaults)
    }

    fn list_states(&self, vault_id: Uuid, replica: ReplicaId) -> Result<Vec<StateHash>, Error> {
        let folder = self.folder();
        Self::check_available(&folder)?;
        if folder.unlistable.contains(&replica) {
            return Err(Error::SyncTransportError("listing failed".to_string()));
        }
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
            Some(FakeFile::Remote(_)) => ReadResult::Remote,
            Some(FakeFile::Local(bytes)) => ReadResult::Local(bytes.clone()),
        };
        let hook = match &result {
            ReadResult::Local(_) => {
                folder.reads += 1;
                folder.read_hook.clone()
            },
            _ => None,
        };
        drop(folder);
        if let Some(ReadHook(hook)) = hook {
            hook();
        }
        Ok(result)
    }

    fn is_local(&self, vault_id: Uuid, replica: ReplicaId, name: FileName) -> Result<bool, Error> {
        let folder = self.folder();
        Self::check_available(&folder)?;
        let key = (vault_id, replica, name.file_name(vault_id));
        Ok(matches!(folder.files.get(&key), Some(FakeFile::Local(_))))
    }

    fn read_meta(&self, vault_id: Uuid) -> Result<ReadResult, Error> {
        let folder = self.folder();
        Self::check_available(&folder)?;
        Ok(match folder.meta.get(&vault_id) {
            None => ReadResult::Missing,
            Some(bytes) => ReadResult::Local(bytes.clone()),
        })
    }

    fn write_meta(&self, vault_id: Uuid, data: &[u8]) -> Result<(), Error> {
        self.run_write_hook(vault_id);
        let mut folder = self.folder();
        Self::check_writable(&folder)?;
        folder.meta.insert(vault_id, data.to_vec());
        folder.writes += 1;
        Ok(())
    }

    fn write_own(
        &self,
        vault_id: Uuid,
        replica: ReplicaId,
        name: FileName,
        data: &[u8],
    ) -> Result<(), Error> {
        self.run_write_hook(vault_id);
        let mut folder = self.folder();
        Self::check_writable(&folder)?;
        let key = (vault_id, replica, name.file_name(vault_id));
        folder.write_log.push(key.2.clone());
        folder.files.insert(key, FakeFile::Local(data.to_vec()));
        folder.writes += 1;
        Ok(())
    }

    fn delete_own(&self, vault_id: Uuid, replica: ReplicaId, name: FileName) -> Result<(), Error> {
        self.run_write_hook(vault_id);
        let mut folder = self.folder();
        Self::check_writable(&folder)?;
        folder
            .files
            .remove(&(vault_id, replica, name.file_name(vault_id)));
        Ok(())
    }

    fn delete_replica(&self, vault_id: Uuid, replica: ReplicaId) -> Result<(), Error> {
        self.run_write_hook(vault_id);
        let mut folder = self.folder();
        Self::check_writable(&folder)?;
        folder
            .files
            .retain(|(v, r, _), _| !(*v == vault_id && *r == replica));
        Ok(())
    }

    fn request_download(&self, vault_id: Uuid) -> Result<(), Error> {
        let mut folder = self.folder();
        Self::check_available(&folder)?;
        folder.downloads.push(vault_id);
        Ok(())
    }

    fn watch(&self, vault_id: Uuid, notify: Box<dyn Fn() + Send>) -> Option<WatchHandle> {
        Some(self.add_watch(Some(vault_id), notify))
    }

    fn list_pairings(&self) -> Result<Vec<PairingEntry>, Error> {
        let folder = self.folder();
        Self::check_available(&folder)?;
        Ok(folder
            .pairings
            .iter()
            .map(|(id, pairing)| PairingEntry {
                id: *id,
                modified: pairing.modified,
                size: pairing.size,
            })
            .collect())
    }

    fn read_pairing(&self, request: RequestId) -> Result<ReadResult, Error> {
        let mut folder = self.folder();
        Self::check_available(&folder)?;
        let result = match folder.pairings.get(&request) {
            None => ReadResult::Missing,
            Some(pairing) => ReadResult::Local(pairing.bytes.clone()),
        };
        if matches!(result, ReadResult::Local(_)) {
            folder.pairing_reads += 1;
        }
        Ok(result)
    }

    fn write_pairing(&self, request: RequestId, data: &[u8]) -> Result<(), Error> {
        let mut folder = self.folder();
        Self::check_writable(&folder)?;
        let pairing = FakePairing {
            bytes: data.to_vec(),
            modified: folder.now,
            size: data.len() as u64,
        };
        folder.pairings.insert(request, pairing);
        folder.writes += 1;
        folder.pairing_writes += 1;
        Ok(())
    }

    fn delete_pairing(&self, request: RequestId) -> Result<(), Error> {
        let mut folder = self.folder();
        Self::check_writable(&folder)?;
        folder.pairings.remove(&request);
        folder.pairing_writes += 1;
        Ok(())
    }

    fn watch_pairings(&self, notify: Box<dyn Fn() + Send>) -> Option<WatchHandle> {
        Some(self.add_watch(None, notify))
    }

    fn list_blobs(&self, vault_id: Uuid) -> Result<Vec<FileHash>, Error> {
        let folder = self.folder();
        Self::check_available(&folder)?;
        Ok(folder
            .blobs
            .keys()
            .filter(|(v, _)| *v == vault_id)
            .map(|(_, blob)| *blob)
            .collect())
    }

    fn list_blob_sizes(&self, vault_id: Uuid) -> Result<Vec<(FileHash, u64)>, Error> {
        let folder = self.folder();
        Self::check_available(&folder)?;
        Ok(folder
            .blobs
            .iter()
            .filter(|((v, _), _)| *v == vault_id)
            .map(|((_, blob), file)| {
                let size = match file {
                    FakeFile::Local(bytes) | FakeFile::Remote(Some(bytes)) => bytes.len(),
                    FakeFile::Remote(None) => 0,
                };
                (*blob, size as u64)
            })
            .collect())
    }

    fn read_blob(&self, vault_id: Uuid, blob: FileHash) -> Result<ReadResult, Error> {
        let mut folder = self.folder();
        Self::check_available(&folder)?;
        let result = match folder.blobs.get(&(vault_id, blob)) {
            None => ReadResult::Missing,
            Some(FakeFile::Remote(_)) => ReadResult::Remote,
            Some(FakeFile::Local(bytes)) => ReadResult::Local(bytes.clone()),
        };
        if matches!(result, ReadResult::Local(_)) {
            folder.reads += 1;
        }
        Ok(result)
    }

    fn write_blob(&self, vault_id: Uuid, blob: FileHash, data: &[u8]) -> Result<(), Error> {
        self.run_write_hook(vault_id);
        let mut folder = self.folder();
        Self::check_writable(&folder)?;
        if folder.failing_blob_writes {
            return Err(Error::SyncTransportError("blob write failed".to_string()));
        }
        if folder.blobs.contains_key(&(vault_id, blob)) {
            return Ok(());
        }
        folder
            .blobs
            .insert((vault_id, blob), FakeFile::Local(data.to_vec()));
        folder.write_log.push(format!("blobs/{blob}"));
        folder.writes += 1;
        Ok(())
    }

    fn is_blob_local(&self, vault_id: Uuid, blob: FileHash) -> Result<bool, Error> {
        let folder = self.folder();
        Self::check_available(&folder)?;
        Ok(matches!(
            folder.blobs.get(&(vault_id, blob)),
            Some(FakeFile::Local(_))
        ))
    }

    fn delete_blob(&self, vault_id: Uuid, blob: FileHash) -> Result<(), Error> {
        self.run_write_hook(vault_id);
        let mut folder = self.folder();
        Self::check_writable(&folder)?;
        folder.blobs.remove(&(vault_id, blob));
        Ok(())
    }

    fn request_blob_download(&self, vault_id: Uuid, blob: FileHash) -> Result<(), Error> {
        let mut folder = self.folder();
        Self::check_available(&folder)?;
        folder.blob_downloads.push((vault_id, blob));
        Ok(())
    }
}

/// Synced folder under test, with the hooks of the shared transport tests.
/// The tests run against [`FakeTransport`] here, and against the folder
/// transport in `sync/tests/folder.rs`.
pub(super) trait SyncedFolder {
    fn transport(&self) -> &dyn SyncTransport;
    /// Put `bytes` at `name` in the directory of `replica`, with any name.
    fn put(&self, vault_id: Uuid, replica: ReplicaId, name: &str, bytes: &[u8]);
    /// Put the file `name` of `replica` as not local yet, holding `bytes`
    /// once a download completes, if set.
    fn put_not_local(&self, vault_id: Uuid, replica: ReplicaId, name: &str, bytes: Option<&[u8]>);
    /// Make local each file under vault `vault_id` put with bytes by
    /// [`Self::put_not_local`]. Returns the number of files made local.
    fn complete_downloads(&self, vault_id: Uuid) -> usize;
    /// Vaults of the `request_download` calls, in call order.
    fn download_requests(&self) -> Vec<Uuid>;
    /// Count of reads that returned a local file.
    fn reads(&self) -> usize;
    /// Make every call fail, as a folder that is missing or unreachable.
    fn set_unavailable(&self, unavailable: bool);
    /// Make every write and delete fail.
    fn set_failing_writes(&self, failing: bool);
    /// File names in the directory of `replica`.
    fn names(&self, vault_id: Uuid, replica: ReplicaId) -> Vec<String>;
    /// `meta.json` of the directory of vault `vault_id`, if any.
    fn meta(&self, vault_id: Uuid) -> Option<Vec<u8>>;

    /// Put the state file `bytes` in the directory of `replica`, named by
    /// the hash of its bytes. Returns the hash.
    fn put_state(&self, vault_id: Uuid, replica: ReplicaId, bytes: &[u8]) -> StateHash {
        let hash = StateHash::of(bytes);
        self.put(vault_id, replica, &StateFile::name(vault_id, hash), bytes);
        hash
    }
}

impl SyncedFolder for FakeTransport {
    fn transport(&self) -> &dyn SyncTransport {
        self
    }

    fn put(&self, vault_id: Uuid, replica: ReplicaId, name: &str, bytes: &[u8]) {
        FakeTransport::put(self, vault_id, replica, name, bytes);
    }

    fn put_not_local(&self, vault_id: Uuid, replica: ReplicaId, name: &str, bytes: Option<&[u8]>) {
        match bytes {
            Some(bytes) => self.put_remote_with(vault_id, replica, name, bytes),
            None => self.put_remote(vault_id, replica, name),
        }
    }

    fn complete_downloads(&self, vault_id: Uuid) -> usize {
        FakeTransport::complete_downloads(self, vault_id)
    }

    fn download_requests(&self) -> Vec<Uuid> {
        FakeTransport::download_requests(self)
    }

    fn reads(&self) -> usize {
        FakeTransport::reads(self)
    }

    fn set_unavailable(&self, unavailable: bool) {
        FakeTransport::set_unavailable(self, unavailable);
    }

    fn set_failing_writes(&self, failing: bool) {
        FakeTransport::set_failing_writes(self, failing);
    }

    fn names(&self, vault_id: Uuid, replica: ReplicaId) -> Vec<String> {
        FakeTransport::names(self, vault_id, replica)
    }

    fn meta(&self, vault_id: Uuid) -> Option<Vec<u8>> {
        FakeTransport::meta(self, vault_id)
    }
}

pub(super) fn reads_only_exact_state_file_names(folder: &dyn SyncedFolder) {
    let transport = folder.transport();
    let hash = folder.put_state(VAULT, WRITER, b"state");
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
        folder.put(VAULT, WRITER, &planted, b"planted");
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

pub(super) fn returns_remote_for_file_not_yet_local(folder: &dyn SyncedFolder) {
    let transport = folder.transport();
    let hash = StateHash::of(b"state");
    folder.put_not_local(VAULT, WRITER, &StateFile::name(VAULT, hash), None);

    assert_eq!(transport.list_states(VAULT, WRITER).unwrap(), vec![hash]);
    assert_eq!(
        transport
            .read(VAULT, WRITER, FileName::State(hash))
            .unwrap(),
        ReadResult::Remote
    );
    assert_eq!(folder.reads(), 0);
}

pub(super) fn tells_local_file_from_one_not_local_or_missing_without_read(
    folder: &dyn SyncedFolder,
) {
    let transport = folder.transport();
    let local = folder.put_state(VAULT, WRITER, b"local");
    let remote = StateHash::of(b"remote");
    folder.put_not_local(VAULT, WRITER, &StateFile::name(VAULT, remote), None);

    let is_local = |hash| {
        transport
            .is_local(VAULT, WRITER, FileName::State(hash))
            .unwrap()
    };
    assert!(is_local(local));
    assert!(!is_local(remote));
    assert!(!is_local(StateHash::of(b"absent")));
    assert_eq!(folder.reads(), 0);

    folder.set_unavailable(true);
    assert!(
        transport
            .is_local(VAULT, WRITER, FileName::State(local))
            .is_err()
    );
}

pub(super) fn writes_and_deletes_own_files_and_fails_while_unavailable(folder: &dyn SyncedFolder) {
    let transport = folder.transport();
    let hash = StateHash::of(b"state");
    let name = FileName::State(hash);
    transport.write_own(VAULT, WRITER, name, b"state").unwrap();
    assert_eq!(transport.list_replicas(VAULT).unwrap(), vec![WRITER]);
    assert_eq!(folder.names(VAULT, WRITER), vec![name.file_name(VAULT)]);

    folder.set_failing_writes(true);
    assert!(transport.delete_own(VAULT, WRITER, name).is_err());
    assert!(
        transport
            .write_own(VAULT, WRITER, FileName::Key, b"{}")
            .is_err()
    );
    assert!(transport.list_states(VAULT, WRITER).is_ok());
    folder.set_failing_writes(false);

    folder.set_unavailable(true);
    assert!(transport.list_replicas(VAULT).is_err());
    assert!(transport.list_states(VAULT, WRITER).is_err());
    assert!(transport.read(VAULT, WRITER, name).is_err());
    folder.set_unavailable(false);

    transport.delete_own(VAULT, WRITER, name).unwrap();
    assert!(folder.names(VAULT, WRITER).is_empty());
}

/// Request id `n`.
pub(super) fn request(n: u128) -> RequestId {
    RequestId(Uuid::from_u128(n))
}

pub(super) fn lists_vaults_and_reads_and_writes_meta(folder: &dyn SyncedFolder) {
    let transport = folder.transport();
    let other = Uuid::from_u128(0x200);
    assert_eq!(transport.read_meta(VAULT).unwrap(), ReadResult::Missing);

    transport.write_meta(VAULT, b"meta").unwrap();
    folder.put_state(other, WRITER, b"state");

    assert_eq!(transport.list_vaults().unwrap(), vec![VAULT, other]);
    assert_eq!(
        transport.read_meta(VAULT).unwrap(),
        ReadResult::Local(b"meta".to_vec())
    );
    assert_eq!(folder.meta(VAULT), Some(b"meta".to_vec()));
    // `meta.json` is not a file of a replica directory.
    assert!(transport.list_replicas(VAULT).unwrap().is_empty());

    folder.set_failing_writes(true);
    assert!(transport.write_meta(VAULT, b"other").is_err());
    folder.set_unavailable(true);
    assert!(transport.list_vaults().is_err());
    assert!(transport.read_meta(VAULT).is_err());
}

pub(super) fn deletes_replica_directory_and_leaves_others(folder: &dyn SyncedFolder) {
    let transport = folder.transport();
    let peer = ReplicaId(Uuid::from_u128(2));
    folder.put_state(VAULT, WRITER, b"own");
    transport
        .write_own(VAULT, WRITER, FileName::Key, b"{}")
        .unwrap();
    folder.put_state(VAULT, peer, b"peer");

    folder.set_failing_writes(true);
    assert!(transport.delete_replica(VAULT, WRITER).is_err());
    folder.set_failing_writes(false);
    transport.delete_replica(VAULT, WRITER).unwrap();

    assert_eq!(transport.list_replicas(VAULT).unwrap(), vec![peer]);
    assert!(folder.names(VAULT, WRITER).is_empty());
    assert_eq!(folder.names(VAULT, peer).len(), 1);
}

pub(super) fn records_download_requests_and_makes_remote_files_local(folder: &dyn SyncedFolder) {
    let transport = folder.transport();
    let hash = StateHash::of(b"state");
    let name = StateFile::name(VAULT, hash);
    folder.put_not_local(VAULT, WRITER, &name, Some(b"state"));
    let pending = StateFile::name(VAULT, StateHash::of(b"pending"));
    folder.put_not_local(VAULT, WRITER, &pending, None);

    transport.request_download(VAULT).unwrap();
    assert_eq!(folder.download_requests(), vec![VAULT]);
    // A request does not wait, so the file is still remote.
    assert_eq!(
        transport
            .read(VAULT, WRITER, FileName::State(hash))
            .unwrap(),
        ReadResult::Remote
    );

    assert_eq!(folder.complete_downloads(VAULT), 1);
    assert_eq!(
        transport
            .read(VAULT, WRITER, FileName::State(hash))
            .unwrap(),
        ReadResult::Local(b"state".to_vec())
    );
    assert_eq!(
        transport
            .read(VAULT, WRITER, FileName::State(StateHash::of(b"pending")))
            .unwrap(),
        ReadResult::Remote
    );

    folder.set_unavailable(true);
    assert!(transport.request_download(VAULT).is_err());
    assert_eq!(folder.download_requests(), vec![VAULT]);
}
