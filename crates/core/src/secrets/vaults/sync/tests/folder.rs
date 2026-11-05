//! Local folder transport with `PlainIo` and `CoordinatedIo`, against a temp
//! directory, and the transaction through it.

use std::fs::{self, File};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use jiff::Timestamp;
use tempfile::TempDir;
use uuid::Uuid;

use super::load::{Fixture, GENERATION, REPLICA};
use super::publish::last_publish;
use super::state_file::{VAULT, WRITER};
use super::transport::{self, SyncedFolder, request};
use super::txn::saved;
use crate::secrets::vaults::Error;
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::storage::txn::AppTransports;
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::local_state::LocalSyncState;
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::state_file::{StateFile, StateHash};
use crate::secrets::vaults::sync::status::{PausedCause, SyncStatus};
use crate::secrets::vaults::sync::transport::folder::FolderTransport;
use crate::secrets::vaults::sync::transport::folder::io::{CoordinatedIo, FolderIo, PlainIo};
use crate::secrets::vaults::sync::transport::{
    FileName, MAX_PAIRING_SIZE, PairingEntry, ReadResult, RequestId, SyncTransport, SyncTransports,
    TransportRoot,
};

/// File access of a test folder.
enum Io {
    Plain(Arc<PlainIo>),
    Coordinated,
}

/// Synced folder in a temp directory, read through a [`FolderTransport`].
struct Folder {
    dir: TempDir,
    root: PathBuf,
    io: Io,
    transport: FolderTransport,
    /// Files put as not local, with the bytes they hold once a download
    /// completes.
    pending: Mutex<Vec<(PathBuf, Option<Vec<u8>>)>>,
}

impl Folder {
    /// Folder read with `PlainIo`, with temp files in a directory beside the
    /// root.
    fn plain() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let temp = dir.path().join("temp");
        fs::create_dir(&temp).unwrap();
        Self::build(dir, Io::Plain(Arc::new(PlainIo::new(temp))))
    }

    /// Folder read with `CoordinatedIo`.
    fn coordinated() -> Self {
        Self::build(tempfile::tempdir().unwrap(), Io::Coordinated)
    }

    /// One folder of each file access.
    fn each() -> [Self; 2] {
        [Self::plain(), Self::coordinated()]
    }

    fn build(dir: TempDir, io: Io) -> Self {
        let root = dir.path().join("Vaults");
        fs::create_dir(&root).unwrap();
        let transport = FolderTransport::new(&root, Self::file_io(&io));
        Self {
            dir,
            root,
            io,
            transport,
            pending: Mutex::default(),
        }
    }

    fn file_io(io: &Io) -> Arc<dyn FolderIo> {
        match io {
            Io::Plain(plain) => plain.clone(),
            Io::Coordinated => Arc::new(CoordinatedIo),
        }
    }

    /// Transport of the folder `root` with the file access of this folder.
    fn transport_at(&self, root: &Path) -> FolderTransport {
        FolderTransport::new(root, Self::file_io(&self.io))
    }

    fn plain_io(&self) -> &PlainIo {
        match &self.io {
            Io::Plain(io) => io,
            Io::Coordinated => panic!("CoordinatedIo cannot mark a file as not local"),
        }
    }

    /// Path of the root while the folder is unavailable.
    fn away(&self) -> PathBuf {
        self.dir.path().join("Vaults.away")
    }

    fn vault_dir(&self, vault_id: Uuid) -> PathBuf {
        self.root.join(ShortId::encode_uuid(vault_id))
    }

    fn replica_dir(&self, vault_id: Uuid, replica: ReplicaId) -> PathBuf {
        self.vault_dir(vault_id)
            .join(ShortId::encode_uuid(replica.0))
    }

    fn pairing_path(&self, request: RequestId) -> PathBuf {
        self.root.join("pairing").join(request.file_name())
    }

    /// Paths of every file and directory under the root, relative to it, in
    /// order.
    fn tree(&self) -> Vec<String> {
        fn walk(dir: &Path, prefix: &str, paths: &mut Vec<String>) {
            for entry in fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                let name = entry.file_name().into_string().unwrap();
                let path = format!("{prefix}{name}");
                if entry.file_type().unwrap().is_dir() {
                    walk(&entry.path(), &format!("{path}/"), paths);
                }
                paths.push(path);
            }
        }
        let mut paths = Vec::new();
        walk(&self.root, "", &mut paths);
        paths.sort();
        paths
    }
}

/// Set the mode of `path` and of every directory under it, if it is a
/// directory. Symlinks are not followed.
fn set_tree_mode(path: &Path, mode: u32) {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return;
    };
    if !meta.is_dir() {
        return;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    for entry in fs::read_dir(path).unwrap() {
        set_tree_mode(&entry.unwrap().path(), mode);
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        // Make every directory writable again, so the temp directory is
        // deleted.
        set_tree_mode(&self.root, 0o755);
        set_tree_mode(&self.away(), 0o755);
    }
}

impl SyncedFolder for Folder {
    fn transport(&self) -> &dyn SyncTransport {
        &self.transport
    }

    /// A name that the file system folds into the name of an existing file,
    /// such as an uppercase hash on a volume that ignores case, is not put,
    /// so the existing file is kept.
    fn put(&self, vault_id: Uuid, replica: ReplicaId, name: &str, bytes: &[u8]) {
        let dir = self.replica_dir(vault_id, replica);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let listed = fs::read_dir(&dir)
            .unwrap()
            .any(|entry| entry.unwrap().file_name() == name);
        if path.exists() && !listed {
            return;
        }
        fs::write(path, bytes).unwrap();
    }

    fn put_not_local(&self, vault_id: Uuid, replica: ReplicaId, name: &str, bytes: Option<&[u8]>) {
        self.put(vault_id, replica, name, b"");
        let path = self.replica_dir(vault_id, replica).join(name);
        self.plain_io().set_remote(&path, true);
        self.pending
            .lock()
            .unwrap()
            .push((path, bytes.map(<[u8]>::to_vec)));
    }

    fn complete_downloads(&self, vault_id: Uuid) -> usize {
        let vault_dir = self.vault_dir(vault_id);
        let mut completed = 0;
        self.pending.lock().unwrap().retain(|(path, bytes)| {
            let Some(bytes) = bytes.as_ref().filter(|_| path.starts_with(&vault_dir)) else {
                return true;
            };
            fs::write(path, bytes).unwrap();
            self.plain_io().set_remote(path, false);
            completed += 1;
            false
        });
        completed
    }

    fn download_requests(&self) -> Vec<Uuid> {
        self.plain_io()
            .downloads()
            .iter()
            .map(|paths| {
                let relative = paths[0].strip_prefix(&self.root).unwrap();
                let vault = relative.components().next().unwrap();
                ShortId::parse_uuid(vault.as_os_str().to_str().unwrap()).unwrap()
            })
            .collect()
    }

    fn reads(&self) -> usize {
        self.plain_io().reads()
    }

    fn set_unavailable(&self, unavailable: bool) {
        if unavailable {
            // Renaming a directory needs write permission on it.
            set_tree_mode(&self.root, 0o755);
            fs::rename(&self.root, self.away()).unwrap();
        } else {
            fs::rename(self.away(), &self.root).unwrap();
        }
    }

    fn set_failing_writes(&self, failing: bool) {
        set_tree_mode(&self.root, if failing { 0o555 } else { 0o755 });
    }

    fn names(&self, vault_id: Uuid, replica: ReplicaId) -> Vec<String> {
        let Ok(entries) = fs::read_dir(self.replica_dir(vault_id, replica)) else {
            return Vec::new();
        };
        let mut names: Vec<String> = entries
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    fn meta(&self, vault_id: Uuid) -> Option<Vec<u8>> {
        fs::read(self.vault_dir(vault_id).join("meta.json")).ok()
    }
}

#[test]
fn plain_io_reads_only_exact_state_file_names() {
    transport::reads_only_exact_state_file_names(&Folder::plain());
}

#[test]
fn coordinated_io_reads_only_exact_state_file_names() {
    transport::reads_only_exact_state_file_names(&Folder::coordinated());
}

#[test]
fn plain_io_tells_local_file_from_one_not_local_or_missing_without_read() {
    transport::tells_local_file_from_one_not_local_or_missing_without_read(&Folder::plain());
}

#[test]
fn plain_io_returns_remote_for_file_not_yet_local() {
    transport::returns_remote_for_file_not_yet_local(&Folder::plain());
}

#[test]
fn plain_io_writes_and_deletes_own_files_and_fails_while_unavailable() {
    transport::writes_and_deletes_own_files_and_fails_while_unavailable(&Folder::plain());
}

#[test]
fn coordinated_io_writes_and_deletes_own_files_and_fails_while_unavailable() {
    transport::writes_and_deletes_own_files_and_fails_while_unavailable(&Folder::coordinated());
}

#[test]
fn plain_io_lists_vaults_and_reads_and_writes_meta() {
    transport::lists_vaults_and_reads_and_writes_meta(&Folder::plain());
}

#[test]
fn coordinated_io_lists_vaults_and_reads_and_writes_meta() {
    transport::lists_vaults_and_reads_and_writes_meta(&Folder::coordinated());
}

#[test]
fn plain_io_deletes_replica_directory_and_leaves_others() {
    transport::deletes_replica_directory_and_leaves_others(&Folder::plain());
}

#[test]
fn coordinated_io_deletes_replica_directory_and_leaves_others() {
    transport::deletes_replica_directory_and_leaves_others(&Folder::coordinated());
}

#[test]
fn plain_io_records_download_requests_and_makes_remote_files_local() {
    transport::records_download_requests_and_makes_remote_files_local(&Folder::plain());
}

#[test]
fn directory_that_is_not_short_id_is_not_listed() {
    for folder in Folder::each() {
        let transport = &folder.transport;
        transport.write_meta(VAULT, b"meta").unwrap();
        transport
            .write_own(VAULT, WRITER, FileName::Key, b"{}")
            .unwrap();
        transport.write_pairing(request(1), b"request").unwrap();
        let outside = folder.dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let other = Uuid::from_u128(0x200);
        for dir in [folder.root.clone(), folder.vault_dir(VAULT)] {
            for name in [
                "notes".to_string(),
                other.hyphenated().to_string(),
                other.simple().to_string(),
                format!("{} 2", ShortId::encode_uuid(other)),
            ] {
                fs::create_dir(dir.join(name)).unwrap();
            }
            // A file and a symlink named by a short id.
            fs::write(dir.join(ShortId::encode_uuid(Uuid::from_u128(0x300))), b"").unwrap();
            symlink(
                &outside,
                dir.join(ShortId::encode_uuid(Uuid::from_u128(0x400))),
            )
            .unwrap();
            fs::write(dir.join(".DS_Store"), b"").unwrap();
        }

        assert_eq!(transport.list_vaults().unwrap(), vec![VAULT]);
        assert_eq!(transport.list_replicas(VAULT).unwrap(), vec![WRITER]);
    }
}

#[test]
fn only_exact_file_forms_are_read() {
    for folder in Folder::each() {
        let transport = &folder.transport;
        transport.write_meta(VAULT, b"meta").unwrap();
        transport
            .write_own(VAULT, WRITER, FileName::Key, b"key")
            .unwrap();
        transport.write_pairing(request(1), b"request").unwrap();
        // Conflict copies in iCloud, Dropbox, and Syncthing naming, temp
        // files, and `.DS_Store`.
        for (dir, stem) in [
            (folder.vault_dir(VAULT), "meta"),
            (folder.replica_dir(VAULT, WRITER), "key"),
        ] {
            for name in [
                format!("{stem} 2.json"),
                format!("{stem} (conflicted copy).json"),
                format!("{stem}.sync-conflict-20261103-120000-ABCDEFG.json"),
                format!("{stem}.json.tmp"),
                ".DS_Store".to_string(),
            ] {
                fs::write(dir.join(name), b"planted").unwrap();
            }
        }
        let id = request(2).0;
        let upper = request(0xab).0.hyphenated().to_string().to_uppercase();
        for name in [
            format!("{} 2.json", id.hyphenated()),
            format!("{}.json", id.simple()),
            format!("{}.json.tmp", id.hyphenated()),
            format!("{upper}.json"),
            "not-a-uuid.json".to_string(),
            ".DS_Store".to_string(),
        ] {
            fs::write(folder.root.join("pairing").join(name), b"planted").unwrap();
        }

        assert_eq!(
            transport.read_meta(VAULT).unwrap(),
            ReadResult::Local(b"meta".to_vec())
        );
        assert_eq!(
            transport.read(VAULT, WRITER, FileName::Key).unwrap(),
            ReadResult::Local(b"key".to_vec())
        );
        assert!(transport.list_states(VAULT, WRITER).unwrap().is_empty());
        let listed: Vec<RequestId> = transport
            .list_pairings()
            .unwrap()
            .iter()
            .map(|entry| entry.id)
            .collect();
        assert_eq!(listed, vec![request(1)]);
        assert_eq!(
            transport.read_pairing(request(1)).unwrap(),
            ReadResult::Local(b"request".to_vec())
        );
        assert_eq!(
            transport.read_pairing(request(2)).unwrap(),
            ReadResult::Missing
        );
    }
}

#[test]
fn pairing_request_larger_than_16_kb_is_listed_with_its_size_and_not_read() {
    for folder in Folder::each() {
        let transport = &folder.transport;
        let largest = vec![b'a'; MAX_PAIRING_SIZE as usize];
        transport.write_pairing(request(1), &largest).unwrap();
        transport
            .write_pairing(request(2), &[b'b'; MAX_PAIRING_SIZE as usize + 1])
            .unwrap();
        let modified = |seconds| SystemTime::UNIX_EPOCH + Duration::from_secs(seconds);
        for (request, seconds) in [(request(1), 1_000), (request(2), 10)] {
            File::options()
                .write(true)
                .open(folder.pairing_path(request))
                .unwrap()
                .set_modified(modified(seconds))
                .unwrap();
        }

        assert_eq!(
            transport.list_pairings().unwrap(),
            vec![
                PairingEntry {
                    id: request(1),
                    modified: Timestamp::from_second(1_000).unwrap(),
                    size: MAX_PAIRING_SIZE,
                },
                PairingEntry {
                    id: request(2),
                    modified: Timestamp::from_second(10).unwrap(),
                    size: MAX_PAIRING_SIZE + 1,
                },
            ]
        );
        assert!(matches!(
            transport.read_pairing(request(2)),
            Err(Error::SyncTransportError(_))
        ));
        assert_eq!(
            transport.read_pairing(request(1)).unwrap(),
            ReadResult::Local(largest)
        );
        if let Io::Plain(io) = &folder.io {
            assert_eq!(io.reads(), 1);
        }
    }
}

#[test]
fn state_file_write_never_overwrites_file_and_key_json_write_replaces_it() {
    for folder in Folder::each() {
        let transport = &folder.transport;
        let name = FileName::State(StateHash::of(b"first"));
        transport.write_own(VAULT, WRITER, name, b"first").unwrap();
        assert!(transport.write_own(VAULT, WRITER, name, b"second").is_err());
        assert_eq!(
            transport.read(VAULT, WRITER, name).unwrap(),
            ReadResult::Local(b"first".to_vec())
        );

        for bytes in [b"one", b"two"] {
            transport
                .write_own(VAULT, WRITER, FileName::Key, bytes)
                .unwrap();
            transport.write_meta(VAULT, bytes).unwrap();
            transport.write_pairing(request(1), bytes).unwrap();
        }
        let two = ReadResult::Local(b"two".to_vec());
        assert_eq!(transport.read(VAULT, WRITER, FileName::Key).unwrap(), two);
        assert_eq!(transport.read_meta(VAULT).unwrap(), two);
        assert_eq!(transport.read_pairing(request(1)).unwrap(), two);
    }
}

#[test]
fn write_leaves_no_file_in_synced_folder_other_than_target() {
    for folder in Folder::each() {
        let transport = &folder.transport;
        let hash = StateHash::of(b"state");
        transport.write_meta(VAULT, b"meta").unwrap();
        transport
            .write_own(VAULT, WRITER, FileName::Key, b"key")
            .unwrap();
        transport
            .write_own(VAULT, WRITER, FileName::State(hash), b"state")
            .unwrap();
        transport.write_pairing(request(1), b"request").unwrap();
        // A failed write leaves no file either.
        assert!(
            transport
                .write_own(VAULT, WRITER, FileName::State(hash), b"other")
                .is_err()
        );

        let vault = ShortId::encode_uuid(VAULT);
        let replica = format!("{vault}/{}", ShortId::encode_uuid(WRITER.0));
        let mut expected = vec![
            "pairing".to_string(),
            format!("pairing/{}", request(1).file_name()),
            vault.clone(),
            format!("{vault}/meta.json"),
            replica.clone(),
            format!("{replica}/key.json"),
            format!("{replica}/{}", StateFile::name(VAULT, hash)),
        ];
        expected.sort();
        assert_eq!(folder.tree(), expected);
        if let Io::Plain(_) = folder.io {
            let temp = fs::read_dir(folder.dir.path().join("temp")).unwrap();
            assert_eq!(temp.count(), 0);
        }
    }
}

#[test]
fn file_marked_as_not_local_is_remote_and_is_not_read() {
    let folder = Folder::plain();
    let transport = &folder.transport;
    let io = folder.plain_io();
    transport.write_meta(VAULT, b"meta").unwrap();
    transport
        .write_own(VAULT, WRITER, FileName::Key, b"key")
        .unwrap();
    transport.write_pairing(request(1), b"request").unwrap();
    let meta = folder.vault_dir(VAULT).join("meta.json");
    let key = folder.replica_dir(VAULT, WRITER).join("key.json");
    for path in [&meta, &key, &folder.pairing_path(request(1))] {
        io.set_remote(path, true);
    }

    assert_eq!(transport.read_meta(VAULT).unwrap(), ReadResult::Remote);
    assert_eq!(
        transport.read(VAULT, WRITER, FileName::Key).unwrap(),
        ReadResult::Remote
    );
    assert_eq!(
        transport.read_pairing(request(1)).unwrap(),
        ReadResult::Remote
    );
    assert_eq!(transport.list_pairings().unwrap().len(), 1);
    assert_eq!(io.reads(), 0);

    transport.request_download(VAULT).unwrap();
    assert_eq!(io.downloads(), vec![vec![meta, key]]);
    assert_eq!(io.reads(), 0);
}

#[test]
fn missing_root_fails_every_call_and_is_not_created() {
    for folder in Folder::each() {
        let missing = folder.dir.path().join("Missing");
        let transport = folder.transport_at(&missing);
        let state = FileName::State(StateHash::of(b"state"));

        assert!(transport.check_root().is_err());
        assert!(transport.list_vaults().is_err());
        assert!(transport.list_replicas(VAULT).is_err());
        assert!(transport.list_states(VAULT, WRITER).is_err());
        assert!(transport.read(VAULT, WRITER, state).is_err());
        assert!(transport.read_meta(VAULT).is_err());
        assert!(transport.write_meta(VAULT, b"meta").is_err());
        assert!(transport.write_own(VAULT, WRITER, state, b"state").is_err());
        assert!(
            transport
                .write_own(VAULT, WRITER, FileName::Key, b"key")
                .is_err()
        );
        assert!(transport.delete_own(VAULT, WRITER, state).is_err());
        assert!(transport.delete_replica(VAULT, WRITER).is_err());
        assert!(transport.request_download(VAULT).is_err());
        assert!(transport.list_pairings().is_err());
        assert!(transport.read_pairing(request(1)).is_err());
        assert!(transport.write_pairing(request(1), b"request").is_err());
        assert!(transport.delete_pairing(request(1)).is_err());
        assert!(!missing.exists());

        // A file in place of the root fails too.
        fs::write(&missing, b"file").unwrap();
        assert!(transport.check_root().is_err());
        assert!(transport.list_vaults().is_err());
    }
}

#[test]
fn folder_transport_has_no_watch() {
    for folder in Folder::each() {
        let transport = &folder.transport;
        assert!(transport.watch(VAULT, Box::new(|| {})).is_none());
        assert!(transport.watch_pairings(Box::new(|| {})).is_none());
    }
}

#[test]
fn symlink_is_not_read_and_no_write_or_delete_reaches_its_target() {
    for folder in Folder::each() {
        let transport = &folder.transport;
        let outside = folder.dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let secret = outside.join("secret");
        fs::write(&secret, b"secret").unwrap();
        let own = folder.replica_dir(VAULT, WRITER);
        fs::create_dir_all(&own).unwrap();
        symlink(&secret, own.join("key.json")).unwrap();
        symlink(&secret, folder.vault_dir(VAULT).join("meta.json")).unwrap();
        let peer = ReplicaId(Uuid::from_u128(2));
        symlink(&outside, folder.replica_dir(VAULT, peer)).unwrap();

        assert_eq!(
            transport.read(VAULT, WRITER, FileName::Key).unwrap(),
            ReadResult::Missing
        );
        assert_eq!(transport.read_meta(VAULT).unwrap(), ReadResult::Missing);
        assert_eq!(transport.list_replicas(VAULT).unwrap(), vec![WRITER]);
        assert!(
            transport
                .write_own(VAULT, WRITER, FileName::Key, b"key")
                .is_err()
        );
        assert!(transport.write_meta(VAULT, b"meta").is_err());
        let state = FileName::State(StateHash::of(b"state"));
        assert!(transport.write_own(VAULT, peer, state, b"state").is_err());

        transport.delete_own(VAULT, WRITER, FileName::Key).unwrap();
        transport.delete_replica(VAULT, peer).unwrap();
        assert_eq!(fs::read(&secret).unwrap(), b"secret");
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 1);
        assert!(!own.join("key.json").exists());
        assert!(!folder.replica_dir(VAULT, peer).exists());
    }
}

#[test]
fn app_transports_resolve_folder_root_once_and_refuse_missing_folder_and_icloud() {
    let dir = tempfile::tempdir().unwrap();
    let transports = AppTransports::default();
    let root = TransportRoot::Folder {
        path: dir.path().to_path_buf(),
    };
    let first = transports.resolve(Some(&root)).unwrap().unwrap();
    let second = transports.resolve(Some(&root)).unwrap().unwrap();
    assert!(Arc::ptr_eq(&first, &second));

    let path = dir.path().join("Missing");
    let missing = TransportRoot::Folder { path: path.clone() };
    assert!(matches!(
        transports.resolve(Some(&missing)),
        Err(Error::SyncTransportError(_))
    ));
    // A root that failed is resolved again.
    fs::create_dir(&path).unwrap();
    assert!(transports.resolve(Some(&missing)).unwrap().is_some());

    assert!(matches!(
        transports.resolve(Some(&TransportRoot::ICloud {})),
        Err(Error::SyncTransportError(_))
    ));
}

/// Synced vault with a valid sync state, whose sidecar holds the root of a
/// folder in a temp directory. The writer of the fixture resolves the root
/// with `AppTransports`, so the transport is a `FolderTransport` with
/// `CoordinatedIo`.
fn synced_in_folder() -> (Fixture, TempDir, PathBuf) {
    let fx = Fixture::synced();
    fx.put_state(GENERATION);
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("Vaults");
    fs::create_dir(&root).unwrap();
    let sidecar = Sidecar {
        transport: Some(TransportRoot::Folder { path: root.clone() }),
        ..Sidecar::default()
    };
    sidecar.save(&fx.root, fx.id()).unwrap();
    (fx, dir, root)
}

/// Own state files of `fx` in the folder `root`, in order.
fn published(root: &Path, fx: &Fixture) -> Vec<StateHash> {
    let dir = root
        .join(ShortId::encode_uuid(fx.id()))
        .join(ShortId::encode_uuid(REPLICA.0));
    let mut hashes: Vec<StateHash> = fs::read_dir(dir)
        .unwrap()
        .filter_map(|entry| {
            let name = entry.unwrap().file_name().into_string().unwrap();
            FileName::parse_state(fx.id(), &name)
        })
        .collect();
    hashes.sort();
    hashes
}

fn staged_bytes(fx: &Fixture) -> Vec<u8> {
    fs::read(LocalSyncState::staged_path(&fx.root, fx.id())).unwrap()
}

#[test]
fn transaction_through_folder_transport_copies_staged_file_and_next_moves_staged_context() {
    let (fx, _dir, root) = synced_in_folder();

    let committed = fx.add_item().unwrap();

    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    let staged = staged_bytes(&fx);
    let hash = StateHash::of(&staged);
    let (local, state) = saved(&fx);
    assert_eq!(local.staged_hash, Some(hash));
    assert_ne!(local.published_context, state.context);
    assert_eq!(last_publish(&fx), Some(hash));
    assert_eq!(published(&root, &fx), vec![hash]);
    let path = root
        .join(ShortId::encode_uuid(fx.id()))
        .join(ShortId::encode_uuid(REPLICA.0))
        .join(StateFile::name(fx.id(), hash));
    assert_eq!(fs::read(path).unwrap(), staged);

    fx.write(|_| Ok(())).unwrap();

    let (local, state) = saved(&fx);
    assert_eq!(local.staged_hash, None);
    assert_eq!(local.published_context, state.context);
    assert_eq!(published(&root, &fx), vec![hash]);
}

#[test]
fn root_removed_while_app_runs_pauses_sync_with_unreachable_and_next_transaction_publishes() {
    let (fx, dir, root) = synced_in_folder();
    fx.add_item().unwrap();
    let first = last_publish(&fx).unwrap();
    let away = dir.path().join("Vaults.away");
    fs::rename(&root, &away).unwrap();

    let committed = fx
        .write(|vh| vh.add_item("second", "Second").map(|_| ()))
        .unwrap();

    assert!(committed.changed);
    let Some(SyncStatus::Paused(causes)) = committed.sync_status else {
        panic!("sync is paused");
    };
    assert!(
        causes
            .iter()
            .any(|cause| matches!(cause, PausedCause::Unreachable { .. }))
    );
    assert_eq!(last_publish(&fx), Some(first));
    assert!(!root.exists());
    let staged = StateHash::of(&staged_bytes(&fx));

    fs::rename(&away, &root).unwrap();
    let committed = fx.write(|_| Ok(())).unwrap();

    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    assert_eq!(last_publish(&fx), Some(staged));
    assert!(published(&root, &fx).contains(&staged));
}

#[test]
fn sidecar_that_fails_to_parse_and_holds_valid_root_keeps_root_and_next_transaction_syncs_through_it()
 {
    let (fx, _dir, root) = synced_in_folder();
    let path = Sidecar::path(&fx.root, fx.id());
    let mut saved: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    saved["unknown"] = 1.into();
    fs::write(&path, saved.to_string()).unwrap();
    let kept = Some(TransportRoot::Folder { path: root.clone() });
    assert_eq!(Sidecar::load(&fx.root, fx.id()).transport, kept);

    let committed = fx.add_item().unwrap();

    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    let hash = last_publish(&fx).unwrap();
    assert_eq!(published(&root, &fx), vec![hash]);
    assert_eq!(Sidecar::load(&fx.root, fx.id()).transport, kept);
}
