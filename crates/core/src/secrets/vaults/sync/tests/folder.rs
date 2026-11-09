//! Local folder transport with `PlainIo` and `CoordinatedIo`, against a temp
//! directory, and the transaction through it.

use std::fs::{self, File};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

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
use crate::secrets::vaults::sync::transport::folder::watch::FolderWatch;
use crate::secrets::vaults::sync::transport::{
    FileName, MAX_PAIRING_SIZE, PairingEntry, ReadResult, RequestId, SyncTransport, SyncTransports,
    TransportRoot,
};

mod io;
mod transactions;
mod watch;

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
