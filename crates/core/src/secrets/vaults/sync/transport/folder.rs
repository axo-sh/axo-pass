//! Local folder transport.
//!
//! The synced folder is a folder the user picked, such as a Dropbox,
//! OneDrive, Google Drive, or Syncthing folder, or a network share. Its
//! layout is `{root}/{short_vault_id}/meta.json`,
//! `{root}/{short_vault_id}/{short_replica_id}/key.json` and
//! `{vault_id}.{hash}.apstate`, and `{root}/pairing/{request_id}.json`.
//!
//! Every file in the folder is untrusted. Only directories named by the exact
//! short id of a UUID are listed as vaults and replicas, so `pairing/` is
//! never a vault. Only the exact names of [`FileName`], `meta.json`, and
//! [`RequestId`] are listed or read, so conflict copies, temp files, and
//! `.DS_Store` are ignored. A symlink is never listed or read, and no write
//! goes through a symlinked directory. A file that is not local is `Remote`
//! and is not read, so no transaction waits on the network. The root is never
//! created, and a root that is missing or not a folder fails every call.

pub mod io;

use std::fs::{self, FileType};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use jiff::Timestamp;
use uuid::Uuid;

use self::io::{FileStatus, FolderIo, WriteMode};
use super::{
    FileName, MAX_PAIRING_SIZE, PairingEntry, ReadResult, RequestId, SyncTransport, WatchHandle,
};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::state_file::StateHash;

/// Name of the file of the vault format in each vault directory.
const META_FILE: &str = "meta.json";

/// Directory of the pairing requests under the root.
const PAIRING_DIR: &str = "pairing";

/// Transport of a folder the user picked. Files are read and written through
/// a [`FolderIo`].
#[derive(Debug)]
pub struct FolderTransport {
    root: PathBuf,
    io: Arc<dyn FolderIo>,
}

impl FolderTransport {
    /// Transport of the folder `root`, with file access `io`.
    pub fn new(root: impl Into<PathBuf>, io: Arc<dyn FolderIo>) -> Self {
        Self {
            root: root.into(),
            io,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Fail unless the root is a folder. A symlink to a folder is a folder.
    pub fn check_root(&self) -> Result<(), Error> {
        match fs::metadata(&self.root) {
            Ok(meta) if meta.is_dir() => Ok(()),
            Ok(_) => Err(Error::SyncTransportError(format!(
                "{} is not a folder",
                self.root.display()
            ))),
            Err(e) => Err(Self::error("read", &self.root, e)),
        }
    }

    fn vault_dir(&self, vault_id: Uuid) -> PathBuf {
        self.root.join(ShortId::encode_uuid(vault_id))
    }

    fn replica_dir(&self, vault_id: Uuid, replica: ReplicaId) -> PathBuf {
        self.vault_dir(vault_id)
            .join(ShortId::encode_uuid(replica.0))
    }

    fn file_path(&self, vault_id: Uuid, replica: ReplicaId, name: FileName) -> PathBuf {
        self.replica_dir(vault_id, replica)
            .join(name.file_name(vault_id))
    }

    fn meta_path(&self, vault_id: Uuid) -> PathBuf {
        self.vault_dir(vault_id).join(META_FILE)
    }

    fn pairing_dir(&self) -> PathBuf {
        self.root.join(PAIRING_DIR)
    }

    fn pairing_path(&self, request: RequestId) -> PathBuf {
        self.pairing_dir().join(request.file_name())
    }

    fn error(action: &str, path: &Path, e: std::io::Error) -> Error {
        Error::SyncTransportError(format!("Failed to {action} {}: {e}", path.display()))
    }

    /// Names and types of the entries of the directory `dir`. Empty if it is
    /// missing. A name that is not UTF-8 is left out. A symlink has the
    /// symlink type.
    fn entries(dir: &Path) -> Result<Vec<(String, FileType)>, Error> {
        let read = match fs::read_dir(dir) {
            Ok(read) => read,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(Self::error("list", dir, e)),
        };
        let mut entries = Vec::new();
        for entry in read {
            let entry = entry.map_err(|e| Self::error("list", dir, e))?;
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            let file_type = entry.file_type().map_err(|e| Self::error("list", dir, e))?;
            entries.push((name, file_type));
        }
        Ok(entries)
    }

    /// Names of the regular files of the directory `dir`.
    fn file_names(dir: &Path) -> Result<Vec<String>, Error> {
        Ok(Self::entries(dir)?
            .into_iter()
            .filter(|(_, file_type)| file_type.is_file())
            .map(|(name, _)| name)
            .collect())
    }

    /// Ids of the directories of `dir` named by a short id, in order.
    fn short_id_dirs(dir: &Path) -> Result<Vec<Uuid>, Error> {
        let mut ids: Vec<Uuid> = Self::entries(dir)?
            .into_iter()
            .filter(|(_, file_type)| file_type.is_dir())
            .filter_map(|(name, _)| Self::parse_short_id(&name))
            .collect();
        ids.sort();
        Ok(ids)
    }

    /// Id named by `name`, the exact short form of a UUID. The hex forms that
    /// `ShortId::decode` also reads are refused.
    fn parse_short_id(name: &str) -> Option<Uuid> {
        let id = ShortId::parse_uuid(name).ok()?;
        (ShortId::encode_uuid(id) == name).then_some(id)
    }

    /// Read the file at `path` if it is local, with at most `limit` bytes.
    fn read_file(&self, path: &Path, limit: u64) -> Result<ReadResult, Error> {
        let status = self
            .io
            .status(path)
            .map_err(|e| Self::error("read", path, e))?;
        match status {
            FileStatus::Missing => Ok(ReadResult::Missing),
            FileStatus::Remote => Ok(ReadResult::Remote),
            FileStatus::Local => self
                .io
                .read(path, limit)
                .map(ReadResult::Local)
                .map_err(|e| Self::error("read", path, e)),
        }
    }

    /// Create the directory `dir` in its parent, which must exist. An
    /// existing directory is kept. A symlink fails.
    fn create_dir(dir: &Path) -> Result<(), Error> {
        match fs::create_dir(dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                match fs::symlink_metadata(dir) {
                    Ok(meta) if meta.is_dir() => Ok(()),
                    _ => Err(Self::error("create", dir, e)),
                }
            },
            Err(e) => Err(Self::error("create", dir, e)),
        }
    }

    /// Write `data` at `path`. A symlink at `path` fails the write, so no
    /// write reaches its target.
    fn write_file(&self, path: &Path, data: &[u8], mode: WriteMode) -> Result<(), Error> {
        if Self::is_symlink(path) {
            return Err(Error::SyncTransportError(format!(
                "{} is a symlink",
                path.display()
            )));
        }
        self.io
            .write(path, data, mode)
            .map_err(|e| Self::error("write", path, e))
    }

    /// Delete the file or directory at `path`. A symlink is deleted without
    /// coordination, so its target is never deleted.
    fn delete_path(&self, path: &Path) -> Result<(), Error> {
        let result = if Self::is_symlink(path) {
            fs::remove_file(path)
        } else {
            self.io.delete(path)
        };
        result.map_err(|e| Self::error("delete", path, e))
    }

    fn is_symlink(path: &Path) -> bool {
        fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
    }

    /// Whether the file at `path` exists and is not local.
    fn is_remote(&self, path: &Path) -> Result<bool, Error> {
        let status = self
            .io
            .status(path)
            .map_err(|e| Self::error("read", path, e))?;
        Ok(status == FileStatus::Remote)
    }
}

impl SyncTransport for FolderTransport {
    fn list_replicas(&self, vault_id: Uuid) -> Result<Vec<ReplicaId>, Error> {
        self.check_root()?;
        let ids = Self::short_id_dirs(&self.vault_dir(vault_id))?;
        Ok(ids.into_iter().map(ReplicaId).collect())
    }

    fn list_vaults(&self) -> Result<Vec<Uuid>, Error> {
        self.check_root()?;
        Self::short_id_dirs(&self.root)
    }

    fn list_states(&self, vault_id: Uuid, replica: ReplicaId) -> Result<Vec<StateHash>, Error> {
        self.check_root()?;
        let mut hashes: Vec<StateHash> = Self::file_names(&self.replica_dir(vault_id, replica))?
            .iter()
            .filter_map(|name| FileName::parse_state(vault_id, name))
            .collect();
        hashes.sort();
        Ok(hashes)
    }

    fn read(
        &self,
        vault_id: Uuid,
        replica: ReplicaId,
        name: FileName,
    ) -> Result<ReadResult, Error> {
        self.check_root()?;
        self.read_file(&self.file_path(vault_id, replica, name), u64::MAX)
    }

    fn is_local(&self, vault_id: Uuid, replica: ReplicaId, name: FileName) -> Result<bool, Error> {
        self.check_root()?;
        let path = self.file_path(vault_id, replica, name);
        let status = self
            .io
            .status(&path)
            .map_err(|e| Self::error("read", &path, e))?;
        Ok(status == FileStatus::Local)
    }

    fn read_meta(&self, vault_id: Uuid) -> Result<ReadResult, Error> {
        self.check_root()?;
        self.read_file(&self.meta_path(vault_id), u64::MAX)
    }

    fn write_meta(&self, vault_id: Uuid, data: &[u8]) -> Result<(), Error> {
        self.check_root()?;
        Self::create_dir(&self.vault_dir(vault_id))?;
        self.write_file(&self.meta_path(vault_id), data, WriteMode::Replace)
    }

    /// Write a file of this replica. A state file is never overwritten, and
    /// a write to an existing name fails. `key.json` is replaced.
    fn write_own(
        &self,
        vault_id: Uuid,
        replica: ReplicaId,
        name: FileName,
        data: &[u8],
    ) -> Result<(), Error> {
        self.check_root()?;
        Self::create_dir(&self.vault_dir(vault_id))?;
        Self::create_dir(&self.replica_dir(vault_id, replica))?;
        let mode = match name {
            FileName::Key => WriteMode::Replace,
            FileName::State(_) => WriteMode::New,
        };
        self.write_file(&self.file_path(vault_id, replica, name), data, mode)
    }

    fn delete_own(&self, vault_id: Uuid, replica: ReplicaId, name: FileName) -> Result<(), Error> {
        self.check_root()?;
        self.delete_path(&self.file_path(vault_id, replica, name))
    }

    fn delete_replica(&self, vault_id: Uuid, replica: ReplicaId) -> Result<(), Error> {
        self.check_root()?;
        self.delete_path(&self.replica_dir(vault_id, replica))
    }

    /// Start a coordinated read of `meta.json` and of each `key.json` and
    /// state file of the vault that is not local, and return without
    /// waiting.
    fn request_download(&self, vault_id: Uuid) -> Result<(), Error> {
        self.check_root()?;
        let mut paths = vec![self.meta_path(vault_id)];
        for replica in self.list_replicas(vault_id)? {
            paths.push(self.file_path(vault_id, replica, FileName::Key));
            for hash in self.list_states(vault_id, replica)? {
                paths.push(self.file_path(vault_id, replica, FileName::State(hash)));
            }
        }
        let mut remote = Vec::new();
        for path in paths {
            if self.is_remote(&path)? {
                remote.push(path);
            }
        }
        if !remote.is_empty() {
            self.io.download(remote);
        }
        Ok(())
    }

    fn watch(&self, _vault_id: Uuid, _notify: Box<dyn Fn() + Send>) -> Option<WatchHandle> {
        None
    }

    fn list_pairings(&self) -> Result<Vec<PairingEntry>, Error> {
        self.check_root()?;
        let dir = self.pairing_dir();
        let mut entries = Vec::new();
        for name in Self::file_names(&dir)? {
            let Some(id) = RequestId::parse_file_name(&name) else {
                continue;
            };
            let path = dir.join(&name);
            let meta = match fs::symlink_metadata(&path) {
                Ok(meta) => meta,
                // Deleted since the listing.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(Self::error("read", &path, e)),
            };
            let modified = meta.modified().map_err(|e| Self::error("read", &path, e))?;
            let modified = Timestamp::try_from(modified).map_err(|e| {
                Error::SyncTransportError(format!(
                    "Failed to read the time of {}: {e}",
                    path.display()
                ))
            })?;
            entries.push(PairingEntry {
                id,
                modified,
                size: meta.len(),
            });
        }
        entries.sort_by_key(|entry| entry.id);
        Ok(entries)
    }

    /// Read a pairing request. A request larger than [`MAX_PAIRING_SIZE`]
    /// fails and is not read.
    fn read_pairing(&self, request: RequestId) -> Result<ReadResult, Error> {
        self.check_root()?;
        let path = self.pairing_path(request);
        if let Ok(meta) = fs::symlink_metadata(&path)
            && meta.len() > MAX_PAIRING_SIZE
        {
            return Err(Error::SyncTransportError(format!(
                "Pairing request {request} is larger than {MAX_PAIRING_SIZE} bytes"
            )));
        }
        self.read_file(&path, MAX_PAIRING_SIZE)
    }

    fn write_pairing(&self, request: RequestId, data: &[u8]) -> Result<(), Error> {
        self.check_root()?;
        Self::create_dir(&self.pairing_dir())?;
        self.write_file(&self.pairing_path(request), data, WriteMode::Replace)
    }

    fn delete_pairing(&self, request: RequestId) -> Result<(), Error> {
        self.check_root()?;
        self.delete_path(&self.pairing_path(request))
    }

    fn watch_pairings(&self, _notify: Box<dyn Fn() + Send>) -> Option<WatchHandle> {
        None
    }
}
