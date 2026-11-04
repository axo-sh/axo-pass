//! Transport of the synced folder: `meta.json` of each vault directory, the
//! state files and `key.json` of each replica, and pairing requests.
//!
//! The root of a vault's transport is in its sidecar. [`SyncTransports`]
//! resolves a root to a transport. [`folder::FolderTransport`] is the local
//! folder transport. Milestone 9 adds the watches of the real transports.

pub mod folder;

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::crdt::ReplicaId;
use super::state_file::{StateFile, StateHash};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::short_id::ShortId;

/// Storage of the synced folder. Each replica writes only its own directory.
pub trait SyncTransport: fmt::Debug + Send + Sync {
    /// Replicas with a directory under the directory of vault `vault_id`.
    fn list_replicas(&self, vault_id: Uuid) -> Result<Vec<ReplicaId>, Error>;
    /// List the vault directories under the root.
    fn list_vaults(&self) -> Result<Vec<Uuid>, Error>;
    /// List a replica's state files by content hash. Only names that
    /// [`FileName::parse_state`] accepts are listed.
    fn list_states(&self, vault_id: Uuid, replica: ReplicaId) -> Result<Vec<StateHash>, Error>;
    /// Read a state file or `key.json`.
    /// Returns `Remote` if the file exists but is not local yet.
    fn read(&self, vault_id: Uuid, replica: ReplicaId, name: FileName)
    -> Result<ReadResult, Error>;
    /// Read `meta.json` of the directory of vault `vault_id`.
    fn read_meta(&self, vault_id: Uuid) -> Result<ReadResult, Error>;
    /// Write `meta.json` of the directory of vault `vault_id`.
    fn write_meta(&self, vault_id: Uuid, data: &[u8]) -> Result<(), Error>;
    fn write_own(
        &self,
        vault_id: Uuid,
        replica: ReplicaId,
        name: FileName,
        data: &[u8],
    ) -> Result<(), Error>;
    fn delete_own(&self, vault_id: Uuid, replica: ReplicaId, name: FileName) -> Result<(), Error>;
    /// Delete a removed, retired, or departed replica directory.
    fn delete_replica(&self, vault_id: Uuid, replica: ReplicaId) -> Result<(), Error>;
    /// Ask the provider to make every file under the vault local. Does not
    /// wait.
    fn request_download(&self, vault_id: Uuid) -> Result<(), Error>;
    /// Call `notify` when a file under the vault changes. `None` if the
    /// transport has no watch. The watch ends when the handle drops.
    fn watch(&self, vault_id: Uuid, notify: Box<dyn Fn() + Send>) -> Option<WatchHandle>;
    /// Pairing requests under `{root}/pairing/`. Only names that
    /// [`RequestId::parse_file_name`] accepts are listed.
    fn list_pairings(&self) -> Result<Vec<PairingEntry>, Error>;
    fn read_pairing(&self, request: RequestId) -> Result<ReadResult, Error>;
    fn write_pairing(&self, request: RequestId, data: &[u8]) -> Result<(), Error>;
    fn delete_pairing(&self, request: RequestId) -> Result<(), Error>;
    /// Call `notify` when a pairing request changes. `None` if the transport
    /// has no watch. The watch ends when the handle drops.
    fn watch_pairings(&self, notify: Box<dyn Fn() + Send>) -> Option<WatchHandle>;
}

/// Result of a read from the synced folder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadResult {
    Missing,
    /// File exists and is not local yet.
    Remote,
    Local(Vec<u8>),
}

/// File of a replica directory. A transport reads only these names, so it
/// cannot read a conflict copy. `meta.json` of the vault directory is read
/// with [`SyncTransport::read_meta`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileName {
    /// `key.json` of a replica directory.
    Key,
    /// `{vault_id}.{hash}.apstate` of a replica directory, with the short id
    /// of the vault directory.
    State(StateHash),
}

impl FileName {
    /// Name of this file in a directory of vault `vault_id`.
    pub fn file_name(&self, vault_id: Uuid) -> String {
        match self {
            Self::Key => "key.json".to_string(),
            Self::State(hash) => StateFile::name(vault_id, *hash),
        }
    }

    /// Hash of the state file named `name` in a directory of vault
    /// `vault_id`. `None` unless the name is the short vault id, a
    /// 64-character lowercase hex hash, and `.apstate`, each exactly.
    pub fn parse_state(vault_id: Uuid, name: &str) -> Option<StateHash> {
        let rest = name.strip_prefix(&ShortId::encode_uuid(vault_id))?;
        let hash = rest.strip_prefix('.')?.strip_suffix(".apstate")?;
        StateHash::parse(hash)
    }
}

/// Largest pairing request in bytes that a transport reads. A larger request
/// is listed with its size and not read.
pub const MAX_PAIRING_SIZE: u64 = 16 * 1024;

/// Id of a pairing request, the name of its file under `{root}/pairing/`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(pub Uuid);

impl RequestId {
    /// File name of the request: the lowercase hyphenated UUID and `.json`.
    pub fn file_name(&self) -> String {
        format!("{}.json", self.0.hyphenated())
    }

    /// Request id of the file `name`. `None` unless the name is a lowercase
    /// hyphenated UUID and `.json`, each exactly.
    pub fn parse_file_name(name: &str) -> Option<Self> {
        let stem = name.strip_suffix(".json")?;
        let id = Uuid::try_parse(stem).ok()?;
        (id.hyphenated().to_string() == stem).then_some(Self(id))
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.hyphenated().fmt(f)
    }
}

/// Listed pairing request. The modification time and the size decide only
/// the pairing prompt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PairingEntry {
    pub id: RequestId,
    pub modified: Timestamp,
    /// Size of the file in bytes.
    pub size: u64,
}

/// Watch of the synced folder. The watch ends when the handle drops.
pub struct WatchHandle {
    stop: Option<Box<dyn FnOnce() + Send>>,
}

impl WatchHandle {
    /// Handle that calls `stop` when it drops.
    pub fn new(stop: impl FnOnce() + Send + 'static) -> Self {
        Self {
            stop: Some(Box::new(stop)),
        }
    }
}

impl Drop for WatchHandle {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            stop();
        }
    }
}

impl fmt::Debug for WatchHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WatchHandle").finish_non_exhaustive()
    }
}

/// Root of the transport of one vault, held in its sidecar.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum TransportRoot {
    /// `Vaults` in the ubiquity container of the app.
    ICloud {},
    /// Folder the user picked.
    Folder { path: PathBuf },
}

impl fmt::Display for TransportRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ICloud {} => f.write_str("iCloud"),
            Self::Folder { path } => write!(f, "folder {}", path.display()),
        }
    }
}

/// Transports of the vaults of one writer, by root.
pub trait SyncTransports: fmt::Debug + Send + Sync {
    /// Transport of `root`. `Ok(None)` if the vault has no root. An error is
    /// a root that cannot be reached.
    fn resolve(
        &self,
        root: Option<&TransportRoot>,
    ) -> Result<Option<Arc<dyn SyncTransport>>, Error>;
}

/// One transport for any root and for no root, so a test writer syncs every
/// vault through it.
#[cfg(test)]
#[derive(Debug)]
pub struct FixedTransport(pub Arc<dyn SyncTransport>);

#[cfg(test)]
impl SyncTransports for FixedTransport {
    fn resolve(
        &self,
        _root: Option<&TransportRoot>,
    ) -> Result<Option<Arc<dyn SyncTransport>>, Error> {
        Ok(Some(self.0.clone()))
    }
}
