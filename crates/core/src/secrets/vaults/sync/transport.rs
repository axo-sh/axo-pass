//! Transport of the synced folder: `meta.json` of each vault directory, the
//! state files and `key.json` of each replica, the file blobs of each vault,
//! and pairing requests.
//!
//! File blobs are in `blobs/` of the vault directory. It is shared by every
//! replica, the one exception to the rule that each replica writes only its
//! own directory. A blob is named by the SHA-256 of its bytes, so two writers
//! never write different bytes under one name.
//!
//! The root of a vault's transport is in its sidecar. [`SyncTransports`]
//! resolves a root to a transport. [`folder::FolderTransport`] is the local
//! folder transport, which watches with FSEvents. [`s3::S3Transport`] is the
//! S3 transport, which watches by polling.

pub mod folder;
pub mod s3;

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::crdt::ReplicaId;
use super::state_file::{StateFile, StateHash};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::files::FileHash;
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
    /// Whether a state file or `key.json` exists and is local. Reads no
    /// bytes. False for a file that is missing or not local yet.
    fn is_local(&self, vault_id: Uuid, replica: ReplicaId, name: FileName) -> Result<bool, Error>;
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
    /// Blobs under `blobs/` of the directory of vault `vault_id`, local or
    /// not, ordered by name. Only names that [`FileHash::parse`] accepts are
    /// listed.
    fn list_blobs(&self, vault_id: Uuid) -> Result<Vec<FileHash>, Error>;
    /// Blobs listed by [`Self::list_blobs`], each with its size in bytes.
    /// The size is read from the directory entry, so a blob that is not local
    /// is not downloaded and not coordinated. A blob whose size the provider
    /// does not report has size 0.
    fn list_blob_sizes(&self, vault_id: Uuid) -> Result<Vec<(FileHash, u64)>, Error>;
    /// Read blob `blob` of vault `vault_id`. Returns `Remote` if the blob
    /// exists but is not local yet. The bytes are not checked against the
    /// name.
    fn read_blob(&self, vault_id: Uuid, blob: FileHash) -> Result<ReadResult, Error>;
    /// Write `data` as blob `blob` of vault `vault_id`. An existing blob of
    /// that name is kept, since a name holds one content. The caller checks
    /// that `data` hashes to `blob`.
    fn write_blob(&self, vault_id: Uuid, blob: FileHash, data: &[u8]) -> Result<(), Error>;
    /// Whether blob `blob` of vault `vault_id` exists and is local. Reads no
    /// bytes.
    fn is_blob_local(&self, vault_id: Uuid, blob: FileHash) -> Result<bool, Error>;
    /// Delete blob `blob` of vault `vault_id`. A missing blob is not an
    /// error.
    fn delete_blob(&self, vault_id: Uuid, blob: FileHash) -> Result<(), Error>;
    /// Ask the provider to make blob `blob` of vault `vault_id` local. Does
    /// not wait.
    fn request_blob_download(&self, vault_id: Uuid, blob: FileHash) -> Result<(), Error>;
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
/// The serde form is the `Uuid`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestId(pub Uuid);

impl RequestId {
    /// New random request id.
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }

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
    /// S3 location saved under `name` in the credential store. The sidecar
    /// holds no endpoint, bucket, or key.
    S3 { name: String },
}

impl fmt::Display for TransportRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ICloud {} => f.write_str("iCloud"),
            Self::Folder { path } => write!(f, "folder {}", path.display()),
            Self::S3 { name } => write!(f, "S3 location {name}"),
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

/// One transport for each listed root, so a test writer syncs a vault only
/// through the root in its sidecar. No root gives no transport, and a root
/// that is not listed cannot be reached.
#[cfg(test)]
#[derive(Debug)]
pub struct RootTransports(pub Vec<(TransportRoot, Arc<dyn SyncTransport>)>);

#[cfg(test)]
impl SyncTransports for RootTransports {
    fn resolve(
        &self,
        root: Option<&TransportRoot>,
    ) -> Result<Option<Arc<dyn SyncTransport>>, Error> {
        let Some(root) = root else {
            return Ok(None);
        };
        self.0
            .iter()
            .find(|(listed, _)| listed == root)
            .map(|(_, transport)| Some(transport.clone()))
            .ok_or_else(|| Error::SyncTransportError(format!("{root} cannot be reached")))
    }
}
