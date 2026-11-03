//! Transport of the synced folder: the state files of each replica of a vault.
//!
//! Only the state file methods exist. Milestone 7 adds `key.json`,
//! `meta.json`, pairing requests, watches, and the real transports.

use std::fmt;

use uuid::Uuid;

use super::crdt::ReplicaId;
use super::state_file::{StateFile, StateHash};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::short_id::ShortId;

/// Storage of the synced folder. Each replica writes only its own directory.
pub trait SyncTransport: fmt::Debug + Send + Sync {
    /// Replicas with a directory under the directory of vault `vault_id`.
    fn list_replicas(&self, vault_id: Uuid) -> Result<Vec<ReplicaId>, Error>;
    /// List a replica's state files by content hash. Only names that
    /// [`FileName::parse_state`] accepts are listed.
    fn list_states(&self, vault_id: Uuid, replica: ReplicaId) -> Result<Vec<StateHash>, Error>;
    /// Read a state file or `key.json`.
    /// Returns `Remote` if the file exists but is not local yet.
    fn read(&self, vault_id: Uuid, replica: ReplicaId, name: FileName)
    -> Result<ReadResult, Error>;
    fn write_own(
        &self,
        vault_id: Uuid,
        replica: ReplicaId,
        name: FileName,
        data: &[u8],
    ) -> Result<(), Error>;
    fn delete_own(&self, vault_id: Uuid, replica: ReplicaId, name: FileName) -> Result<(), Error>;
}

/// Result of a read from the synced folder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadResult {
    Missing,
    /// File exists and is not local yet.
    Remote,
    Local(Vec<u8>),
}

/// File of a vault directory or a replica directory. A transport reads only
/// these names, so it cannot read a conflict copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileName {
    /// `meta.json` of the vault directory.
    Meta,
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
            Self::Meta => "meta.json".to_string(),
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
