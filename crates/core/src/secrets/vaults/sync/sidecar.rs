//! Status sidecar: an unsigned record of the state files of one vault.
//!
//! The sidecar holds the content hash of the last publish, the hashes of the
//! state files joined, the quarantined files, and the causes of a paused
//! sync. It is at
//! `sync/{short_vault_id}.json` and is written under the vault locks. It is
//! not a source of truth. A sidecar that fails to parse is read as empty,
//! which causes an extra join and never a wrong result, since a join checks
//! the hash of every file and decrypts it.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::crdt::ReplicaId;
use super::state_file::StateHash;
use super::status::PausedCause;
use crate::core::files::write_atomic;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::short_id::ShortId;

/// Status sidecar of one vault.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sidecar {
    /// Content hash of this replica's last successful publish.
    pub last_publish: Option<StateHash>,
    /// Content hashes of the state files joined, by replica. Only hashes of
    /// files still listed, and of replicas still listed, are kept.
    pub joined: BTreeMap<ReplicaId, BTreeSet<StateHash>>,
    /// Quarantined state files. An entry is kept when its file is gone.
    pub quarantined: Vec<QuarantinedFile>,
    /// Causes of a paused sync found by the last transaction that synced.
    #[serde(default)]
    pub paused: Vec<PausedCause>,
}

/// State file quarantined by path and content hash. A later file at the same
/// path with other bytes is read again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantinedFile {
    /// Replica directory of the file.
    pub replica: ReplicaId,
    /// File name in the replica directory.
    pub name: String,
    /// SHA-256 of the file bytes.
    pub hash: StateHash,
    pub reason: String,
}

impl Sidecar {
    /// Sidecar file of vault `vault_id` under the app data directory `root`.
    pub fn path(root: &Path, vault_id: Uuid) -> PathBuf {
        let vault_id = ShortId::encode_uuid(vault_id);
        root.join("sync").join(format!("{vault_id}.json"))
    }

    /// Sidecar of vault `vault_id` under the app data directory `root`. Empty
    /// if the file is missing, cannot be read, or fails to parse.
    pub fn load(root: &Path, vault_id: Uuid) -> Self {
        let path = Self::path(root, vault_id);
        let contents = match fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Self::default(),
            Err(e) => {
                log::warn!("Failed to read {}, read as empty: {e}", path.display());
                return Self::default();
            },
        };
        serde_json::from_str(&contents).unwrap_or_else(|e| {
            log::warn!("Failed to parse {}, read as empty: {e}", path.display());
            Self::default()
        })
    }

    /// Write the sidecar of vault `vault_id` under the app data directory
    /// `root`, replacing the file in one rename.
    pub fn save(&self, root: &Path, vault_id: Uuid) -> Result<(), Error> {
        let contents = serde_json::to_string_pretty(self)
            .map_err(|e| Error::SyncStateEncodeError(e.to_string()))?;
        let path = Self::path(root, vault_id);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(Error::SyncStateWriteError)?;
        }
        write_atomic(&path, contents.as_bytes()).map_err(Error::SyncStateWriteError)
    }

    /// Whether the state file with hash `hash` of `replica` was joined.
    pub fn is_joined(&self, replica: ReplicaId, hash: StateHash) -> bool {
        self.joined
            .get(&replica)
            .is_some_and(|hashes| hashes.contains(&hash))
    }

    /// Record the state file with hash `hash` of `replica` as joined.
    pub fn record_joined(&mut self, replica: ReplicaId, hash: StateHash) {
        self.joined.entry(replica).or_default().insert(hash);
    }

    /// Keep only the joined hashes of `replica` in `listed`. Returns whether
    /// a hash was dropped.
    pub fn retain_joined(&mut self, replica: ReplicaId, listed: &[StateHash]) -> bool {
        let Some(hashes) = self.joined.get_mut(&replica) else {
            return false;
        };
        let before = hashes.len();
        hashes.retain(|hash| listed.contains(hash));
        let dropped = hashes.len() != before;
        if hashes.is_empty() {
            self.joined.remove(&replica);
        }
        dropped
    }

    /// Keep only the joined hashes of `own` and of the replicas in `listed`.
    /// Returns whether a replica was dropped.
    pub fn retain_replicas(&mut self, own: ReplicaId, listed: &[ReplicaId]) -> bool {
        let before = self.joined.len();
        self.joined
            .retain(|replica, _| *replica == own || listed.contains(replica));
        self.joined.len() != before
    }

    /// Whether the file `name` of `replica` with content hash `hash` is
    /// quarantined.
    pub fn is_quarantined(&self, replica: ReplicaId, name: &str, hash: StateHash) -> bool {
        self.quarantined
            .iter()
            .any(|file| file.replica == replica && file.name == name && file.hash == hash)
    }

    /// Quarantine the file `name` of `replica` with content hash `hash`.
    pub fn quarantine(
        &mut self,
        replica: ReplicaId,
        name: String,
        hash: StateHash,
        reason: String,
    ) {
        if !self.is_quarantined(replica, &name, hash) {
            self.quarantined.push(QuarantinedFile {
                replica,
                name,
                hash,
                reason,
            });
        }
    }
}
