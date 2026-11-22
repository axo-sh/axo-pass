//! Status sidecar: an unsigned record of the state files of one vault.
//!
//! The sidecar holds the content hash of the last publish, the hashes of the
//! state files joined, the quarantined files, the causes of a paused sync,
//! the last failure to load the sync state, and the transport root. It is at
//! `sync/{short_vault_id}.json` and is written under the vault locks. It is
//! not a source of truth, except for the transport root. A sidecar that fails
//! to parse is read as empty, which causes an extra join and never a wrong
//! result, since a join checks the hash of every file and decrypts it. Its
//! root is kept if the `transport` field parses. A sidecar that cannot be
//! read fails the transaction, so no save replaces its root.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::crdt::ReplicaId;
use super::local_state::SYNC_DIR;
use super::state_file::StateHash;
use super::status::PausedCause;
use super::transport::TransportRoot;
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
    /// Health found by the last transaction that ran. A transaction records
    /// audit events only if it finds another health.
    #[serde(default)]
    pub health: Health,
    /// Root of the transport of the vault. `None` gives no transport. The
    /// root is unsigned. A changed root can withhold files, and cannot plant
    /// a state or read one.
    #[serde(default)]
    pub transport: Option<TransportRoot>,
}

/// What the last transaction found about the sync of a vault.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Health {
    /// The sync state loaded and no cause was found.
    #[default]
    Ok,
    /// Causes of a paused sync found by the last transaction that synced. A
    /// sync stopped by drift keeps the health as found before the stop.
    Paused { causes: Vec<PausedCause> },
    /// The sync state failed to load.
    Failed { failure: LoadFailure },
}

impl Health {
    /// Health of a transaction that found `causes`.
    pub fn of_causes(causes: Vec<PausedCause>) -> Self {
        if causes.is_empty() {
            Self::Ok
        } else {
            Self::Paused { causes }
        }
    }

    /// Causes of a paused sync. Empty if the health is not `Paused`.
    pub fn paused(&self) -> &[PausedCause] {
        match self {
            Self::Paused { causes } => causes,
            _ => &[],
        }
    }

    /// Whether `other` is the same health for an audit event. Causes are
    /// compared by name, so another error text records no event.
    pub fn same_event(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Ok, Self::Ok) => true,
            (Self::Failed { failure: a }, Self::Failed { failure: b }) => a == b,
            (Self::Paused { causes: a }, Self::Paused { causes: b }) => {
                let names = |causes: &[PausedCause]| -> BTreeSet<&'static str> {
                    causes.iter().map(PausedCause::name).collect()
                };
                names(a) == names(b)
            },
            _ => false,
        }
    }
}

/// Failure to load the sync state of a vault that stops the transaction before
/// any sync step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadFailure {
    /// The vault names a replica and its sync state file is missing.
    StateMissing,
    /// The sync state fails its signature check.
    SignatureFailed,
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
        root.join(SYNC_DIR).join(format!("{vault_id}.json"))
    }

    /// Sidecar of vault `vault_id` under the app data directory `root`. Empty
    /// if the file is missing. A file that fails to parse is read as empty,
    /// with the root of its `transport` field if that field parses. A file
    /// that cannot be read fails with `SyncStateReadError`.
    pub fn read(root: &Path, vault_id: Uuid) -> Result<Self, Error> {
        let path = Self::path(root, vault_id);
        let contents = match fs::read(&path) {
            Ok(contents) => contents,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(Error::SyncStateReadError(e)),
        };
        Ok(serde_json::from_slice(&contents).unwrap_or_else(|e| {
            let sidecar = Self::recovered(&contents);
            let kept = if sidecar.transport.is_some() {
                ", root kept"
            } else {
                ""
            };
            log::warn!(
                "Failed to parse {}, read as empty{kept}: {e}",
                path.display()
            );
            sidecar
        }))
    }

    /// [`Self::read`], with a file that cannot be read read as empty.
    #[cfg(test)]
    pub fn load(root: &Path, vault_id: Uuid) -> Self {
        Self::read(root, vault_id).unwrap_or_default()
    }

    /// Empty sidecar with the root of `contents`, a sidecar that fails to
    /// parse. No root if the `transport` field is missing or fails to parse.
    fn recovered(contents: &[u8]) -> Self {
        let transport = serde_json::from_slice::<serde_json::Value>(contents)
            .ok()
            .and_then(|mut value| value.get_mut("transport").map(serde_json::Value::take))
            .and_then(|root| serde_json::from_value::<Option<TransportRoot>>(root).ok())
            .flatten();
        Self {
            transport,
            ..Self::default()
        }
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

    /// Whether the paused causes hold `SeparateKey`, a separate enable found
    /// by the last transaction that synced.
    pub fn separate_key(&self) -> bool {
        self.health
            .paused()
            .iter()
            .any(|cause| matches!(cause, PausedCause::SeparateKey { .. }))
    }

    /// Causes of a paused sync. Empty if the health is not `Paused`.
    pub fn paused(&self) -> &[PausedCause] {
        self.health.paused()
    }

    /// Drop the `PublishFailed` cause, after the staged file is copied. The
    /// health is `Ok` if no cause is left.
    pub fn clear_publish_failed(&mut self) {
        if let Health::Paused { causes } = &mut self.health {
            causes.retain(|cause| !matches!(cause, PausedCause::PublishFailed { .. }));
            if causes.is_empty() {
                self.health = Health::Ok;
            }
        }
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
