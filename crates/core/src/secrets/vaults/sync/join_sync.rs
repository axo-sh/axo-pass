//! Join of a sync key into a local vault or a new one (D5).
//!
//! One join serves the join offer of "Enable sync", the re-link of a vault
//! whose sync state is missing or fails its signature, and the import on
//! another Mac. The sync key comes from a pairing ([`JoinKey::paired`]) or a
//! recovery kit ([`JoinKey::recovered`]). A local vault of the vault id is
//! always joined ([`JoinInto::Existing`]). A copy with a new vault id is not
//! offered, since the synced folder lacks its id. An import of a vault id that
//! no vault file on this Mac holds builds a new vault ([`JoinInto::New`]).
//!
//! The join runs one transaction under the vault locks
//! (`VaultWriter::join_sync`). It checks `meta.json`, builds an empty sync
//! state under a new replica id with the one key, and joins every local peer
//! file. An existing vault then runs the recovery merge (decision 5): each
//! difference of the vault against the view is added as a concurrent value
//! under one write id, and the vault takes the view. A new vault is built from
//! the view with a new file key. The Mac that paired is pinned with
//! `pairing`, the other peers at first use, and the display name and the
//! public keys of this Mac are recorded under one more write id. The sidecar
//! with the root is saved first, then the staged file, the sync state, and
//! the vault, then `key.json` is written and the staged file is copied.

use std::path::PathBuf;

use uuid::Uuid;

use super::crdt::ReplicaId;
use super::keys::SyncKey;
use super::model::{KeyId, ReplicaKeys};
use super::pairing::PairedVault;
use super::recovery::import::RecoveredKey;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::storage::txn::Target;

/// Sync key of a join, with the replica id of this Mac in the vault.
#[derive(Debug)]
pub struct JoinKey {
    pub(crate) vault_id: Uuid,
    /// New replica id of this Mac in the vault.
    pub(crate) replica_id: ReplicaId,
    pub(crate) key_id: KeyId,
    pub(crate) key: SyncKey,
    /// Mac that paired and its keys, pinned with `pairing`. `None` for a key
    /// from a recovery kit.
    pub(crate) paired: Option<(ReplicaId, ReplicaKeys)>,
}

impl JoinKey {
    /// Key received by pairing, with the keys of the Mac that paired.
    pub fn paired(vault: PairedVault) -> Self {
        let keys = ReplicaKeys {
            encryption: vault.pin.encryption,
            signing: vault.pin.signing,
        };
        Self {
            vault_id: vault.vault_id,
            replica_id: vault.replica_id,
            key_id: vault.key_id,
            key: vault.key,
            paired: Some((vault.peer, keys)),
        }
    }

    /// Key opened with a recovery kit.
    pub fn recovered(key: RecoveredKey) -> Self {
        Self {
            vault_id: key.vault_id,
            replica_id: key.replica_id,
            key_id: key.key_id,
            key: key.key,
            paired: None,
        }
    }

    pub fn vault_id(&self) -> Uuid {
        self.vault_id
    }

    /// Replica id of this Mac in the vault after the join.
    pub fn replica_id(&self) -> ReplicaId {
        self.replica_id
    }
}

/// Vault a join writes, as the caller chooses it (D5).
#[derive(Clone, Debug)]
pub enum JoinInto {
    /// Local vault with the vault id of the key.
    Existing(Target),
    /// New vault, for an import of a vault id that no vault file on this Mac
    /// holds.
    New,
}

/// Vault file a join writes under the vault locks.
pub(crate) enum JoinFile<'a> {
    Existing(&'a Target),
    /// New vault file at `path`, with the vault key that `choose_key` returns
    /// for the vault name of the view.
    New {
        path: PathBuf,
        choose_key: &'a dyn Fn(Option<&str>) -> Result<String, Error>,
    },
}
