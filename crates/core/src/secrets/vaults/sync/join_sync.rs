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
//!
//! A pairing import runs on the `SyncManager` thread, which holds the keys
//! of the pairing (D6 of doc 18). Each paired vault waits in an
//! [`ImportWait`] until a state file of the Mac that paired is local and
//! decodes under the received key, then joins as the [`PairingImport`] of
//! the caller states. A kit import waits in the UI, which calls
//! `RecoveryImport::check` again until it returns the key (D7 of doc 18).

use std::collections::BTreeMap;
use std::path::PathBuf;

use uuid::Uuid;

use super::crdt::ReplicaId;
use super::keys::{SyncKey, SyncKeyring};
use super::model::{KeyId, ReplicaKeys};
use super::pairing::PairedVault;
use super::recovery::import::RecoveredKey;
use super::state_file::{StateFile, StateSource};
use super::transport::{FileName, ReadResult, SyncTransport, TransportRoot};
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

/// Import of the vaults of a pairing on the new Mac (D6 of doc 18), as the
/// caller states it.
#[derive(Clone, Debug)]
pub struct PairingImport {
    /// Display name of this Mac.
    pub name: String,
    /// Synced folder of the pairing.
    pub root: TransportRoot,
    /// Vault that each vault id of the request map joins into (D5). A vault
    /// id with no entry is imported as a new vault.
    pub into: BTreeMap<Uuid, JoinInto>,
}

impl PairingImport {
    /// Vault that vault `vault_id` joins into.
    pub(crate) fn join_into(&self, vault_id: Uuid) -> JoinInto {
        self.into.get(&vault_id).cloned().unwrap_or(JoinInto::New)
    }
}

/// Why the import of a paired vault still waits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WaitReason {
    /// A state file of the Mac that paired is listed and not downloaded yet.
    NotDownloaded,
    /// The Mac that paired has published no state file.
    NoStateFile,
    /// State files are local and none decodes under the received key.
    Undecodable,
    /// The listing or a read failed, with the error text.
    Unreachable(String),
}

impl std::fmt::Display for WaitReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotDownloaded => f.write_str("Files of the other Mac are not downloaded yet"),
            Self::NoStateFile => f.write_str("The other Mac has not published this vault yet"),
            Self::Undecodable => {
                f.write_str("Files of the other Mac do not open with the received key")
            },
            Self::Unreachable(error) => write!(f, "Cannot read the synced location: {error}"),
        }
    }
}

/// Paired vault whose import waits for a state file of the Mac that paired
/// (D6 of doc 18, C11).
#[derive(Debug)]
pub(crate) struct ImportWait {
    vault: PairedVault,
    into: JoinInto,
    /// Keyring of the one received key, for the decode of the wait.
    keyring: SyncKeyring,
}

impl ImportWait {
    /// Wait of `vault`, which joins into `into`.
    pub fn new(vault: PairedVault, into: JoinInto) -> Self {
        let keyring = SyncKeyring::new(vec![(vault.key_id, vault.key.clone())])
            .expect("one key has no duplicate key id");
        Self {
            vault,
            into,
            keyring,
        }
    }

    pub fn vault_id(&self) -> Uuid {
        self.vault.vault_id
    }

    /// `None` if a state file of the Mac that paired is local and decodes
    /// under the received key. Otherwise the reason the wait holds.
    ///
    /// Each state file of the replica of the Mac that paired is checked with
    /// `is_local`, then read in full and decoded with `StateFile::decode`,
    /// since a folder sync tool can show a torn file as local. A torn file,
    /// or one under another key, does not end the wait. A file that is not
    /// local requests the download of the vault. A listing or read that
    /// fails is logged and ends nothing.
    pub fn check(&self, transport: &dyn SyncTransport) -> Option<WaitReason> {
        let vault_id = self.vault.vault_id;
        let peer = self.vault.peer;
        let hashes = match transport.list_states(vault_id, peer) {
            Ok(hashes) => hashes,
            Err(e) => {
                log::warn!("Import of vault {vault_id} failed to list the paired Mac's files: {e}");
                return Some(WaitReason::Unreachable(e.to_string()));
            },
        };
        let mut remote = false;
        let mut undecodable = false;
        let mut failure: Option<String> = None;
        let mut ready = false;
        for hash in hashes {
            let name = FileName::State(hash);
            match transport.is_local(vault_id, peer, name) {
                Ok(true) => {},
                Ok(false) => {
                    remote = true;
                    continue;
                },
                Err(e) => {
                    log::warn!("Import of vault {vault_id} failed to check state file {hash}: {e}");
                    failure = Some(e.to_string());
                    continue;
                },
            }
            let bytes = match transport.read(vault_id, peer, name) {
                Ok(ReadResult::Local(bytes)) => bytes,
                Ok(ReadResult::Remote) => {
                    remote = true;
                    continue;
                },
                Ok(ReadResult::Missing) => continue,
                Err(e) => {
                    log::warn!("Import of vault {vault_id} failed to read state file {hash}: {e}");
                    failure = Some(e.to_string());
                    continue;
                },
            };
            let source = StateSource {
                vault_id,
                replica_id: peer,
                hash,
            };
            match StateFile::decode(&bytes, &source, &self.keyring) {
                Ok(_) => {
                    ready = true;
                    break;
                },
                Err(e) => {
                    log::info!("Import of vault {vault_id} skips state file {hash}: {e}");
                    undecodable = true;
                },
            }
        }
        if ready {
            return None;
        }
        if remote && let Err(e) = transport.request_download(vault_id) {
            log::warn!("Failed to request the download of vault {vault_id}: {e}");
        }
        Some(if remote {
            WaitReason::NotDownloaded
        } else if let Some(failure) = failure {
            WaitReason::Unreachable(failure)
        } else if undecodable {
            WaitReason::Undecodable
        } else {
            WaitReason::NoStateFile
        })
    }

    /// Key and vault of the join that ends the wait. The wait stays intact,
    /// so a failed join can run again.
    pub fn join(&self) -> (JoinKey, JoinInto) {
        (JoinKey::paired(self.vault.clone()), self.into.clone())
    }
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
