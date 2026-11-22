//! Age import of the sync key with a recovery kit ("Age recovery kit").
//!
//! [`RecoveryImport::check`] reads the folder of the kit vault and does not
//! write it, other than the download request. It first reads the plaintext
//! header of every state file of every replica for its key id only, with no
//! decryption ([`StateFile::peek_key_id`]). A kit whose key id is below the
//! highest key id is refused. A planted header can refuse a kit, and no state
//! is accepted from it. While any state file is `Remote`, the check requests
//! its download and returns `Waiting`. It never skips the check. The user
//! cancels by not calling `check` again.
//!
//! The key is read from the `Age` wrappings of the kit recipient and key id
//! in every `key.json`. A key that is not 32 bytes, or whose fingerprint
//! differs from the kit fingerprint in any of the 16 bytes, is refused,
//! whatever `key_fingerprint` the wrapping holds.
//!
//! `VaultCatalog::import_recovered` takes a [`RecoveredKey`] and joins it
//! (`sync/join_sync.rs`).

use std::collections::BTreeSet;

use uuid::Uuid;

use super::RecoveryKit;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::keys::{SyncKey, SyncKeyring};
use crate::secrets::vaults::sync::model::KeyId;
use crate::secrets::vaults::sync::state_file::{StateFile, StateHash, StateSource};
use crate::secrets::vaults::sync::transport::{FileName, ReadResult, SyncTransport};
use crate::secrets::vaults::sync::wrapping::KeyFile;

/// Sync key recovered with a kit, for the import of milestone 10.
#[derive(Debug)]
pub struct RecoveredKey {
    pub vault_id: Uuid,
    pub key_id: KeyId,
    pub key: SyncKey,
    /// New replica id of this Mac in the vault.
    pub replica_id: ReplicaId,
}

/// Replica whose files are still downloading (D20).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WaitingReplica {
    pub replica: ReplicaId,
    /// Name of the Mac in a local state file that opens under the key that
    /// the kit fingerprint checked. `None` if no such file names it, shown as
    /// "another Mac".
    pub name: Option<String>,
}

/// Result of [`RecoveryImport::check`].
#[derive(Debug)]
pub enum RecoveryCheck {
    Recovered(RecoveredKey),
    /// Files of these replicas are `Remote`, and their download was
    /// requested.
    Waiting(Vec<WaitingReplica>),
    /// The kit key id is below the highest key id of a peer header.
    KitOutdated {
        kit: KeyId,
        highest: KeyId,
    },
    /// No `Age` wrapping of the folder opens the key of the kit.
    NoKey,
}

/// Age import of the sync key.
pub struct RecoveryImport;

impl RecoveryImport {
    /// Check the kit `kit` against the folder of its vault in `transport`.
    /// Fails if a directory or a file cannot be listed or read.
    pub fn check(kit: &RecoveryKit, transport: &dyn SyncTransport) -> Result<RecoveryCheck, Error> {
        let vault_id = kit.vault_id;
        let replicas = transport.list_replicas(vault_id)?;

        // Key id of every local state file, before any wrapping is read.
        let mut remote = BTreeSet::new();
        let mut local = Vec::new();
        let mut highest: Option<KeyId> = None;
        for replica in &replicas {
            for hash in transport.list_states(vault_id, *replica)? {
                match transport.read(vault_id, *replica, FileName::State(hash))? {
                    ReadResult::Missing => {},
                    ReadResult::Remote => {
                        remote.insert(*replica);
                    },
                    ReadResult::Local(bytes) => match StateFile::peek_key_id(&bytes) {
                        Ok(key_id) => {
                            if highest.is_none_or(|highest| key_id.0 > highest.0) {
                                highest = Some(key_id);
                            }
                            local.push((*replica, hash, bytes));
                        },
                        Err(e) => {
                            let name = StateFile::name(hash);
                            log::warn!("Age import ignores state file {name}: {e}");
                        },
                    },
                }
            }
        }
        if let Some(highest) = highest.filter(|highest| highest.0 > kit.key_id.0) {
            log::warn!(
                "Recovery kit of vault {vault_id} is under key {}, below key {}",
                kit.key_id.0,
                highest.0
            );
            return Ok(RecoveryCheck::KitOutdated {
                kit: kit.key_id,
                highest,
            });
        }

        let mut remote_keys = BTreeSet::new();
        let key = Self::find_key(kit, transport, &replicas, &mut remote_keys)?;
        if !remote.is_empty() {
            transport.request_download(vault_id)?;
            let waiting = Self::waiting(kit, key.as_ref(), &remote, &local);
            return Ok(RecoveryCheck::Waiting(waiting));
        }
        match key {
            Some(key) => Ok(RecoveryCheck::Recovered(RecoveredKey {
                vault_id,
                key_id: kit.key_id,
                key,
                replica_id: ReplicaId::generate(),
            })),
            None if !remote_keys.is_empty() => {
                transport.request_download(vault_id)?;
                Ok(RecoveryCheck::Waiting(Self::waiting(
                    kit,
                    None,
                    &remote_keys,
                    &local,
                )))
            },
            None => Ok(RecoveryCheck::NoKey),
        }
    }

    /// First key of an `Age` wrapping of the kit recipient and key id in the
    /// `key.json` of `replicas` that the kit opens. A `Remote` `key.json` is
    /// added to `remote`. A file that fails to parse is skipped.
    fn find_key(
        kit: &RecoveryKit,
        transport: &dyn SyncTransport,
        replicas: &[ReplicaId],
        remote: &mut BTreeSet<ReplicaId>,
    ) -> Result<Option<SyncKey>, Error> {
        let vault_id = kit.vault_id;
        let recipient = kit.recipient();
        for replica in replicas {
            let bytes = match transport.read(vault_id, *replica, FileName::Key)? {
                ReadResult::Missing => continue,
                ReadResult::Remote => {
                    remote.insert(*replica);
                    continue;
                },
                ReadResult::Local(bytes) => bytes,
            };
            let file = match KeyFile::parse(&bytes) {
                Ok(file) => file,
                Err(e) => {
                    log::warn!("Age import skips key.json of replica {}: {e}", replica.0);
                    continue;
                },
            };
            let wrappings = file
                .ages()
                .filter(|age| age.recipient == recipient && age.key_id == kit.key_id);
            for wrapping in wrappings {
                match wrapping.unwrap(kit.identity()) {
                    Ok(key) if kit.opens(&key) => return Ok(Some(key)),
                    Ok(_) => log::warn!(
                        "Age import refuses a key of replica {} with another fingerprint",
                        replica.0
                    ),
                    Err(e) => {
                        log::warn!("Age import skips a wrapping of replica {}: {e}", replica.0)
                    },
                }
            }
        }
        Ok(None)
    }

    /// Labels of the replicas `remote` (D20). The name of each is its shown
    /// name in a local state file of `local` that opens under `key`. The
    /// files are opened for the names only, and no state is kept.
    fn waiting(
        kit: &RecoveryKit,
        key: Option<&SyncKey>,
        remote: &BTreeSet<ReplicaId>,
        local: &[(ReplicaId, StateHash, Vec<u8>)],
    ) -> Vec<WaitingReplica> {
        let keyring = key.and_then(|key| SyncKeyring::new(vec![(kit.key_id, key.clone())]).ok());
        let states: Vec<_> = keyring
            .iter()
            .flat_map(|keyring| {
                local.iter().filter_map(move |(replica, hash, bytes)| {
                    let source = StateSource {
                        vault_id: kit.vault_id,
                        replica_id: *replica,
                        hash: *hash,
                    };
                    StateFile::decode(bytes, &source, keyring)
                        .ok()
                        .map(|(_, state)| state)
                })
            })
            .collect();
        remote
            .iter()
            .map(|replica| WaitingReplica {
                replica: *replica,
                name: states.iter().find_map(|state| {
                    state
                        .store
                        .replica_names
                        .get(replica)
                        .and_then(|register| register.shown())
                        .cloned()
                }),
            })
            .collect()
    }
}
