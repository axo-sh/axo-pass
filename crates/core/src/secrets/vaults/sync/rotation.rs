//! Key rotation and Remove Mac (`06-keys-and-pairing.md`, "Key rotation").
//!
//! A rotation generates a sync key under the next key id. "Remove Mac" writes
//! a `Removal` with the new key id for each removed replica, and "Rotate sync
//! key" removes none. "Revoke and replace" removes the `recovery` entry of
//! one kit in the same write id, and removes no replica. The rotating replica
//! wraps the new key to the pinned encryption key of each remaining replica
//! in its own `key.json`, signs each wrapping with its `device-signing-key`
//! (`wrapping.rs`), and publishes under the new key id. A remaining replica is
//! a replica of `replica_keys` with an unrevoked pin that is not this replica,
//! not removed, and has not left. A replica with no pin receives no wrapping
//! and is listed.
//!
//! The rotation of a replica removed as retired runs only after its state
//! files are local and joined. The wait for the downloads runs outside the
//! vault locks. The transaction ends with `RotationWaiting` and rotates
//! nothing if one of its files is still remote. After the publish, the
//! directory of a replica removed as lost or stolen is deleted. The
//! directory of a retired replica is deleted only if every listed file of it
//! was joined, so the published file covers it.
//!
//! Each transaction that syncs reads the `key.json` of every peer before the
//! peer joins. A signed `Device` wrapping to this replica under a key id
//! above the accepted key, or under the accepted key id with another
//! fingerprint, is verified against the pinned signing key of the directory
//! that holds it and kept in the signed header as a pending rotation. Joins
//! of the files of the replicas it removes are paused until the user
//! answers. A rotation signed by a revoked or removed replica is rejected
//! without a prompt. A wrapping that fails its signature is skipped.
//!
//! Concurrent rotations to one key id are decided by [`winner`]: a rotation
//! signed by a replica the other removes loses, then the lower fingerprint
//! wins. If each removes the signer of the other, the user chooses. A
//! replica that signed one of the two stays with its own.
//!
//! A revoked kit receives no `Age` wrapping of the new key, since the
//! `recovery` map no longer holds its recipient. The rotation and each
//! acceptance drop from the own `key.json` the `Age` wrappings of recipients
//! that the map no longer holds, under any key id, so the copies of the
//! current key for the revoked kit are deleted. The `key.json` of another
//! replica keeps its copies until that replica accepts the rotation or
//! rotates. A copy that a sync service or a backup kept stays readable with
//! the kit, and opens only the key it wraps. The wrappings of key ids below
//! the current key are also dropped once every remaining replica has
//! published under it (`SyncTxn::write_key_file`).
//!
//! Accepting a rotation adds its key, revokes the pins of the replicas it
//! removes, writes their `Removal` entries if the state lacks them, and
//! publishes under the new key. Every later state file under a lower key id
//! is ignored. Declining it drops it, so the joins it paused resume. A
//! declined rotation under a key id above the accepted key pauses sync with
//! `RotationDeclined`, since the Macs that accepted it ignore this Mac.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::audit_events::SyncEvents;
use super::crdt::{ReplicaId, Session};
use super::keys::{KeyFingerprint, SyncKey, SyncKeyWrapper};
use super::local_state::LocalSyncState;
use super::model::{KeyId, SyncState};
use super::sidecar::Sidecar;
use super::transport::{FileName, ReadResult, SyncTransport};
use super::txn::SyncTxn;
use super::wrapping::{DeviceUnwrap, DeviceWrapping, KeyFile};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::encrypted_vault::VaultHeader;
use crate::secrets::vaults::format::signing::VaultSigner;
use crate::secrets::vaults::storage::txn::{Committed, Target, Unlock, VaultWriter};

/// Most rejected rotations the sidecar records, for one audit event each.
const MAX_REJECTED: usize = 64;

/// Signed rotation to one key: its signer, its key, and the replicas it
/// removes and keeps, as one `Device` wrapping lists them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationRecord {
    /// Replica whose `key.json` holds the wrapping and whose key signed it.
    pub signer: ReplicaId,
    pub key_id: KeyId,
    pub key_fingerprint: KeyFingerprint,
    pub removed: Vec<ReplicaId>,
    pub remaining: Vec<ReplicaId>,
}

impl RotationRecord {
    /// Record of the signed wrapping `wrapping` in the `key.json` of
    /// `signer`.
    fn of(wrapping: &DeviceWrapping, signer: ReplicaId) -> Self {
        Self {
            signer,
            key_id: wrapping.key_id,
            key_fingerprint: wrapping.key_fingerprint,
            removed: wrapping.removed.clone().unwrap_or_default(),
            remaining: wrapping.remaining.clone().unwrap_or_default(),
        }
    }

    /// Whether `other` has the signer, key id, and fingerprint of this
    /// record.
    pub fn same(&self, other: &Self) -> bool {
        self.signer == other.signer
            && self.key_id == other.key_id
            && self.key_fingerprint == other.key_fingerprint
    }

    pub fn removes(&self, replica: ReplicaId) -> bool {
        self.removed.contains(&replica)
    }

    /// Text id of the record for the sidecar.
    fn id(&self) -> String {
        format!(
            "{}:{}:{}",
            self.signer.0,
            self.key_id.0,
            self.key_fingerprint.to_hex()
        )
    }
}

/// Reason a Mac is removed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemovalReason {
    /// The Mac is no longer used. Its files are joined before the rotation,
    /// so its writes are kept.
    Retired,
    /// The rotation does not wait for its files. Writes that only its files
    /// hold are lost.
    Lost,
}

/// Replicas a rotation removes, with their reasons, and the recovery kits it
/// revokes. Both are empty for "Rotate sync key".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RotationPlan {
    pub removals: BTreeMap<ReplicaId, RemovalReason>,
    /// Age recipients of the kits whose `recovery` entries the rotation
    /// removes, under the write id of its `Removal` entries.
    pub revoke: BTreeSet<String>,
}

impl RotationPlan {
    /// Plan of "Rotate sync key", which removes no replica.
    pub fn rotate_key() -> Self {
        Self::default()
    }

    /// Plan that removes each of `removals` for its reason.
    pub fn remove(removals: impl IntoIterator<Item = (ReplicaId, RemovalReason)>) -> Self {
        Self {
            removals: removals.into_iter().collect(),
            ..Self::default()
        }
    }

    /// Plan that revokes the kit of the age recipient `recipient` and removes
    /// no replica.
    pub fn revoke_kit(recipient: impl Into<String>) -> Self {
        Self {
            revoke: BTreeSet::from([recipient.into()]),
            ..Self::default()
        }
    }

    /// Replicas removed as `reason`.
    pub fn with_reason(&self, reason: RemovalReason) -> Vec<ReplicaId> {
        self.removals
            .iter()
            .filter(|(_, r)| **r == reason)
            .map(|(replica, _)| *replica)
            .collect()
    }
}

/// Result of a rotation on the rotating Mac.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rotated {
    pub key_id: KeyId,
    pub removed: Vec<ReplicaId>,
    /// Replicas that received a wrapping.
    pub remaining: Vec<ReplicaId>,
    /// Replicas of `replica_keys` with no pin. They received no wrapping
    /// and lose access.
    pub unpinned: Vec<ReplicaId>,
    /// Directories deleted after the publish.
    pub deleted: Vec<ReplicaId>,
    /// Directories of retired replicas kept, since the publish failed or did
    /// not cover every file of the replica.
    pub kept: Vec<ReplicaId>,
}

/// Result of accepting a rotation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Accepted {
    pub key_id: KeyId,
    /// Removals of the rotation this Mac signed that the accepted rotation
    /// replaced and did not include. The app runs them as a new rotation.
    pub repeat: Vec<ReplicaId>,
}

/// Winner of two rotations to one key id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Winner {
    First,
    Second,
    /// Each rotation removes the signer of the other. The user chooses.
    UserChoice,
}

/// Winner of the rotations `a` and `b` to one key id, by the rules in order:
/// a rotation signed by a replica that the other removes loses, then the
/// lower fingerprint wins. Fingerprints are compared in all 16 bytes.
pub fn winner(a: &RotationRecord, b: &RotationRecord) -> Winner {
    match (b.removes(a.signer), a.removes(b.signer)) {
        (true, true) => Winner::UserChoice,
        (true, false) => Winner::Second,
        (false, true) => Winner::First,
        (false, false) if a.key_fingerprint.0 <= b.key_fingerprint.0 => Winner::First,
        (false, false) => Winner::Second,
    }
}

/// Rotation the user is asked about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RotationPrompt {
    /// Accept or decline one rotation. `replaces` is set if it replaces the
    /// key this Mac uses, under the same key id.
    Confirm {
        rotation: RotationRecord,
        replaces: bool,
    },
    /// Two rotations that remove each other's signer. The user accepts one
    /// or declines both. `current` is set if this Mac uses the key of
    /// `first`.
    Choose {
        first: RotationRecord,
        second: RotationRecord,
        current: bool,
    },
}

/// Sync key of a rotation on this Mac, with its stored form, prepared before
/// the vault locks.
#[derive(Clone)]
pub(crate) struct NewKey {
    pub(crate) key: SyncKey,
    /// Key wrapped to `vault-encryption-key`, as the local keyring stores
    /// it.
    pub(crate) wrapped: String,
}

impl NewKey {
    /// New random key, wrapped by `wrapper`.
    pub(crate) fn generate(wrapper: &(impl SyncKeyWrapper + ?Sized)) -> Result<Self, Error> {
        Self::of(SyncKey::generate(), wrapper)
    }

    /// `key`, wrapped by `wrapper`.
    pub(crate) fn of(
        key: SyncKey,
        wrapper: &(impl SyncKeyWrapper + ?Sized),
    ) -> Result<Self, Error> {
        let wrapped = wrapper
            .wrap(key.as_bytes())
            .ok_or(Error::SyncKeyEncryptionError(0))?;
        Ok(Self { key, wrapped })
    }
}

/// Keys of this Mac that a rotation unwraps and stores keys with.
pub trait RotationKeys: DeviceUnwrap + SyncKeyWrapper {}

impl<T: DeviceUnwrap + SyncKeyWrapper> RotationKeys for T {}

/// Rotations found in the `key.json` of the peers.
#[derive(Debug, Default)]
pub(crate) struct Found {
    /// Verified rotations not yet pending, declined, or accepted.
    pub(crate) verified: Vec<RotationRecord>,
    /// Rotations signed by a revoked or removed replica.
    pub(crate) rejected: Vec<RotationRecord>,
}

/// Rotations of the local sync state.
pub(crate) struct Rotations;

impl Rotations {
    /// Signed `Device` wrappings to the replica of `local` in the `key.json`
    /// of every other listed replica, checked against `local` and `state`.
    /// `current` is the fingerprint of the accepted key. A `key.json` that
    /// is missing, remote, or fails to parse, and a listing that fails, are
    /// skipped.
    pub(crate) fn find(
        transport: &dyn SyncTransport,
        local: &LocalSyncState,
        state: &SyncState,
        current: KeyFingerprint,
    ) -> Found {
        let vault_id = local.vault_id;
        let own = local.replica_id;
        let mut found = Found::default();
        let Ok(replicas) = transport.list_replicas(vault_id) else {
            return found;
        };
        for signer in replicas.into_iter().filter(|replica| *replica != own) {
            let Ok(ReadResult::Local(bytes)) = transport.read(vault_id, signer, FileName::Key)
            else {
                continue;
            };
            let Ok(file) = KeyFile::parse(&bytes) else {
                continue;
            };
            for wrapping in file.devices() {
                if wrapping.to_replica != own || wrapping.signature.is_none() {
                    continue;
                }
                let record = RotationRecord::of(wrapping, signer);
                if !Self::is_new(local, &record, current) {
                    continue;
                }
                match Self::check(vault_id, local, state, wrapping, &record) {
                    Ok(()) => found.verified.push(record),
                    Err(Check::Revoked) => found.rejected.push(record),
                    Err(Check::Invalid(reason)) => log::info!(
                        "Rotation wrapping of replica {} in vault {vault_id} is skipped: {reason}",
                        signer.0
                    ),
                }
            }
        }
        found
    }

    /// Whether `record` is a rotation that `local` neither accepted, holds
    /// pending, nor declined: a key id above the accepted key, or the
    /// accepted key id with a fingerprint other than `current`. Key id 1 is
    /// never a rotation.
    fn is_new(local: &LocalSyncState, record: &RotationRecord, current: KeyFingerprint) -> bool {
        let newer = record.key_id.0 > local.key_id.0;
        let concurrent = record.key_id == local.key_id && record.key_fingerprint != current;
        let known = |list: &[RotationRecord]| list.iter().any(|r| r.same(record));
        record.key_id.0 > 1
            && (newer || concurrent)
            && !known(&local.pending_rotations)
            && !known(&local.declined_rotations)
            && local.rotation.as_ref().is_none_or(|r| !r.same(record))
    }

    /// Check the signed wrapping `wrapping` of `record`: its signer is
    /// pinned, not revoked, and not removed in `state`, the signature
    /// verifies against the pin, this replica is in `remaining` and not in
    /// `removed`, and no replica is in both lists.
    fn check(
        vault_id: Uuid,
        local: &LocalSyncState,
        state: &SyncState,
        wrapping: &DeviceWrapping,
        record: &RotationRecord,
    ) -> Result<(), Check> {
        let invalid = |reason: &str| Err(Check::Invalid(reason.to_string()));
        let Some(pin) = local.pinned_keys.get(&record.signer) else {
            return invalid("signer is not pinned");
        };
        if let Err(e) = wrapping.verify_rotation(vault_id, record.signer, &pin.signing) {
            return invalid(&e.to_string());
        }
        if pin.revoked || state.removed.get(&record.signer).is_some() {
            return Err(Check::Revoked);
        }
        let own = local.replica_id;
        if record.removes(own) || !record.remaining.contains(&own) {
            return invalid("this replica is not listed as keeping access");
        }
        if record.removes(record.signer) {
            return invalid("rotation removes its signer");
        }
        if record.removed.iter().any(|r| record.remaining.contains(r)) {
            return invalid("a replica is both removed and remaining");
        }
        Ok(())
    }

    /// Add the verified rotations of `found` to the pending rotations of
    /// `local`, record the rejected ones in `sidecar` with one event each,
    /// and settle the pending rotations against the accepted one. Returns
    /// whether `local` changed.
    pub(crate) fn add(
        local: &mut LocalSyncState,
        found: Found,
        current: KeyFingerprint,
        sidecar: &mut Sidecar,
        events: &mut SyncEvents,
    ) -> (bool, bool) {
        let mut changed = false;
        let mut sidecar_changed = false;
        for record in found.rejected {
            let id = record.id();
            if !sidecar.rejected_rotations.contains(&id) {
                log::warn!(
                    "Vault {} rejects a rotation signed by revoked replica {}",
                    local.vault_id,
                    record.signer.0
                );
                events.rotation("rejected", record.signer, record.key_id.0, &record.removed);
                sidecar.rejected_rotations.push(id);
                let excess = sidecar
                    .rejected_rotations
                    .len()
                    .saturating_sub(MAX_REJECTED);
                sidecar.rejected_rotations.drain(..excess);
                sidecar_changed = true;
            }
        }
        for record in found.verified {
            log::info!(
                "Vault {} holds a verified rotation to key {} signed by replica {}",
                local.vault_id,
                record.key_id.0,
                record.signer.0
            );
            local.pending_rotations.push(record);
            changed = true;
        }
        changed |= Self::settle(local, current, events);
        (changed, sidecar_changed)
    }

    /// Drop the pending rotations of `local` that an accepted rotation
    /// decides. A rotation under a lower key id than the accepted key is
    /// dropped. A rotation under the accepted key id that loses to the
    /// accepted rotation is declined. So is one that each removes the signer
    /// of the other, if this replica signed the accepted rotation. `current`
    /// is the fingerprint of the accepted key. Returns whether `local`
    /// changed.
    pub(crate) fn settle(
        local: &mut LocalSyncState,
        current: KeyFingerprint,
        events: &mut SyncEvents,
    ) -> bool {
        let own = local.replica_id;
        let key_id = local.key_id;
        let before = local.pending_rotations.len();
        let pending = std::mem::take(&mut local.pending_rotations);
        for record in pending {
            if record.key_id.0 < key_id.0 {
                continue;
            }
            if record.key_id == key_id {
                if record.key_fingerprint == current {
                    continue;
                }
                let Some(accepted) = &local.rotation else {
                    continue;
                };
                let lost = match winner(accepted, &record) {
                    Winner::First => true,
                    Winner::Second => false,
                    Winner::UserChoice => accepted.signer == own,
                };
                if lost {
                    events.rotation("lost", record.signer, record.key_id.0, &record.removed);
                    local.declined_rotations.push(record);
                    continue;
                }
            }
            local.pending_rotations.push(record);
        }
        local.pending_rotations.len() != before
    }

    /// Replicas removed by the pending rotations of `local`, whose files are
    /// not joined.
    pub(crate) fn paused(local: &LocalSyncState) -> BTreeSet<ReplicaId> {
        local
            .pending_rotations
            .iter()
            .flat_map(|record| record.removed.iter().copied())
            .collect()
    }

    /// Signer of a declined rotation under a key id above the accepted key,
    /// which cuts this Mac off from the Macs that accepted it.
    pub(crate) fn declined_signer(local: &LocalSyncState) -> Option<ReplicaId> {
        local
            .declined_rotations
            .iter()
            .filter(|record| record.key_id.0 > local.key_id.0)
            .map(|record| record.signer)
            .next()
    }

    /// Prompts of the pending rotations of `local`. The pending rotations of
    /// the highest key id are asked about first: the winner of them, or two
    /// that each remove the signer of the other. Otherwise each pending
    /// rotation under the accepted key id replaces the accepted one, or is
    /// a choice against it.
    pub(crate) fn prompts(local: &LocalSyncState) -> Vec<RotationPrompt> {
        let Some(top) = local.pending_rotations.iter().map(|r| r.key_id.0).max() else {
            return Vec::new();
        };
        let group: Vec<&RotationRecord> = local
            .pending_rotations
            .iter()
            .filter(|r| r.key_id.0 == top)
            .collect();
        if top > local.key_id.0 {
            let mut best = group[0];
            for record in &group[1..] {
                match winner(best, record) {
                    Winner::First => {},
                    Winner::Second => best = record,
                    Winner::UserChoice => {
                        return vec![RotationPrompt::Choose {
                            first: best.clone(),
                            second: (*record).clone(),
                            current: false,
                        }];
                    },
                }
            }
            return vec![RotationPrompt::Confirm {
                rotation: best.clone(),
                replaces: false,
            }];
        }
        let Some(accepted) = &local.rotation else {
            return Vec::new();
        };
        group
            .into_iter()
            .map(|record| match winner(accepted, record) {
                Winner::UserChoice => RotationPrompt::Choose {
                    first: accepted.clone(),
                    second: record.clone(),
                    current: true,
                },
                _ => RotationPrompt::Confirm {
                    rotation: record.clone(),
                    replaces: true,
                },
            })
            .collect()
    }

    /// Signed wrapping of `record` in the `key.json` of its signer, read
    /// through `transport`, verified against the pin of the signer in
    /// `local`. Fails if the file or the wrapping is missing, or the
    /// signature fails.
    pub(crate) fn wrapping_of(
        transport: &dyn SyncTransport,
        local: &LocalSyncState,
        record: &RotationRecord,
    ) -> Result<DeviceWrapping, Error> {
        let vault_id = local.vault_id;
        let refused = |reason: &str| Error::RotationRefused(reason.to_string());
        let pin = local
            .pinned_keys
            .get(&record.signer)
            .ok_or_else(|| refused("signer is not pinned"))?;
        let bytes = match transport.read(vault_id, record.signer, FileName::Key)? {
            ReadResult::Local(bytes) => bytes,
            _ => return Err(refused("key.json of the signer is not local")),
        };
        let file = KeyFile::parse(&bytes).map_err(|e| refused(&e.to_string()))?;
        let wrapping = file
            .devices()
            .find(|w| {
                w.to_replica == local.replica_id
                    && w.signature.is_some()
                    && RotationRecord::of(w, record.signer) == *record
            })
            .ok_or_else(|| refused("signer key.json lacks the wrapping"))?;
        wrapping.verify_rotation(vault_id, record.signer, &pin.signing)?;
        Ok(wrapping.clone())
    }
}

/// Failure of the check of a signed wrapping.
enum Check {
    /// Signer is revoked or removed. Rejected without a prompt.
    Revoked,
    /// Wrapping is skipped for the reason.
    Invalid(String),
}

/// Step of a rotation, an acceptance, a decline, or a cleanup in the
/// transaction of one vault. It runs before the peer joins, after the joins
/// and the first-use pins, and after the publish.
pub(crate) enum RotationStep<'a> {
    Rotate {
        plan: &'a RotationPlan,
        key: NewKey,
        rotated: Option<Rotated>,
    },
    Accept {
        record: &'a RotationRecord,
        key: NewKey,
        accepted: Option<Accepted>,
    },
    Decline {
        records: &'a [RotationRecord],
    },
    Clean {
        replica: ReplicaId,
        cleaned: Option<Cleaned>,
    },
}

/// Result of a cleanup.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cleaned {
    /// Whether the directory was deleted. It is kept if the publish failed
    /// or did not cover every file of the replica.
    pub deleted: bool,
}

impl RotationStep<'_> {
    /// Accept or decline before the peer joins, after the own files. A
    /// decline resumes the joins it paused. An acceptance joins the peer
    /// files under the new key in the same transaction. An acceptance is
    /// refused with no transport.
    pub(crate) fn before_peers(
        &mut self,
        sync: &mut SyncTxn,
        transport: Option<&dyn SyncTransport>,
        session: &mut Session,
        now: i64,
    ) -> Result<(), Error> {
        match self {
            Self::Decline { records } => sync.decline_rotations(records),
            Self::Accept {
                record,
                key,
                accepted,
            } => {
                if transport.is_none() {
                    return Err(Error::RotationRefused(
                        "synced folder cannot be reached".to_string(),
                    ));
                }
                *accepted = Some(sync.accept_rotation(record, key.clone(), session, now)?);
                Ok(())
            },
            _ => Ok(()),
        }
    }

    /// Rotate or clean up on the joined state. Refused with no transport.
    pub(crate) fn after_joins(
        &mut self,
        sync: &mut SyncTxn,
        transport: Option<&dyn SyncTransport>,
        session: &mut Session,
        now: i64,
        signer: &dyn VaultSigner,
    ) -> Result<(), Error> {
        if matches!(self, Self::Decline { .. } | Self::Accept { .. }) {
            return Ok(());
        }
        let Some(transport) = transport else {
            return Err(Error::RotationRefused(
                "synced folder cannot be reached".to_string(),
            ));
        };
        match self {
            Self::Rotate { plan, key, rotated } => {
                sync.check_joined(transport, &plan.with_reason(RemovalReason::Retired))?;
                *rotated = Some(sync.rotate(plan, key.clone(), session, now)?);
            },
            Self::Clean { replica, cleaned } => {
                sync.clean_replica(transport, *replica, session, now, signer)?;
                *cleaned = Some(Cleaned::default());
            },
            Self::Decline { .. } | Self::Accept { .. } => {},
        }
        Ok(())
    }

    /// Delete the directories of the removed or cleaned replicas after the
    /// publish. A lost or stolen replica is deleted if `published`. A
    /// retired or cleaned replica is deleted if `published` and every listed
    /// file of it was joined. A failed delete is logged and keeps the
    /// directory.
    pub(crate) fn after_publish(
        &mut self,
        sync: &SyncTxn,
        transport: &dyn SyncTransport,
        published: bool,
    ) {
        let vault_id = sync.vault_id();
        let delete = |replica: ReplicaId| match transport.delete_replica(vault_id, replica) {
            Ok(()) => {
                log::info!(
                    "Deleted the directory of replica {} of vault {vault_id}",
                    replica.0
                );
                true
            },
            Err(e) => {
                log::warn!(
                    "Failed to delete the directory of replica {} of vault {vault_id}: {e}",
                    replica.0
                );
                false
            },
        };
        match self {
            Self::Rotate {
                plan,
                rotated: Some(rotated),
                ..
            } => {
                for (replica, reason) in &plan.removals {
                    let deletes = published
                        && (*reason == RemovalReason::Lost || sync.covers(transport, *replica));
                    if deletes && delete(*replica) {
                        rotated.deleted.push(*replica);
                    } else {
                        rotated.kept.push(*replica);
                    }
                }
            },
            Self::Clean {
                replica,
                cleaned: Some(cleaned),
            } => {
                cleaned.deleted = published && sync.covers(transport, *replica) && delete(*replica);
            },
            _ => {},
        }
    }
}

impl VaultWriter {
    /// Rotate the sync key of the vault `target` and remove the replicas of
    /// `plan`, in one transaction (see the module comment). The new key is
    /// generated and wrapped to `vault-encryption-key` before the locks.
    /// Fails with `RotationWaiting` and writes nothing if a file of a
    /// retired replica is still remote. [`Self::rotate_waiting`] waits for
    /// those files first.
    pub fn rotate(
        &self,
        target: &Target,
        unlock: Unlock<'_>,
        plan: &RotationPlan,
    ) -> Result<Committed<Rotated>, Error> {
        let key = self.with_rotation_keys(&unlock, |keys| NewKey::generate(keys))?;
        let mut step = RotationStep::Rotate {
            plan,
            key,
            rotated: None,
        };
        let committed = self.write_rotating(target, unlock, &mut step)?;
        let RotationStep::Rotate { rotated, .. } = step else {
            unreachable!("step is a rotation");
        };
        Ok(committed.with_value(rotated.unwrap_or_default()))
    }

    /// Replicas of `replicas` with a listed state file of the vault `target`
    /// that is not local, after a download request for the vault. Takes no
    /// vault lock and decrypts nothing. A file that the sidecar records as
    /// joined is not read.
    pub fn remote_files(
        &self,
        target: &Target,
        replicas: &[ReplicaId],
    ) -> Result<Vec<ReplicaId>, Error> {
        if replicas.is_empty() {
            return Ok(Vec::new());
        }
        let id = VaultHeader::peek(&target.path)?.id;
        let sidecar = Sidecar::read(self.root(), id)?;
        let transport = self
            .transport_of(sidecar.transport.as_ref())?
            .ok_or_else(|| Error::RotationRefused("vault has no synced folder".to_string()))?;
        if let Err(e) = transport.request_download(id) {
            log::warn!("Failed to request the download of the files of vault {id}: {e}");
        }
        let mut remote = Vec::new();
        for replica in replicas {
            for hash in transport.list_states(id, *replica)? {
                if sidecar.is_joined(*replica, hash) {
                    continue;
                }
                if matches!(
                    transport.read(id, *replica, FileName::State(hash))?,
                    ReadResult::Remote
                ) {
                    remote.push(*replica);
                    break;
                }
            }
        }
        Ok(remote)
    }

    /// [`Self::rotate`] after the files of the replicas `plan` removes as
    /// retired are local. While a file is remote, `wait` is called with the
    /// replicas whose files are still downloading, outside the vault locks.
    /// It returns whether to keep waiting. A transaction that finds a file
    /// still remote waits again. The rotation never runs without the join.
    /// Fails with `RotationCancelled` if `wait` returns false.
    pub fn rotate_waiting<'u>(
        &self,
        target: &Target,
        unlock: impl Fn() -> Unlock<'u>,
        plan: &RotationPlan,
        wait: impl FnMut(&[ReplicaId]) -> bool,
    ) -> Result<Committed<Rotated>, Error> {
        let retired = plan.with_reason(RemovalReason::Retired);
        self.waiting(target, &retired, wait, || {
            self.rotate(target, unlock(), plan)
        })
    }

    /// Run `run` once no file of `replicas` is remote, waiting with `wait`
    /// as [`Self::rotate_waiting`] states.
    pub(crate) fn waiting<R>(
        &self,
        target: &Target,
        replicas: &[ReplicaId],
        mut wait: impl FnMut(&[ReplicaId]) -> bool,
        mut run: impl FnMut() -> Result<R, Error>,
    ) -> Result<R, Error> {
        loop {
            let remote = self.remote_files(target, replicas)?;
            if !remote.is_empty() {
                if !wait(&remote) {
                    return Err(Error::RotationCancelled);
                }
                continue;
            }
            match run() {
                Err(Error::RotationWaiting(ids)) => {
                    let remote: Vec<ReplicaId> = ids.into_iter().map(ReplicaId).collect();
                    if !wait(&remote) {
                        return Err(Error::RotationCancelled);
                    }
                },
                other => return other,
            }
        }
    }

    /// [`Self::rotate_waiting`] for each vault of `picks`, by vault id, in
    /// order, with its plan. Each vault runs its own transactions with the
    /// unlock that `unlock` returns for its target, `Unlock::App` in the app,
    /// so the user sees the one prompt of the app unlock. `wait` is called
    /// with the vault id. A vault that fails does not stop the others, and
    /// is returned with its error.
    pub fn rotate_vaults<'u>(
        &self,
        picks: &[(Uuid, Target, RotationPlan)],
        unlock: impl Fn(&Target) -> Unlock<'u>,
        mut wait: impl FnMut(Uuid, &[ReplicaId]) -> bool,
    ) -> Vec<(Uuid, Result<Rotated, Error>)> {
        picks
            .iter()
            .map(|(vault_id, target, plan)| {
                let result = self.rotate_waiting(
                    target,
                    || unlock(target),
                    plan,
                    |remote| wait(*vault_id, remote),
                );
                if let Err(e) = &result {
                    log::warn!("Vault {vault_id} was not rotated: {e}");
                }
                (*vault_id, result.map(|committed| committed.value))
            })
            .collect()
    }

    /// Accept the pending rotation `record` of the vault `target`. Before
    /// the locks, the wrapping of `record` is read from the `key.json` of
    /// its signer, verified against the pinned signing key in the local sync
    /// state, and unwrapped with `vault-encryption-key`, which can prompt.
    /// Under the locks the transaction checks that `record` is still pending
    /// and accepts it (see the module comment).
    pub fn accept_rotation(
        &self,
        target: &Target,
        unlock: Unlock<'_>,
        record: &RotationRecord,
    ) -> Result<Committed<Accepted>, Error> {
        let id = VaultHeader::peek(&target.path)?.id;
        let local = LocalSyncState::load(self.root(), id, &**self.signer())
            .map_err(|e| Error::RotationRefused(e.to_string()))?;
        if local.vault_id != id || !local.pending_rotations.contains(record) {
            return Err(Error::RotationRefused(
                "rotation is not pending".to_string(),
            ));
        }
        let sidecar = Sidecar::read(self.root(), id)?;
        let transport = self
            .transport_of(sidecar.transport.as_ref())?
            .ok_or_else(|| Error::RotationRefused("vault has no synced folder".to_string()))?;
        let wrapping = Rotations::wrapping_of(&*transport, &local, record)?;
        let key =
            self.with_rotation_keys(&unlock, |keys| NewKey::of(wrapping.unwrap(keys)?, keys))?;
        let mut step = RotationStep::Accept {
            record,
            key,
            accepted: None,
        };
        let committed = self.write_rotating(target, unlock, &mut step)?;
        let RotationStep::Accept { accepted, .. } = step else {
            unreachable!("step is an acceptance");
        };
        Ok(committed.with_value(accepted.unwrap_or_default()))
    }

    /// Decline the pending rotations `records` of the vault `target`, in one
    /// transaction. The joins they paused resume in it.
    pub fn decline_rotations(
        &self,
        target: &Target,
        unlock: Unlock<'_>,
        records: &[RotationRecord],
    ) -> Result<Committed<()>, Error> {
        let mut step = RotationStep::Decline { records };
        self.write_rotating(target, unlock, &mut step)
    }
}
