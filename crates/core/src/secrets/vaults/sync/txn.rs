//! Sync state in the write transaction of a synced vault.
//!
//! A transaction on a vault with a trusted sync state joins this replica's
//! own state files first, then the local state files of the other replicas,
//! before any write id is minted (`sync/join.rs`). If the joins listed a file
//! that is not local yet, the transaction asks the transport once to download
//! the files of the vault, and does not wait. If the join changed the
//! state, the view is applied to the vault without a diff. The requested
//! change then runs, and its local edits are recorded under one write id of
//! the session. `s` advances if and only if the vault file changes. The sync
//! state is saved if it or `s` changed, always before the vault.
//!
//! After the joins and the apply of the joined state, each peer of
//! `replica_keys` with no pin is pinned at first use (`sync/pins.rs`). A
//! stopped transaction pins nothing.
//!
//! Before the peer joins, the `key.json` of each peer is read for signed
//! rotations to this replica, and a verified one is kept as pending in the
//! header. The files of the replicas a pending rotation removes are not
//! joined. A rotation, an acceptance, a decline, and a cleanup are steps of
//! a transaction (`sync/rotation.rs`, `sync/cleanup.rs`). A change of the
//! key makes the transaction publish under the new key. An own
//! `replica_keys` register with a second value is superseded.
//!
//! A transaction that publishes writes the staged file before the sync state,
//! and copies it to the synced folder after the vault (`sync/publish.rs`).
//! The file blobs that the staged file needs are uploaded first
//! (`sync/blobs.rs`).
//! Before the copy, the own `key.json` is read and written once, with the
//! `Device` wrapping of a pairing grant and the missing `Age` wrappings of the
//! recovery recipients (`sync/recovery.rs`).
//!
//! Before any join, the no-edit guard diffs the vault as loaded against the
//! view of the state as loaded. If it finds edits, sync stops by drift. A
//! stopped transaction joins nothing, records no edit, mints no write id, and
//! publishes nothing. A save then reseals the unchanged body at the next
//! generation (`sync/status.rs`).
//!
//! The `v > s` repair and the recovery merge run in place of the guard. They
//! add the vault differences as concurrent values after the own files and
//! before the peer files (`sync/repair.rs`). A vault at `v > s` is saved at
//! `v + 1`.
//!
//! An apply or diff failure pauses sync and never fails the save. If the view
//! of the joined state fails to apply, the join is discarded, and the
//! requested change runs on the vault as it was before the join and is
//! recorded against the state as loaded. If the view fails to apply after a
//! recorded edit, the edit is kept and the vault is saved as the change left
//! it. If a diff fails, or the view fails to apply in a repair, the
//! transaction saves the vault only, at the next generation, so the next
//! transaction runs the `v > s` repair. A discarded join is not recorded as
//! joined, so the next transaction reads its files again.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use jiff::Timestamp;
use p256::ecdsa::VerifyingKey;
use uuid::Uuid;
use zeroize::Zeroizing;

#[cfg(test)]
use super::apply::ApplyFault;
use super::apply::ApplyReport;
use super::audit_events::SyncEvents;
use super::blobs;
use super::crdt::{CausalState, JoinOutcome, OwnFile, OwnFileState, ReplicaId, Session, WriteId};
use super::diff::LocalEdits;
use super::edit_check::{EditRefusal, EditRequest, RefusalReason, ResolvePick};
use super::join::{FileJoin, StateJoin};
use super::keys::{KeyFingerprint, SyncKey, SyncKeyring, WrappedSyncKey};
use super::load::TrustedState;
use super::local_state::LocalSyncState;
use super::model::{KeyId, Removal, ReplicaKeys, SyncState};
use super::pins::{PairedPin, Pins};
use super::publish::Staged;
use super::rebuild::Rebuild;
use super::recovery::{RecoveryAdd, RecoveryRecipients};
use super::repair::{Repair, SyncRequest};
use super::resolve::HistoryIds;
use super::rotation::{
    Accepted, NewKey, Rotated, RotationPlan, RotationPrompt, RotationRecord, Rotations,
};
use super::sidecar::{Health, Sidecar};
use super::state_file::StateHash;
use super::state_file::padded::PaddedBody;
use super::status::{BUILD_ID, FoundCauses, SyncStatus};
use super::transport::{FileName, ReadResult, SyncTransport, TransportRoot};
use super::view::VaultView;
use super::wrapping::{DeviceWrapping, KeyFile, Wrapping};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::files::store::BlobStore;
use crate::secrets::vaults::format::signing::VaultSigner;
use crate::secrets::vaults::model::{UnlockedKey, Vault};

/// Outcome of [`SyncTxn::record`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Recorded {
    /// The write id minted for the edits, or `None` if nothing was recorded.
    Minted(Option<WriteId>),
    /// The edit check refused the change. Nothing was recorded.
    Refused(EditRefusal),
}

/// Trusted sync state of one transaction, with the keyring that opened it and
/// the sidecar.
pub(crate) struct SyncTxn {
    local: LocalSyncState,
    state: CausalState<SyncState>,
    keyring: SyncKeyring,
    /// SHA-256 of the sync state file as loaded.
    loaded: StateHash,
    /// Generation `v` of a vault newer than the sync state.
    newer_vault: Option<u64>,
    /// Whether a join or a mint changed the state since it was loaded.
    changed: bool,
    /// Whether the publish fields, the stop fields, or the pins of the
    /// header changed since it was loaded.
    header_changed: bool,
    /// Padded body of the changed state, shared by the staged file and the
    /// sync state.
    padded: Option<Zeroizing<Vec<u8>>>,
    /// Own state files as the publish rules take them. `None` if no
    /// transport listed them.
    own_files: Option<Vec<OwnFile<StateHash>>>,
    /// Staged file to copy after the vault is saved.
    staged: Option<Staged>,
    sidecar: Sidecar,
    sidecar_changed: bool,
    /// Joined hashes of the sidecar as loaded, restored if the join is
    /// discarded.
    loaded_joined: BTreeMap<ReplicaId, BTreeSet<StateHash>>,
    /// `stopped_build` and `override_build` as loaded, restored if a repair
    /// is discarded.
    loaded_stop: (Option<String>, Option<String>),
    /// Whether the transaction runs a repair.
    repairing: bool,
    /// Whether the transaction saves the vault only, after a diff failure or
    /// a failed apply in a repair. It joins and records nothing more, stages
    /// nothing, and saves no sync state.
    vault_only: bool,
    /// Paused causes found by this transaction.
    found: FoundCauses,
    /// Audit events of this transaction, recorded after its saves.
    events: SyncEvents,
    /// Replicas whose peer files changed the state in this transaction.
    sources: BTreeSet<ReplicaId>,
    /// Count of listed own and peer files that are not local yet.
    remote: usize,
    /// Whether the peer join listed the replica directories and every peer
    /// directory.
    peers_listed: bool,
    /// Local blob store of the vault. `None` for a vault with no vault file.
    blob_store: Option<BlobStore>,
    /// Whether the publish listed the folder blobs and uploaded the missing
    /// ones, so [`Self::heal_blobs`] has nothing more to do.
    blobs_uploaded: bool,
    /// Replicas removed by pending rotations, whose files are not joined.
    paused: BTreeSet<ReplicaId>,
    /// Whether the transaction publishes whatever the context, after a
    /// change of the key.
    force_publish: bool,
    #[cfg(test)]
    apply_fault: Option<ApplyFault>,
}

impl SyncTxn {
    /// Transaction on `trusted`, opened with `keyring`, loaded from a file
    /// with hash `loaded`, and with the sidecar `sidecar`.
    pub(crate) fn new(
        trusted: TrustedState,
        keyring: SyncKeyring,
        loaded: StateHash,
        sidecar: Sidecar,
    ) -> Self {
        let TrustedState { local, state } = trusted;
        let events = SyncEvents::new(local.vault_id);
        let loaded_joined = sidecar.joined.clone();
        let loaded_stop = (local.stopped_build.clone(), local.override_build.clone());
        let paused = Rotations::paused(&local);
        let found = FoundCauses {
            declined: Rotations::declined_signer(&local),
            ..FoundCauses::default()
        };
        Self {
            local,
            state,
            keyring,
            loaded,
            newer_vault: None,
            changed: false,
            header_changed: false,
            padded: None,
            own_files: None,
            staged: None,
            sidecar,
            sidecar_changed: false,
            loaded_joined,
            loaded_stop,
            repairing: false,
            vault_only: false,
            found,
            events,
            sources: BTreeSet::new(),
            remote: 0,
            peers_listed: false,
            blob_store: None,
            blobs_uploaded: false,
            paused,
            force_publish: false,
            #[cfg(test)]
            apply_fault: None,
        }
    }

    /// Set the local blob store of the vault, whose blobs the publish
    /// uploads.
    pub(crate) fn set_blob_store(&mut self, store: BlobStore) {
        self.blob_store = Some(store);
    }

    /// Transaction on the first state of a sync setup: `local`, a sync state
    /// that no file holds yet, with an empty state, the keyring `keyring`,
    /// and the sidecar `sidecar`. The stage, the saves, the `key.json` write,
    /// and the publish are those of a transaction built by [`Self::new`]. The
    /// sidecar is saved even if the publish fails, so its root is kept.
    pub(crate) fn first(local: LocalSyncState, keyring: SyncKeyring, sidecar: Sidecar) -> Self {
        let trusted = TrustedState {
            local,
            state: CausalState::default(),
        };
        // No file was loaded, so no session continues from this hash.
        let mut txn = Self::new(trusted, keyring, StateHash::of(&[]), sidecar);
        txn.sidecar_changed = true;
        txn
    }

    /// Make the apply fail at the first item for which `fault` holds, as on
    /// a build whose view cannot be applied.
    #[cfg(test)]
    pub(crate) fn set_apply_fault(&mut self, fault: Option<ApplyFault>) {
        self.apply_fault = fault;
    }

    pub(crate) fn vault_id(&self) -> Uuid {
        self.local.vault_id
    }

    /// Replica of the sync state.
    pub(crate) fn replica(&self) -> ReplicaId {
        self.local.replica_id
    }

    /// SHA-256 of the sync state file as loaded.
    pub(crate) fn loaded(&self) -> StateHash {
        self.loaded
    }

    /// Generation `s` of the sync state.
    pub(crate) fn generation(&self) -> u64 {
        self.local.generation
    }

    /// Mark the vault as newer than the sync state, at generation `vault`.
    pub(crate) fn set_newer_vault(&mut self, vault: u64) {
        self.newer_vault = Some(vault);
    }

    /// Generation of the next save of the vault and the sync state: one past
    /// `s`, or one past `v` for a vault newer than the sync state, so an
    /// older copy of the vault loads as `v < s`.
    pub(crate) fn next_generation(&self) -> u64 {
        self.local.generation.max(self.newer_vault.unwrap_or(0)) + 1
    }

    /// Whether the vault is saved even if the transaction leaves it
    /// unchanged. A vault newer than the sync state is saved at the next
    /// generation, so `v == s` afterwards.
    pub(crate) fn forces_vault_save(&self) -> bool {
        self.newer_vault.is_some() && !self.vault_only
    }

    pub(crate) fn keyring(&self) -> &SyncKeyring {
        &self.keyring
    }

    /// Root of the transport in the sidecar as loaded.
    pub(crate) fn transport_root(&self) -> Option<&TransportRoot> {
        self.sidecar.transport.as_ref()
    }

    /// Record that the transport cannot be reached, with `error`.
    pub(crate) fn unreachable(&mut self, error: impl ToString) {
        self.found.unreachable(error);
    }

    /// Whether the sync state needs a save with no change to `s`: a join or a
    /// mint changed the state, or the header changed.
    /// A transaction that saves the vault only saves no sync state.
    pub(crate) fn needs_save(&self) -> bool {
        !self.vault_only && (self.changed || self.header_changed)
    }

    /// Whether a join or a mint changed the state, and the transaction saves
    /// the sync state.
    pub(crate) fn state_changed(&self) -> bool {
        !self.vault_only && self.changed
    }

    /// Whether the transaction saves the vault only, with no sync state.
    pub(crate) fn is_vault_only(&self) -> bool {
        self.vault_only
    }

    /// Whether the transaction joins, records, and stages: sync is not
    /// stopped, and no failure made the transaction save the vault only.
    pub(crate) fn syncs(&self) -> bool {
        !self.is_stopped() && !self.vault_only
    }

    /// Join each own state file listed by `transport` that the sidecar does
    /// not record as joined, as received by `session`. Returns whether the
    /// state changed. The listed files are kept for the publish rules.
    ///
    /// A file that is missing, `Remote`, under a key the keyring lacks, or of
    /// a newer format is retried in a later transaction. A file that fails a
    /// context check is refused and retried. A damaged file, and a state that
    /// fails the closure or duplicate write id check, is quarantined by path
    /// and content hash. A folder that cannot be listed joins nothing.
    pub(crate) fn join_own(
        &mut self,
        transport: &dyn SyncTransport,
        session: &mut Session,
    ) -> bool {
        let vault_id = self.vault_id();
        let replica = self.replica();
        let listed = match transport.list_states(vault_id, replica) {
            Ok(listed) => listed,
            Err(e) => {
                log::warn!("Failed to list own state files of vault {vault_id}: {e}");
                self.found.unreachable(e);
                return false;
            },
        };
        let mut join = self.join(session);
        let mut changed = false;
        let mut own_files = Vec::with_capacity(listed.len());
        let mut remote = 0;
        for hash in &listed {
            let file = join.file(transport, replica, *hash);
            changed |= file.changed();
            if file == FileJoin::Remote {
                remote += 1;
            }
            own_files.push(OwnFile {
                hash: *hash,
                state: file.into(),
            });
        }
        join.retain(replica, &listed);
        self.own_files = Some(own_files);
        self.remote += remote;
        self.changed |= changed;
        changed
    }

    /// Join the state files of every other replica that `transport` lists,
    /// as received by `session`, after the own files. Returns whether the
    /// state changed. Peer files are never deleted by this replica.
    ///
    /// A file is left, refused, or quarantined as [`Self::join_own`] states.
    /// A file under another fingerprint for its key id is ignored, and a
    /// file of a newer format is left. Both are read again in each later
    /// transaction. A file under another fingerprint for the current key id,
    /// from a replica with no pin that `replica_keys` lacks, pauses sync with
    /// `SeparateKey`. A folder or a replica directory that cannot be listed
    /// stops no other directory.
    pub(crate) fn join_peers(
        &mut self,
        transport: &dyn SyncTransport,
        session: &mut Session,
    ) -> bool {
        let own = self.replica();
        let join = self.join(session).peers(transport, own);
        self.remote += join.remote;
        self.peers_listed = join.listed;
        self.changed |= join.changed;
        self.sources.extend(join.sources);
        join.changed
    }

    /// Join `old`, the state of the replica that this Mac had before it adopted
    /// the key of a pairing, as received by `session`. A merge of two Macs
    /// that enabled sync separately does this in place of the recovery merge,
    /// so the writes and the removals of the old state are kept.
    pub(crate) fn join_merged(
        &mut self,
        old: CausalState<SyncState>,
        session: &mut Session,
    ) -> Result<(), Error> {
        let outcome = self
            .state
            .try_join(old, session)
            .map_err(|e| Error::SyncMergeFailed(e.to_string()))?;
        if outcome == JoinOutcome::Joined {
            self.mark_changed();
        }
        Ok(())
    }

    /// Whether a disable deletes the own replica directory in place of the
    /// final file (D11 of doc 18). The sidecar records `SeparateKey`, and
    /// `replica_keys` of the state holds no replica other than this one, so
    /// no other Mac reads the own files.
    pub(crate) fn leaves_separately(&self) -> bool {
        let own = self.replica();
        self.sidecar.separate_key()
            && self
                .state
                .store
                .replica_keys
                .iter()
                .all(|(replica, _)| *replica == own)
    }

    /// Whether the peer join listed the replica directories and every peer
    /// directory, whatever the outcome of each file.
    pub(crate) fn listed_every_peer(&self) -> bool {
        self.peers_listed
    }

    /// Ask `transport` once to make the files of the vault local, if the
    /// joins listed an own or peer file that is not local yet. The request
    /// does not wait. A failure is logged and pauses nothing. A transaction
    /// that listed nothing requests nothing.
    pub(crate) fn request_downloads(&self, transport: &dyn SyncTransport) {
        if self.remote == 0 {
            return;
        }
        let vault_id = self.vault_id();
        let remote = self.remote;
        log::info!("Vault {vault_id} lists {remote} state files that are not local");
        if let Err(e) = transport.request_download(vault_id) {
            log::warn!("Failed to request the download of the files of vault {vault_id}: {e}");
        }
    }

    /// Pin with `first_use` each peer of the `replica_keys` of the state that
    /// has no pin, after the joins and the apply of the joined state. A
    /// discarded join pins nothing it held. A pin changes the header only, so
    /// a save of the pins alone keeps `s` and the body ciphertext. A
    /// transaction that does not sync pins nothing.
    pub(crate) fn pin_first_use(&mut self) {
        if self.syncs() && Pins::pin_first_use(&mut self.local, &self.state) {
            self.header_changed = true;
        }
    }

    /// Pin `keys` for `replica` with `pairing` (D14). A changed pin sets the
    /// header changed, so a save of the pin alone keeps `s` and the body
    /// ciphertext.
    pub(crate) fn pin_paired(&mut self, replica: ReplicaId, keys: &ReplicaKeys) -> PairedPin {
        let pin = Pins::pin_paired(&mut self.local, replica, keys);
        if pin.changed() {
            self.header_changed = true;
        }
        pin
    }

    /// Fingerprint of the key of the body.
    fn current_fingerprint(&self) -> Option<KeyFingerprint> {
        self.current_key().map(|(_, key)| key.fingerprint())
    }

    /// Read the `key.json` of every peer that `transport` lists for signed
    /// rotations to this replica, before the peer joins (`sync/rotation.rs`).
    /// A verified rotation is kept as pending in the header, and the files
    /// of the replicas it removes are not joined. A transaction that does
    /// not sync reads nothing.
    pub(crate) fn find_rotations(&mut self, transport: &dyn SyncTransport) {
        if !self.syncs() || self.is_leaving() {
            return;
        }
        let Some(current) = self.current_fingerprint() else {
            return;
        };
        let found = Rotations::find(transport, &self.local, &self.state.store, current);
        let (changed, sidecar_changed) = Rotations::add(
            &mut self.local,
            found,
            current,
            &mut self.sidecar,
            &mut self.events,
        );
        self.header_changed |= changed;
        self.sidecar_changed |= sidecar_changed;
        self.settle_rotations();
    }

    /// Recompute the paused replicas and the declined cause from the header.
    fn settle_rotations(&mut self) {
        self.paused = Rotations::paused(&self.local);
        self.found.declined = Rotations::declined_signer(&self.local);
    }

    /// Prompts of the pending rotations.
    pub(crate) fn rotation_prompts(&self) -> Vec<RotationPrompt> {
        Rotations::prompts(&self.local)
    }

    /// Refuse a rotation step if sync does not run or is being disabled.
    fn check_rotation_step(&self) -> Result<(), Error> {
        if !self.syncs() {
            return Err(Error::RotationRefused(
                "sync is stopped or paused".to_string(),
            ));
        }
        if self.is_leaving() {
            return Err(Error::RotationRefused("sync is being disabled".to_string()));
        }
        Ok(())
    }

    /// Supersede the own `replica_keys` register with the keys of `signer`
    /// if it holds more than one value, under one write id of `session`
    /// minted at `now`. A transaction that does not sync writes nothing.
    pub(crate) fn supersede_own_keys(
        &mut self,
        session: &mut Session,
        now: i64,
        signer: &dyn VaultSigner,
    ) -> Result<(), Error> {
        if !self.syncs() || self.is_leaving() {
            return Ok(());
        }
        let replica = self.replica();
        let values = self
            .state
            .store
            .replica_keys
            .get(&replica)
            .map_or(0, |register| register.values().count());
        if values <= 1 {
            return Ok(());
        }
        let Some(keys) = self.own_keys(signer)? else {
            return Ok(());
        };
        let vault_id = self.vault_id();
        log::warn!("Vault {vault_id} supersedes {values} values of its own replica keys");
        let mut edits = LocalEdits::default();
        edits.add_own_keys(replica, keys);
        self.record_own_edits(edits, session, now).map(|_| ())
    }

    /// Whether `replica` has left: the shown value of its `left` register.
    fn has_left(&self, replica: ReplicaId) -> bool {
        self.state
            .store
            .left
            .get(&replica)
            .and_then(|left| left.shown())
            .copied()
            .unwrap_or(false)
    }

    /// Replace the key of `key_id` in the keyring and in the stored keyring
    /// with `key`, and make it the key of the body.
    fn install_key(&mut self, key_id: KeyId, key: NewKey) -> Result<(), Error> {
        let mut keys: Vec<(KeyId, SyncKey)> = self
            .keyring
            .keys()
            .iter()
            .filter(|(id, _)| *id != key_id)
            .cloned()
            .collect();
        keys.push((key_id, key.key));
        self.keyring = SyncKeyring::new(keys)?;
        self.local
            .sync_keys
            .retain(|stored| stored.key_id != key_id);
        self.local.sync_keys.push(WrappedSyncKey {
            key_id,
            wrapped: key.wrapped,
        });
        self.local.key_id = key_id;
        self.mark_changed();
        self.header_changed = true;
        self.force_publish = true;
        Ok(())
    }

    /// Revoke the pins of `replicas`.
    fn revoke(&mut self, replicas: &[ReplicaId]) {
        for replica in replicas {
            if let Some(pin) = self.local.pinned_keys.get_mut(replica) {
                pin.revoked = true;
            }
        }
    }

    /// Record a `Removal` under `key_id` for each of `replicas` whose
    /// `removed` register lacks one, and remove the `removed` entry of each
    /// of `dropped` whose values are all under `key_id`, under one write id
    /// of `session` minted at `now`. The pin of a dropped replica is no
    /// longer revoked.
    fn record_removals(
        &mut self,
        replicas: &[ReplicaId],
        dropped: &[ReplicaId],
        key_id: KeyId,
        session: &mut Session,
        now: i64,
    ) -> Result<(), Error> {
        let mut edits = LocalEdits::default();
        for replica in dropped {
            let only_this_key = self
                .state
                .store
                .removed
                .get(replica)
                .is_some_and(|register| register.values().all(|(_, v)| v.value.key_id == key_id));
            if only_this_key {
                edits.add_drop_removal(*replica);
                if let Some(pin) = self.local.pinned_keys.get_mut(replica) {
                    pin.revoked = false;
                }
            }
        }
        for replica in replicas {
            let present = self
                .state
                .store
                .removed
                .get(replica)
                .is_some_and(|register| register.values().any(|(_, v)| v.value.key_id == key_id));
            if !present {
                edits.add_removal(*replica, Removal { key_id });
            }
        }
        if !edits.is_empty() {
            self.record_own_edits(edits, session, now)?;
        }
        Ok(())
    }

    /// Rotate the sync key to `key` under the next key id, removing the
    /// replicas of `plan`, after the joins (`sync/rotation.rs`). Records a
    /// `Removal` for each removed replica under one write id of `session`
    /// minted at `now`, revokes their pins, and makes the key the key of the
    /// body. The wrappings are written with the `key.json`, and the
    /// transaction publishes. Refused if sync does not run, if a rotation is
    /// pending, or if a replica of `plan` is this replica, is not in
    /// `replica_keys`, or is already removed.
    pub(crate) fn rotate(
        &mut self,
        plan: &RotationPlan,
        key: NewKey,
        session: &mut Session,
        now: i64,
    ) -> Result<Rotated, Error> {
        self.check_rotation_step()?;
        let refused = |reason: String| Err(Error::RotationRefused(reason));
        if !self.local.pending_rotations.is_empty() {
            return refused("a rotation from another Mac waits for an answer".to_string());
        }
        let own = self.replica();
        let store = &self.state.store;
        for replica in plan.removals.keys() {
            if *replica == own {
                return refused("this Mac cannot remove itself".to_string());
            }
            if store.replica_keys.get(replica).is_none() {
                return refused(format!("replica {} is not a known Mac", replica.0));
            }
            if store.removed.get(replica).is_some() {
                return refused(format!("replica {} is already removed", replica.0));
            }
        }
        let removed: Vec<ReplicaId> = plan.removals.keys().copied().collect();
        let mut remaining = Vec::new();
        let mut unpinned = Vec::new();
        let candidates: Vec<ReplicaId> = store.replica_keys.iter().map(|(r, _)| *r).collect();
        for replica in candidates {
            if replica == own
                || plan.removals.contains_key(&replica)
                || self.state.store.removed.get(&replica).is_some()
                || self.has_left(replica)
            {
                continue;
            }
            match self.local.pinned_keys.get(&replica) {
                Some(pin) if !pin.revoked => remaining.push(replica),
                Some(_) => {},
                None => unpinned.push(replica),
            }
        }
        let key_id = KeyId(self.local.key_id.0 + 1);
        let key_fingerprint = key.key.fingerprint();
        self.record_removals(&removed, &[], key_id, session, now)?;
        self.revoke(&removed);
        self.install_key(key_id, key)?;
        let record = RotationRecord {
            signer: own,
            key_id,
            key_fingerprint,
            removed: removed.clone(),
            remaining: remaining.clone(),
        };
        self.local.rotation = Some(record);
        self.events.rotation("created", own, key_id.0, &removed);
        let vault_id = self.vault_id();
        log::info!(
            "Vault {vault_id} rotates to key {} and removes {} replicas",
            key_id.0,
            removed.len()
        );
        self.settle_rotations();
        Ok(Rotated {
            key_id,
            removed,
            remaining,
            unpinned,
            ..Rotated::default()
        })
    }

    /// Accept the pending rotation `record` with its key `key`, unwrapped
    /// and verified before the locks. Adds the key, replacing a key under
    /// the same key id, revokes the pins of the replicas it removes, records
    /// their `Removal` entries if the state lacks them, under one write id
    /// of `session` minted at `now`, and publishes under the new key. The
    /// other pending rotations under its key id, and a replaced rotation,
    /// are declined. Refused if sync does not run, if `record` is not
    /// pending, or if `key` is not the key of `record`.
    pub(crate) fn accept_rotation(
        &mut self,
        record: &RotationRecord,
        key: NewKey,
        session: &mut Session,
        now: i64,
    ) -> Result<Accepted, Error> {
        self.check_rotation_step()?;
        if !self.local.pending_rotations.contains(record) {
            return Err(Error::RotationRefused(
                "rotation is not pending".to_string(),
            ));
        }
        if key.key.fingerprint() != record.key_fingerprint {
            return Err(Error::SyncKeyFingerprintMismatch(record.key_id.0));
        }
        let own = self.replica();
        let mut repeat = Vec::new();
        // Replicas that only the replaced rotation removed. Their `removed`
        // entries came from it, so they are dropped.
        let mut dropped = Vec::new();
        if let Some(current) = self.local.rotation.take()
            && current.key_id == record.key_id
        {
            dropped = current
                .removed
                .iter()
                .filter(|r| !record.removes(**r))
                .copied()
                .collect();
            if current.signer == own {
                repeat = dropped.clone();
            }
            self.local.declined_rotations.push(current);
        }
        let pending = std::mem::take(&mut self.local.pending_rotations);
        for other in pending {
            if other.key_id.0 > record.key_id.0 {
                self.local.pending_rotations.push(other);
            } else if other.key_id == record.key_id && other != *record {
                self.local.declined_rotations.push(other);
            }
        }
        self.record_removals(&record.removed, &dropped, record.key_id, session, now)?;
        self.revoke(&record.removed);
        self.install_key(record.key_id, key)?;
        self.local.rotation = Some(record.clone());
        self.sidecar.ignored.clear();
        self.sidecar_changed = true;
        self.events
            .rotation("accepted", record.signer, record.key_id.0, &record.removed);
        let vault_id = self.vault_id();
        log::info!(
            "Vault {vault_id} accepts the rotation to key {} signed by replica {}",
            record.key_id.0,
            record.signer.0
        );
        self.settle_rotations();
        Ok(Accepted {
            key_id: record.key_id,
            repeat,
        })
    }

    /// Decline the pending rotations `records`, before the joins, so the
    /// joins they paused resume in this transaction. Refused if one is not
    /// pending.
    pub(crate) fn decline_rotations(&mut self, records: &[RotationRecord]) -> Result<(), Error> {
        self.check_rotation_step()?;
        if records
            .iter()
            .any(|record| !self.local.pending_rotations.contains(record))
        {
            return Err(Error::RotationRefused(
                "rotation is not pending".to_string(),
            ));
        }
        self.local
            .pending_rotations
            .retain(|pending| !records.contains(pending));
        for record in records {
            self.events
                .rotation("declined", record.signer, record.key_id.0, &record.removed);
            self.local.declined_rotations.push(record.clone());
        }
        let before = self.paused.clone();
        self.settle_rotations();
        for replica in before.difference(&self.paused) {
            self.sidecar.ignored.remove(replica);
        }
        self.header_changed = true;
        self.sidecar_changed = true;
        Ok(())
    }

    /// Check that every listed state file of each of `replicas` is joined,
    /// after the joins. Fails with `RotationWaiting` if a file is still
    /// remote, and with `RotationRefused` if a file was neither joined,
    /// ignored, nor quarantined.
    pub(crate) fn check_joined(
        &self,
        transport: &dyn SyncTransport,
        replicas: &[ReplicaId],
    ) -> Result<(), Error> {
        let vault_id = self.vault_id();
        let mut waiting = Vec::new();
        for replica in replicas {
            for hash in transport.list_states(vault_id, *replica)? {
                if self.sidecar.is_joined(*replica, hash) || self.sidecar.is_ignored(*replica, hash)
                {
                    continue;
                }
                let name = FileName::State(hash);
                match transport.read(vault_id, *replica, name)? {
                    ReadResult::Remote => {
                        waiting.push(replica.0);
                        break;
                    },
                    ReadResult::Missing => {},
                    ReadResult::Local(bytes) => {
                        let file_name = name.file_name();
                        let hash = StateHash::of(&bytes);
                        if !self.sidecar.is_quarantined(*replica, &file_name, hash) {
                            return Err(Error::RotationRefused(format!(
                                "state file {file_name} of replica {} was not joined",
                                replica.0
                            )));
                        }
                    },
                }
            }
        }
        if waiting.is_empty() {
            Ok(())
        } else {
            Err(Error::RotationWaiting(waiting))
        }
    }

    /// Whether every listed state file of `replica` is joined, so a publish
    /// of the joined state covers it.
    pub(crate) fn covers(&self, transport: &dyn SyncTransport, replica: ReplicaId) -> bool {
        transport
            .list_states(self.vault_id(), replica)
            .is_ok_and(|listed| {
                listed
                    .iter()
                    .all(|hash| self.sidecar.is_joined(replica, *hash))
            })
    }

    /// Whether `replica` can be cleaned up: it is not this replica, and it
    /// has left, is removed, has a revoked pin, or has the keys of another
    /// replica id, as after a re-link.
    fn is_retired(&self, replica: ReplicaId, signer: &dyn VaultSigner) -> Result<bool, Error> {
        if replica == self.replica() {
            return Ok(false);
        }
        let store = &self.state.store;
        if self.has_left(replica)
            || store.removed.get(&replica).is_some()
            || self
                .local
                .pinned_keys
                .get(&replica)
                .is_some_and(|pin| pin.revoked)
        {
            return Ok(true);
        }
        let keys_of = |r: &ReplicaId| -> Option<ReplicaKeys> {
            match self.local.pinned_keys.get(r) {
                Some(pin) => Some(ReplicaKeys {
                    encryption: pin.encryption.clone(),
                    signing: pin.signing.clone(),
                }),
                None => store
                    .replica_keys
                    .get(r)
                    .and_then(|register| register.shown())
                    .cloned(),
            }
        };
        let Some(keys) = keys_of(&replica) else {
            return Ok(false);
        };
        if self
            .own_keys(signer)?
            .is_some_and(|own| own.signing == keys.signing)
        {
            return Ok(true);
        }
        Ok(store.replica_keys.iter().any(|(other, _)| {
            *other != replica
                && *other != self.replica()
                && keys_of(other).is_some_and(|k| k.signing == keys.signing)
        }))
    }

    /// Clean up the retired or departed replica `replica`, after the joins
    /// (`sync/cleanup.rs`). If its `last_used_day_at` registers hold a later
    /// time than the own register, that time is written into the own
    /// register first. Its `replica_names`, `replica_keys`, and `left`
    /// entries and its `last_used_day_at` registers are then removed, all
    /// under one write id of `session` minted at `now`. Refused if sync does
    /// not run or `replica` cannot be cleaned up. Fails with
    /// `RotationWaiting` if one of its files is still remote.
    pub(crate) fn clean_replica(
        &mut self,
        transport: &dyn SyncTransport,
        replica: ReplicaId,
        session: &mut Session,
        now: i64,
        signer: &dyn VaultSigner,
    ) -> Result<(), Error> {
        self.check_rotation_step()?;
        if !self.is_retired(replica, signer)? {
            return Err(Error::CleanupRefused(format!(
                "replica {} is not retired, departed, or removed",
                replica.0
            )));
        }
        self.check_joined(transport, &[replica])?;
        let own = self.replica();
        let mut edits = LocalEdits::default();
        for (id, credential) in self.state.store.credentials.iter() {
            let shown = |r: &ReplicaId| {
                credential
                    .last_used_day_at
                    .get(r)
                    .and_then(|register| register.shown())
                    .copied()
            };
            if let Some(cleaned) = shown(&replica)
                && shown(&own).is_none_or(|kept| kept < cleaned)
            {
                edits.add_last_used(*id, own, cleaned);
            }
        }
        edits.add_clean_replica(replica);
        self.record_own_edits(edits, session, now)?;
        self.events.replica_cleaned(replica);
        let vault_id = self.vault_id();
        log::info!("Vault {vault_id} cleans up replica {}", replica.0);
        Ok(())
    }

    /// Key id of the body and its key in the keyring. `None` if the keyring
    /// lacks it, which a trusted state never does.
    pub(crate) fn current_key(&self) -> Option<(KeyId, &SyncKey)> {
        let key_id = self.local.key_id;
        self.keyring.get(key_id).map(|key| (key_id, key))
    }

    /// Refuse the recipient `add` of a saved kit, before it is recorded, if
    /// sync does not run, if the sync state is `leaving`, if the kit is for
    /// another vault, or if the kit is not for the current key.
    pub(crate) fn check_recovery(&self, add: &RecoveryAdd) -> Result<(), Error> {
        let refused = |reason: &str| Err(Error::RecoveryKitNotAdded(reason.to_string()));
        if add.vault_id != self.vault_id() {
            return refused("kit is for another vault");
        }
        if !self.syncs() {
            return refused("sync is stopped or paused");
        }
        if self.is_leaving() {
            return refused("sync is being disabled");
        }
        let current = self
            .current_key()
            .map(|(key_id, key)| (key_id, key.fingerprint().0));
        if current != Some((add.value.key_id, add.value.key_fingerprint)) {
            return refused("kit is not for the current key");
        }
        Ok(())
    }

    /// Recipients of the `recovery` map that receive an `Age` wrapping of the
    /// current key (`sync/recovery.rs`).
    pub(crate) fn recovery_recipients(&self) -> Vec<String> {
        RecoveryRecipients::of_key(&self.state.store, self.local.key_id, &self.keyring)
    }

    /// Whether the `recovery` map holds no recipient of the current key, the
    /// degraded state (D18).
    pub(crate) fn recovery_kit_missing(&self) -> bool {
        self.recovery_recipients().is_empty()
    }

    /// Write the own `key.json` through `transport`, after the saves, with
    /// one read and one write. `device` is the `Device` wrapping of a pairing
    /// grant, which replaces any `Device` wrapping to the same replica id and
    /// key id. If the transaction syncs, the `Age` wrapping of each recipient
    /// of [`Self::recovery_recipients`] that the file lacks is then added. The
    /// other wrappings are written back unchanged. Nothing is read with no
    /// `device` and no recipient, and nothing is written if nothing was
    /// added. A missing or malformed file is read as empty, so its `Device`
    /// wrappings are lost. A failed read or write fails with its error, and
    /// pauses sync with `PublishFailed` if a recipient was wanted.
    ///
    /// If this replica signed the rotation of the current key, a signed
    /// `Device` wrapping of the key is added for each of its remaining
    /// replicas that the file lacks, signed by `signer`. The file is read
    /// for them until every one of those replicas has published under the
    /// key. Once every remaining replica has published under the current
    /// key, the wrappings of earlier key ids are dropped, once per key id.
    pub(crate) fn write_key_file(
        &mut self,
        transport: &dyn SyncTransport,
        device: Option<DeviceWrapping>,
        signer: &dyn VaultSigner,
    ) -> Result<(), Error> {
        let recipients = if self.syncs() {
            self.recovery_recipients()
        } else {
            Vec::new()
        };
        let syncs = self.syncs() && !self.is_leaving();
        let rotation = if syncs { self.own_rotation() } else { None };
        let prune = syncs && self.prunes_retired_keys();
        if device.is_none() && recipients.is_empty() && rotation.is_none() && !prune {
            return Ok(());
        }
        let wants_rotation = rotation.is_some();
        let result = self.rewrite_key_file(transport, device, &recipients, rotation, prune, signer);
        match &result {
            Ok(()) if prune => {
                self.sidecar.pruned_key = Some(self.local.key_id);
                self.sidecar_changed = true;
            },
            Err(e) if !recipients.is_empty() || wants_rotation => {
                let vault_id = self.vault_id();
                log::warn!("Failed to write the wrappings of vault {vault_id}: {e}");
                self.found
                    .publish_failed
                    .get_or_insert_with(|| e.to_string());
            },
            _ => {},
        }
        result
    }

    /// Rotation of the current key if this replica signed it and one of its
    /// remaining replicas has not published under the key.
    fn own_rotation(&self) -> Option<RotationRecord> {
        let rotation = self.local.rotation.as_ref()?;
        let waiting = rotation.remaining.iter().any(|replica| {
            self.sidecar
                .key_ids
                .get(replica)
                .is_none_or(|key_id| key_id.0 < rotation.key_id.0)
        });
        (rotation.signer == self.replica() && rotation.key_id == self.local.key_id && waiting)
            .then(|| rotation.clone())
    }

    /// Whether the wrappings of key ids below the current key are dropped:
    /// the current key came from a rotation, the drop did not run for it,
    /// and every peer of `replica_keys` that is not removed and has not left
    /// has a joined state file under the current key.
    fn prunes_retired_keys(&self) -> bool {
        let key_id = self.local.key_id;
        let rotated = self
            .local
            .rotation
            .as_ref()
            .is_some_and(|rotation| rotation.key_id == key_id);
        if !rotated || self.sidecar.pruned_key == Some(key_id) {
            return false;
        }
        let store = &self.state.store;
        store.replica_keys.iter().all(|(replica, _)| {
            *replica == self.replica()
                || store.removed.get(replica).is_some()
                || store
                    .left
                    .get(replica)
                    .and_then(|left| left.shown())
                    .copied()
                    .unwrap_or(false)
                || self
                    .sidecar
                    .key_ids
                    .get(replica)
                    .is_some_and(|k| k.0 >= key_id.0)
        })
    }

    /// Read, change, and write the own `key.json` for
    /// [`Self::write_key_file`].
    fn rewrite_key_file(
        &self,
        transport: &dyn SyncTransport,
        device: Option<DeviceWrapping>,
        recipients: &[String],
        rotation: Option<RotationRecord>,
        prune: bool,
        signer: &dyn VaultSigner,
    ) -> Result<(), Error> {
        let vault_id = self.vault_id();
        let own = self.replica();
        let mut file = KeyFile::read_own(transport, vault_id, own)?;
        let mut changed = false;
        if let Some(device) = device {
            file.put_device(device);
            changed = true;
        }
        if let Some((key_id, key)) = self.current_key() {
            let added = RecoveryRecipients::add_missing(&mut file, key_id, key, recipients);
            if added > 0 {
                log::info!("Vault {vault_id} adds {added} age wrappings to its key.json");
                changed = true;
            }
            if let Some(rotation) = rotation {
                changed |= self.add_rotation_wrappings(&mut file, &rotation, key, signer)?;
            }
        }
        if prune {
            let key_id = self.local.key_id.0;
            let before = file.wrappings.len();
            file.wrappings.retain(|wrapping| match wrapping {
                Wrapping::Device(device) => device.key_id.0 >= key_id,
                Wrapping::Age(age) => age.key_id.0 >= key_id,
                Wrapping::Unknown(_) => true,
            });
            let dropped = before - file.wrappings.len();
            if dropped > 0 {
                log::info!("Vault {vault_id} drops {dropped} wrappings of retired keys");
                changed = true;
            }
        }
        if !changed {
            return Ok(());
        }
        transport.write_own(vault_id, own, FileName::Key, &file.to_bytes())
    }

    /// Add to `file` a `Device` wrapping of `key`, signed by `signer`, for
    /// each remaining replica of `rotation` that it lacks. A replica with no
    /// pin is skipped. Returns whether a wrapping was added.
    fn add_rotation_wrappings(
        &self,
        file: &mut KeyFile,
        rotation: &RotationRecord,
        key: &SyncKey,
        signer: &dyn VaultSigner,
    ) -> Result<bool, Error> {
        let vault_id = self.vault_id();
        let own = self.replica();
        let from = self.own_keys(signer)?.ok_or_else(|| {
            Error::RotationRefused("own keys are not in the sync state".to_string())
        })?;
        let mut added = false;
        for replica in &rotation.remaining {
            let present = file.devices().any(|device| {
                device.to_replica == *replica
                    && device.key_id == rotation.key_id
                    && device.key_fingerprint == rotation.key_fingerprint
                    && device.signature.is_some()
            });
            let Some(pin) = self.local.pinned_keys.get(replica).filter(|_| !present) else {
                continue;
            };
            let mut wrapping =
                DeviceWrapping::wrap(rotation.key_id, key, *replica, &pin.encryption, &from)?;
            wrapping.sign_rotation(
                vault_id,
                own,
                rotation.removed.clone(),
                rotation.remaining.clone(),
                signer,
            )?;
            file.put_device(wrapping);
            added = true;
        }
        Ok(added)
    }

    /// Value of the own `replica_keys` register of the state that holds the
    /// current key of `signer`, as the own key check of the load reads it.
    /// `None` if no value holds it.
    pub(crate) fn own_keys(&self, signer: &dyn VaultSigner) -> Result<Option<ReplicaKeys>, Error> {
        let current = signer.verifying_key()?;
        let Some(register) = self.state.store.replica_keys.get(&self.local.replica_id) else {
            return Ok(None);
        };
        Ok(register
            .values()
            .map(|(_, keys)| &keys.value)
            .find(|keys| {
                VerifyingKey::from_sec1_bytes(&keys.signing.0).is_ok_and(|key| key == current)
            })
            .cloned())
    }

    /// Join of state files into the state, as received by `session`.
    fn join<'a>(&'a mut self, session: &'a mut Session) -> StateJoin<'a> {
        StateJoin {
            vault_id: self.local.vault_id,
            local: &self.local,
            state: &mut self.state,
            keyring: &self.keyring,
            sidecar: &mut self.sidecar,
            sidecar_changed: &mut self.sidecar_changed,
            session,
            found: &mut self.found,
            paused: &self.paused,
            events: &mut self.events,
        }
    }

    /// Vault with key `key` and file key `file_key`, holding the view of the
    /// state, at the generation and the replica id of the sync state.
    ///
    /// If the view of the joined state fails to apply, the join is discarded
    /// and the vault holds the view of the state as loaded. Fails if that
    /// view fails to apply too, since no vault older than the sync state is
    /// saved over it.
    pub(crate) fn rebuilt_vault(
        &mut self,
        key: String,
        file_key: &UnlockedKey,
    ) -> Result<Vault, Error> {
        let mut vault = Rebuild::empty(&self.local, key.clone(), file_key)?;
        match self.apply_view(&mut vault) {
            Ok(_) => {},
            Err(e) if self.changed => {
                self.apply_failed(e);
                self.discard_join()?;
                vault = Rebuild::empty(&self.local, key, file_key)?;
                self.apply_view(&mut vault)?;
            },
            Err(e) => return Err(e),
        }
        self.events.rebuilt();
        Ok(vault)
    }

    /// New vault with file key `file_key`, holding the view of the joined
    /// state, at the generation and the replica id of the sync state, for a
    /// join of a new vault. Its key is the key that `choose_key` returns for
    /// the vault name of the view. Fails if the view fails to apply.
    pub(crate) fn joined_vault(
        &self,
        choose_key: impl FnOnce(Option<&str>) -> Result<String, Error>,
        file_key: &UnlockedKey,
    ) -> Result<Vault, Error> {
        let view = VaultView::of(&self.state);
        let key = choose_key(view.name.as_deref())?;
        let mut vault = Rebuild::empty(&self.local, key, file_key)?;
        self.apply(&view, &mut vault)?;
        Ok(vault)
    }

    /// Apply the view of the joined state to `vault`, an existing vault
    /// after the recovery merge of a join. Fails if the view fails to apply.
    pub(crate) fn apply_merged(&self, vault: &mut Vault) -> Result<(), Error> {
        self.apply_view(vault).map(|_| ())
    }

    /// Apply the view of the state to `vault`, without a diff.
    fn apply_view(&self, vault: &mut Vault) -> Result<ApplyReport, Error> {
        self.apply(&VaultView::of(&self.state), vault)
    }

    /// Apply `view` to `vault`, without a diff.
    fn apply(&self, view: &VaultView, vault: &mut Vault) -> Result<ApplyReport, Error> {
        #[cfg(test)]
        if let Some(fault) = self.apply_fault {
            return view.apply_with_fault(vault, fault);
        }
        view.apply(vault)
    }

    /// Apply the view of the state to `vault`. If the apply fails, `vault`
    /// is put back as it was before the apply, the failure is recorded as a
    /// paused cause, and `None` is returned.
    fn try_apply(&mut self, vault: &mut Vault) -> Result<Option<ApplyReport>, Error> {
        let before = vault.duplicate()?;
        match self.apply_view(vault) {
            Ok(report) => Ok(Some(report)),
            Err(e) => {
                *vault = before;
                self.apply_failed(e);
                Ok(None)
            },
        }
    }

    /// Apply the view of the joined state to `vault`, before the requested
    /// change. If the apply fails, the join is discarded, and `vault` is as
    /// it was before the join. In a repair, the repair is discarded too, and
    /// the transaction saves the vault only.
    ///
    /// A successful apply queues the audit events of the changes that came
    /// from other Macs.
    pub(crate) fn apply_joined(&mut self, vault: &mut Vault) -> Result<(), Error> {
        if let Some(report) = self.try_apply(vault)? {
            self.events.applied(&self.sources, &report);
            return Ok(());
        }
        if self.repairing {
            self.fall_back()
        } else {
            self.discard_join()
        }
    }

    /// Apply the view of the state to `vault` after a recorded edit. If the
    /// apply fails, the edit is kept, and `vault` is saved as the requested
    /// change left it.
    pub(crate) fn apply_recorded(&mut self, vault: &mut Vault) -> Result<(), Error> {
        self.try_apply(vault).map(|_| ())
    }

    /// Apply the view of the state to `vault`, a restored version. If the
    /// apply fails, the join and the recorded differences are discarded, and
    /// the transaction saves the vault only.
    pub(crate) fn apply_restored(&mut self, vault: &mut Vault) -> Result<(), Error> {
        if self.try_apply(vault)?.is_some() {
            return Ok(());
        }
        self.fall_back()
    }

    fn apply_failed(&mut self, e: Error) {
        let vault_id = self.vault_id();
        log::error!("Failed to apply the sync state of vault {vault_id}, sync paused: {e}");
        self.found.apply_failed(e);
    }

    /// Discard the joins of this transaction. The state is the state as
    /// loaded, and the files joined are not recorded as joined, so the next
    /// transaction reads them again. An own file joined by this transaction
    /// is not joined for the delete rule. Quarantined files stay
    /// quarantined.
    fn discard_join(&mut self) -> Result<(), Error> {
        self.sources.clear();
        if self.changed {
            self.state = self
                .local
                .open(&self.keyring)
                .map_err(|e| Error::SyncStateEncodeError(e.to_string()))?;
            self.changed = false;
            self.padded = None;
        }
        if self.sidecar.joined != self.loaded_joined {
            self.sidecar.joined = self.loaded_joined.clone();
            self.sidecar_changed = true;
        }
        let replica = self.replica();
        for file in self.own_files.iter_mut().flatten() {
            if file.state == OwnFileState::Joined && !self.sidecar.is_joined(replica, file.hash) {
                file.state = OwnFileState::NotJoined;
            }
        }
        Ok(())
    }

    /// Discard the joins, the repair, and the edits of this transaction, and
    /// save the vault only. The header is as loaded, so a sync stopped by
    /// drift stays stopped. The vault is saved at the next generation if it
    /// changed, so the next transaction runs the `v > s` repair.
    fn fall_back(&mut self) -> Result<(), Error> {
        self.discard_join()?;
        self.events.discard_writes();
        let (stopped_build, override_build) = self.loaded_stop.clone();
        self.local.stopped_build = stopped_build;
        self.local.override_build = override_build;
        self.header_changed = false;
        self.vault_only = true;
        Ok(())
    }

    /// Record that a diff failed with `e`, and save the vault only.
    fn diff_failed(&mut self, e: Error) -> Result<(), Error> {
        let vault_id = self.vault_id();
        log::error!("Failed to diff vault {vault_id} against its sync state, sync paused: {e}");
        self.found.diff_failed(e);
        self.fall_back()
    }

    /// Whether the user disabled sync and the final state file is not yet
    /// copied. A transaction is never built on a `leaving` state, except by
    /// a disable.
    pub(crate) fn is_leaving(&self) -> bool {
        self.local.leaving
    }

    /// Whether sync is stopped by drift.
    pub(crate) fn is_stopped(&self) -> bool {
        self.local.stopped_build.is_some()
    }

    /// No-edit guard: diff the vault as loaded, `vault`, against the view of
    /// the state as loaded, before any join and before the requested change.
    /// If the diff finds edits, sync stops with `stopped_build` set to this
    /// build, and no edit is recorded. A sync that is already stopped stays
    /// stopped. If the diff fails, the transaction saves the vault only.
    pub(crate) fn guard(&mut self, vault: &Vault) -> Result<(), Error> {
        if self.is_stopped() {
            return Ok(());
        }
        let edits = match self.find(vault) {
            Ok(edits) => edits,
            Err(e) => return self.diff_failed(e),
        };
        if edits.is_empty() {
            return Ok(());
        }
        let vault_id = self.vault_id();
        let count = edits.len();
        log::error!("Vault {vault_id} differs from its sync state in {count} edits, sync stopped");
        self.local.stopped_build = Some(BUILD_ID.to_string());
        self.header_changed = true;
        self.events.stopped("drift", Some(count));
        Ok(())
    }

    /// Local edits of `vault` against the view of the state.
    fn find(&self, vault: &Vault) -> Result<LocalEdits, Error> {
        Ok(LocalEdits::find(&self.state, vault, self.replica())?)
    }

    /// Repair of this transaction, with the user override if `confirmed`.
    /// `None` if the transaction runs the guard.
    pub(crate) fn repair(&self, confirmed: bool) -> Option<Repair> {
        Repair::of(&self.local, self.newer_vault.is_some(), confirmed)
    }

    /// Whether the user override is offered.
    pub(crate) fn override_offered(&self) -> bool {
        Repair::override_offered(&self.local)
    }

    /// Start `repair`, in place of the guard. A recovery merge resumes sync
    /// and is saved in the header.
    ///
    /// A sync state restored from a backup can be older than the sidecar,
    /// which then records files as joined that the state lacks. A repair of a
    /// vault at `v > s` drops the joined hashes, so every listed file is read
    /// again.
    pub(crate) fn start_repair(&mut self, repair: Repair) {
        let vault_id = self.vault_id();
        log::warn!("Vault {vault_id} runs the sync repair {repair:?}");
        self.repairing = true;
        repair.start(&mut self.local);
        self.events.repair(repair.cause());
        if repair != Repair::NewerVault {
            self.events.resumed();
            self.header_changed = true;
        }
        if self.newer_vault.is_some() && !self.sidecar.joined.is_empty() {
            self.sidecar.joined.clear();
            self.sidecar_changed = true;
        }
    }

    /// Add each difference of `vault` against the view of the state as a
    /// repair value, under one write id of `session` minted at `now`, in Unix
    /// seconds. Returns the write id, or `None` if the repair adds nothing.
    /// If the diff fails, the transaction saves the vault only.
    pub(crate) fn record_repair(
        &mut self,
        vault: &Vault,
        session: &mut Session,
        now: i64,
    ) -> Result<Option<WriteId>, Error> {
        let edits = match LocalEdits::find_repair(&self.state, vault, self.replica()) {
            Ok(edits) => edits,
            Err(e) => {
                self.diff_failed(e.into())?;
                return Ok(None);
            },
        };
        Ok(self.record_repair_edits(edits, session, now))
    }

    /// Recovery merge of a join: [`Self::record_repair`] of the existing
    /// vault `vault` against the view of the joined state. Fails with the
    /// diff error and records nothing if the diff fails, since a join saves
    /// no vault alone.
    pub(crate) fn record_merge(
        &mut self,
        vault: &Vault,
        session: &mut Session,
        now: i64,
    ) -> Result<Option<WriteId>, Error> {
        let edits = LocalEdits::find_repair(&self.state, vault, self.replica())?;
        if !edits.is_empty() {
            self.events.repair("recovery merge");
        }
        Ok(self.record_repair_edits(edits, session, now))
    }

    /// Record the repair writes `edits` under one write id of `session`
    /// minted at `now`, in Unix seconds. Returns the write id, or `None` if
    /// `edits` is empty.
    fn record_repair_edits(
        &mut self,
        edits: LocalEdits,
        session: &mut Session,
        now: i64,
    ) -> Option<WriteId> {
        let count = edits.len();
        let write_id = edits.record_repair(&mut self.state, session, now);
        if write_id.is_some() {
            let vault_id = self.vault_id();
            log::warn!("Vault {vault_id} sync repair added {count} differences as conflicts");
            self.events.repair_differences(count);
            self.mark_changed();
        }
        write_id
    }

    /// Record the local edits of `vault` against the view of the state, under
    /// one write id of `session` minted at `now`, in Unix seconds. Returns
    /// the write id, or `None` if the vault has no edits. For
    /// `SyncRequest::Restore`, an item or credential the vault lacks is moved
    /// to the trash, not removed. `SyncRequest::AddRecovery` adds the write
    /// of its recipient under the same write id. If the diff fails, nothing
    /// is recorded, and the transaction saves the vault only.
    ///
    /// Before the diff, the history entry that the requested change added for
    /// a replaced shown value takes the id derived from the write id of that
    /// value ([`HistoryIds::rewrite`]), for every request. Macs that replace
    /// one value therefore write one entry. A rewrite that fails is handled
    /// as a diff that fails.
    ///
    /// Before the mint, the Ask registers that the change writes are checked
    /// by `edit`, the edit check the change declared
    /// ([`EditRequest::check`]). A refused edit records nothing, and is
    /// returned as `Refused`. A restore is not checked, since it changes no
    /// value that a request read. `SyncRequest::Resolve` writes the value it
    /// picks and is refused if the register holds other write ids than it
    /// read.
    ///
    /// A write to an Ask register supersedes every value of the register.
    /// Each credential value not chosen is written to `history` under the
    /// same write id ([`LocalEdits::keep_not_chosen`]).
    pub(crate) fn record(
        &mut self,
        vault: &mut Vault,
        session: &mut Session,
        now: i64,
        request: &SyncRequest,
        edit: &EditRequest,
    ) -> Result<Recorded, Error> {
        if let Err(e) = HistoryIds::rewrite(&self.state, vault) {
            self.diff_failed(e)?;
            return Ok(Recorded::Minted(None));
        }
        let edits = if *request == SyncRequest::Restore {
            let trashed_at = Timestamp::now().as_second();
            LocalEdits::find_restore(&self.state, vault, self.replica(), trashed_at)
                .map_err(Error::from)
        } else {
            self.find(vault)
        };
        let mut edits = match edits {
            Ok(edits) => edits,
            Err(e) => {
                self.diff_failed(e)?;
                return Ok(Recorded::Minted(None));
            },
        };
        let checked = match request {
            SyncRequest::Restore => Ok(()),
            SyncRequest::Resolve(pick) => self.resolve(&mut edits, pick, now),
            _ => edit.check(&self.state, &mut edits),
        };
        if let Err(refusal) = checked {
            let vault_id = self.vault_id();
            log::info!("Vault {vault_id} refused an edit: {refusal}");
            return Ok(Recorded::Refused(refusal));
        }
        edits.keep_not_chosen(&self.state, now);
        if let SyncRequest::AddRecovery(add) = request {
            edits.add_recovery(add.recipient.clone(), add.value.clone());
        }
        let resolved = edits.superseded(&self.state);
        let differences = edits.len();
        let write_id = edits.record(&mut self.state, session, now);
        if write_id.is_some() {
            self.events.conflicts_resolved(&resolved);
            if *request == SyncRequest::Restore {
                self.events.repair("restored version");
                self.events.repair_differences(differences);
            }
            self.mark_changed();
        }
        Ok(Recorded::Minted(write_id))
    }

    /// Add the write of the value that `pick` chooses to `edits`, with `now`
    /// in Unix seconds as the time of each history entry it writes. Refused
    /// as `Changed` if the register holds other write ids than `pick` read,
    /// or no longer holds the chosen value.
    fn resolve(
        &self,
        edits: &mut LocalEdits,
        pick: &ResolvePick,
        now: i64,
    ) -> Result<(), EditRefusal> {
        let changed = EditRefusal {
            register: pick.register,
            reason: RefusalReason::Changed,
        };
        let request = pick.resolve(&self.state).ok_or(changed)?;
        edits
            .resolve(&self.state, request, now)
            .map(|_| ())
            .map_err(|_| changed)
    }

    /// Record the first state of a sync setup under one write id of `session`
    /// minted at `now`, in Unix seconds: every entry of `vault`, the display
    /// name `name` and the public keys `keys` of this replica, and the
    /// recipient `recovery` of the saved kit. Returns the write id. Fails and
    /// records nothing if the kit is not for the current key or the diff
    /// fails.
    pub(crate) fn record_first(
        &mut self,
        vault: &Vault,
        name: String,
        keys: ReplicaKeys,
        recovery: &RecoveryAdd,
        session: &mut Session,
        now: i64,
    ) -> Result<WriteId, Error> {
        self.check_recovery(recovery)?;
        let replica = self.replica();
        let mut edits = self.find(vault)?;
        edits.add_own(replica, name, keys);
        edits.add_recovery(recovery.recipient.clone(), recovery.value.clone());
        self.record_own_edits(edits, session, now)
    }

    /// Record the display name `name` and the public keys `keys` of this
    /// replica under one write id of `session` minted at `now`, in Unix
    /// seconds, for a join. Diffs nothing. Returns the write id.
    pub(crate) fn record_own(
        &mut self,
        name: String,
        keys: ReplicaKeys,
        session: &mut Session,
        now: i64,
    ) -> Result<WriteId, Error> {
        let mut edits = LocalEdits::default();
        edits.add_own(self.replica(), name, keys);
        self.record_own_edits(edits, session, now)
    }

    /// Record `true` in the `left` register of this replica under one write
    /// id of `session` minted at `now`, in Unix seconds, and mark the sync
    /// state `leaving`, for a disable of sync (D9 of doc 18). Diffs nothing,
    /// and records the edit even if sync is stopped by drift. Returns the
    /// write id.
    pub(crate) fn leave(&mut self, session: &mut Session, now: i64) -> Result<WriteId, Error> {
        let mut edits = LocalEdits::default();
        edits.add_left(self.replica());
        let write_id = self.record_own_edits(edits, session, now)?;
        self.local.leaving = true;
        self.header_changed = true;
        Ok(write_id)
    }

    /// Record `edits`, which hold the own registers of this replica, under
    /// one write id of `session` minted at `now`, in Unix seconds. Returns
    /// the write id.
    fn record_own_edits(
        &mut self,
        edits: LocalEdits,
        session: &mut Session,
        now: i64,
    ) -> Result<WriteId, Error> {
        let write_id = edits.record(&mut self.state, session, now).ok_or_else(|| {
            Error::SyncStateEncodeError("own registers record no edit".to_string())
        })?;
        self.mark_changed();
        Ok(write_id)
    }

    fn mark_changed(&mut self) {
        self.changed = true;
        self.padded = None;
    }

    /// Padded body of the state. A state that did not change keeps the
    /// padded body of the sync state as loaded.
    fn padded(&mut self) -> Result<Zeroizing<Vec<u8>>, Error> {
        if let Some(padded) = &self.padded {
            return Ok(padded.clone());
        }
        let padded = if self.changed {
            PaddedBody::of(&self.state)?
        } else {
            self.local
                .open_padded(&self.keyring)
                .map_err(|e| Error::SyncStateEncodeError(e.to_string()))?
        };
        self.padded = Some(padded.clone());
        Ok(padded)
    }

    /// Move `staged_context` to `published_context` if the sidecar records
    /// the staged file as published and the staged file under the app data
    /// directory `root` hashes to `staged_hash`. An older staged file put in
    /// place of the current one, or a sidecar hash of another file, moves
    /// nothing.
    fn settle_staged(&mut self, root: &Path) {
        let (Some(context), Some(hash)) = (&self.local.staged_context, self.local.staged_hash)
        else {
            return;
        };
        if self.sidecar.last_publish != Some(hash)
            || Staged::existing(root, self.vault_id(), hash).is_none()
        {
            return;
        }
        self.local.published_context = context.clone();
        self.local.staged_context = None;
        self.local.staged_hash = None;
        self.local.staged_blobs.clear();
        self.header_changed = true;
    }

    /// Set `staged_blobs` to the blobs that the state references and that
    /// the blob store holds. The folder is not listed. [`blobs::upload`]
    /// lists it when the blobs are uploaded and skips the blobs it has. With
    /// no blob store, none.
    fn set_staged_blobs(&mut self) {
        let pending = match &self.blob_store {
            Some(store) => blobs::pending(&blobs::referenced(&self.state.store), store),
            None => Vec::new(),
        };
        if self.local.staged_blobs != pending {
            self.local.staged_blobs = pending;
            self.header_changed = true;
        }
    }

    /// Settle the staged file of an earlier publish, then write the staged
    /// file under the app data directory `root` if the transaction publishes.
    ///
    /// The transaction publishes if the local context is ahead of
    /// `published_context`, or if the listed own files lack the file of the
    /// last publish. With no listing, only the context decides. A staged
    /// file that already holds the local context and hashes to `staged_hash`
    /// is copied again as it is. Otherwise a new staged file is written and
    /// named in `staged_context` and `staged_hash`. A failed write is logged,
    /// and the transaction saves without a publish.
    ///
    /// A staged file that is copied again, or written, sets `staged_blobs`
    /// to every blob that the state references and the local store holds
    /// ([`Self::set_staged_blobs`]). A copy uploads those that the folder
    /// lacks. A transaction that does not publish leaves `staged_blobs` as it
    /// was.
    pub(crate) fn stage(&mut self, root: &Path) -> Result<(), Error> {
        self.settle_staged(root);
        let (last_publish, own_files) = match &self.own_files {
            Some(own_files) => (self.sidecar.last_publish.as_ref(), &own_files[..]),
            None => (None, &[][..]),
        };
        if !self.force_publish
            && !self.state.context.should_publish(
                &self.local.published_context,
                last_publish,
                own_files,
            )
        {
            return Ok(());
        }
        let vault_id = self.vault_id();
        // A staged file of an earlier key is never copied again.
        if !self.force_publish
            && self.local.staged_context.as_ref() == Some(&self.state.context)
            && let Some(hash) = self.local.staged_hash
            && let Some(staged) = Staged::existing(root, vault_id, hash)
        {
            self.set_staged_blobs();
            self.staged = Some(staged);
            return Ok(());
        }
        let padded = self.padded()?;
        let bytes = self.local.staged_file(&padded, &self.keyring)?;
        match Staged::write(root, vault_id, bytes) {
            Ok(staged) => {
                self.local.staged_context = Some(self.state.context.clone());
                self.local.staged_hash = Some(staged.hash);
                self.header_changed = true;
                self.set_staged_blobs();
                self.staged = Some(staged);
            },
            Err(e) => log::error!("Failed to write the staged file of vault {vault_id}: {e}"),
        }
        Ok(())
    }

    /// Delete the staged file under the app data directory `root` if this
    /// transaction wrote it, after a failed sync state save. The saved sync
    /// state does not name it.
    pub(crate) fn discard_staged(&mut self, root: &Path) {
        if let Some(staged) = self.staged.take() {
            staged.discard(root, self.vault_id());
        }
    }

    /// Upload the blobs of `staged_blobs` that the folder lacks, then copy
    /// the staged file to the synced folder through `transport`, after the
    /// vault is saved. On success the sidecar records its hash as the last
    /// publish and as joined, and each older own file that was joined is
    /// deleted. A failed upload or copy is logged and leaves the staged file
    /// in place, named by `staged_hash`, for the next transaction to copy. A
    /// failed upload copies no state file. Returns whether a staged file was
    /// copied.
    pub(crate) fn publish(&mut self, transport: &dyn SyncTransport) -> bool {
        let Some(staged) = self.staged.take() else {
            return false;
        };
        let vault_id = self.vault_id();
        let replica = self.replica();
        if let Some(store) = &self.blob_store
            && let Err(e) = blobs::upload(transport, vault_id, store, &self.local.staged_blobs)
        {
            log::warn!("Failed to upload the file blobs of vault {vault_id}: {e}");
            self.found.publish_failed = Some(e.to_string());
            return false;
        }
        self.blobs_uploaded = self.blob_store.is_some();
        let own_files = self.own_files.take().unwrap_or_default();
        if let Err(e) = staged.copy(transport, vault_id, replica, &own_files) {
            log::warn!("Failed to publish the staged file of vault {vault_id}: {e}");
            self.found.publish_failed = Some(e.to_string());
            return false;
        }
        self.sidecar.last_publish = Some(staged.hash);
        self.sidecar.record_joined(replica, staged.hash);
        self.sidecar_changed = true;
        for file in own_files
            .iter()
            .filter(|file| file.should_delete(&staged.hash))
        {
            let name = FileName::State(file.hash);
            if let Err(e) = transport.delete_own(vault_id, replica, name) {
                let name = name.file_name();
                log::warn!("Failed to delete own state file {name} of vault {vault_id}: {e}");
            }
        }
        true
    }

    /// Upload each blob that the joined state references, that the local
    /// store holds, and that the folder of `transport` lacks, after the
    /// vault is saved. Runs in a transaction that did not publish. A publish
    /// that uploaded its blobs already did this, and a failed publish is
    /// retried by the next transaction, so neither runs it. The folder is not
    /// listed if the state references no blob that the store holds.
    ///
    /// A failure is logged. It does not pause sync, record a cause, or fail
    /// the save. The local sync state and the sidecar are not changed, since
    /// no signed save follows the vault save.
    pub(crate) fn heal_blobs(&self, transport: &dyn SyncTransport) {
        let Some(store) = &self.blob_store else {
            return;
        };
        if self.blobs_uploaded || self.found.publish_failed.is_some() {
            return;
        }
        let vault_id = self.vault_id();
        let referenced = blobs::referenced(&self.state.store);
        if let Err(e) = blobs::heal(transport, vault_id, store, &referenced) {
            log::warn!("Failed to upload the missing file blobs of vault {vault_id}: {e}");
        }
    }

    /// Save the sync state, signed by `signer`, under the app data directory
    /// `root`, at [`Self::next_generation`] if `advance` is set. A state that
    /// did not change keeps its body, sealed again at a new generation.
    /// Returns the SHA-256 of the file bytes.
    pub(crate) fn save(
        &mut self,
        root: &Path,
        signer: &dyn VaultSigner,
        advance: bool,
    ) -> Result<StateHash, Error> {
        let generation = if advance {
            self.next_generation()
        } else {
            self.local.generation
        };
        if self.changed {
            let padded = self.padded()?;
            self.local.generation = generation;
            self.local.seal(&padded, &self.keyring)?;
        } else if advance {
            self.local.reseal(generation, &self.keyring)?;
        }
        self.local.save(root, signer)
    }

    /// Record the health this transaction found in the sidecar, in place of
    /// the health of the last transaction that ran. A cause that was not found
    /// again clears. A stopped sync found no causes, so its paused causes are
    /// unchanged. The state loaded, so a load failure clears.
    ///
    /// Records the audit events of the transaction, which runs after every
    /// save. A change of health queues `sync.paused`, `sync.resumed`, or the
    /// event of a load failure, and each file quarantined by this transaction
    /// queues `sync.file_quarantined`. A load failure that clears while sync
    /// is stopped queues no event, since sync does not resume.
    pub(crate) fn settle_status(&mut self) {
        for (replica, file) in self.found.new_quarantined.drain(..) {
            self.events.file_quarantined(replica, &file);
        }
        let stopped = self.is_stopped();
        let before = &self.sidecar.health;
        let after = match (stopped, before) {
            (true, Health::Failed { .. }) => Health::Ok,
            (true, health) => health.clone(),
            (false, _) => Health::of_causes(self.found.causes()),
        };
        if *before != after {
            if !stopped {
                self.events.health_changed(before, &after);
            }
            self.sidecar.health = after;
            self.sidecar_changed = true;
        }
        self.events.record();
    }

    /// Audit events queued by this transaction, for a transaction that records
    /// them without [`Self::settle_status`].
    pub(crate) fn take_events(&mut self) -> SyncEvents {
        self.events.take()
    }

    /// Sync status after this transaction.
    pub(crate) fn status(&self) -> SyncStatus {
        SyncStatus::of_trusted(
            self.local.stopped_build.as_deref(),
            self.local.override_build.as_deref(),
            self.sidecar.paused(),
        )
    }

    /// Save the sidecar under the app data directory `root` if it changed. A
    /// failure is logged, since the sidecar is not a source of truth.
    pub(crate) fn save_sidecar(&self, root: &Path) {
        if !self.sidecar_changed {
            return;
        }
        let vault_id = self.vault_id();
        if let Err(e) = self.sidecar.save(root, vault_id) {
            log::error!("Failed to save the sync sidecar of vault {vault_id}: {e}");
        }
    }
}
