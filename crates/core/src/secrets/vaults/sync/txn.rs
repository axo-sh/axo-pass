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
use super::blobs;
use super::crdt::{CausalState, OwnFile, OwnFileState, ReplicaId, Session, WriteId};
use super::diff::LocalEdits;
use super::join::{FileJoin, StateJoin};
use super::keys::{SyncKey, SyncKeyring};
use super::load::TrustedState;
use super::local_state::LocalSyncState;
use super::model::{KeyId, ReplicaKeys, SyncState};
use super::pins::{PairedPin, Pins};
use super::publish::Staged;
use super::rebuild::Rebuild;
use super::recovery::{RecoveryAdd, RecoveryRecipients};
use super::repair::{Repair, SyncRequest};
use super::resolve::HistoryIds;
use super::sidecar::Sidecar;
use super::state_file::StateHash;
use super::state_file::padded::PaddedBody;
use super::status::{BUILD_ID, FoundCauses, SyncStatus};
use super::transport::{FileName, SyncTransport, TransportRoot};
use super::view::VaultView;
use super::wrapping::{DeviceWrapping, KeyFile};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::files::store::BlobStore;
use crate::secrets::vaults::format::signing::VaultSigner;
use crate::secrets::vaults::model::{UnlockedKey, Vault};

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
        let loaded_joined = sidecar.joined.clone();
        let loaded_stop = (local.stopped_build.clone(), local.override_build.clone());
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
            found: FoundCauses::default(),
            remote: 0,
            peers_listed: false,
            blob_store: None,
            blobs_uploaded: false,
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
        join.changed
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
    pub(crate) fn write_key_file(
        &mut self,
        transport: &dyn SyncTransport,
        device: Option<DeviceWrapping>,
    ) -> Result<(), Error> {
        let recipients = if self.syncs() {
            self.recovery_recipients()
        } else {
            Vec::new()
        };
        if device.is_none() && recipients.is_empty() {
            return Ok(());
        }
        let result = self.rewrite_key_file(transport, device, &recipients);
        if let Err(e) = &result
            && !recipients.is_empty()
        {
            let vault_id = self.vault_id();
            log::warn!("Failed to write the age wrappings of vault {vault_id}: {e}");
            self.found
                .publish_failed
                .get_or_insert_with(|| e.to_string());
        }
        result
    }

    /// Read, change, and write the own `key.json` for
    /// [`Self::write_key_file`].
    fn rewrite_key_file(
        &self,
        transport: &dyn SyncTransport,
        device: Option<DeviceWrapping>,
        recipients: &[String],
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
        }
        if !changed {
            return Ok(());
        }
        transport.write_own(vault_id, own, FileName::Key, &file.to_bytes())
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
            Ok(()) => Ok(vault),
            Err(e) if self.changed => {
                self.apply_failed(e);
                self.discard_join()?;
                let mut vault = Rebuild::empty(&self.local, key, file_key)?;
                self.apply_view(&mut vault)?;
                Ok(vault)
            },
            Err(e) => Err(e),
        }
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
        self.apply_view(vault)
    }

    /// Apply the view of the state to `vault`, without a diff.
    fn apply_view(&self, vault: &mut Vault) -> Result<(), Error> {
        self.apply(&VaultView::of(&self.state), vault)
    }

    /// Apply `view` to `vault`, without a diff.
    fn apply(&self, view: &VaultView, vault: &mut Vault) -> Result<(), Error> {
        #[cfg(test)]
        if let Some(fault) = self.apply_fault {
            return view.apply_with_fault(vault, fault).map(|_| ());
        }
        view.apply(vault).map(|_| ())
    }

    /// Apply the view of the state to `vault`. If the apply fails, `vault`
    /// is put back as it was before the apply, the failure is recorded as a
    /// paused cause, and `false` is returned.
    fn try_apply(&mut self, vault: &mut Vault) -> Result<bool, Error> {
        let before = vault.duplicate()?;
        match self.apply_view(vault) {
            Ok(()) => Ok(true),
            Err(e) => {
                *vault = before;
                self.apply_failed(e);
                Ok(false)
            },
        }
    }

    /// Apply the view of the joined state to `vault`, before the requested
    /// change. If the apply fails, the join is discarded, and `vault` is as
    /// it was before the join. In a repair, the repair is discarded too, and
    /// the transaction saves the vault only.
    pub(crate) fn apply_joined(&mut self, vault: &mut Vault) -> Result<(), Error> {
        if self.try_apply(vault)? {
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
        if self.try_apply(vault)? {
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
        if repair != Repair::NewerVault {
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
    /// MVP edit rule. A write to an Ask register supersedes every value of
    /// the register, for every request and writer. Each credential value not
    /// chosen is written to `history` under the same write id
    /// ([`LocalEdits::keep_not_chosen`]).
    pub(crate) fn record(
        &mut self,
        vault: &mut Vault,
        session: &mut Session,
        now: i64,
        request: &SyncRequest,
    ) -> Result<Option<WriteId>, Error> {
        if let Err(e) = HistoryIds::rewrite(&self.state, vault) {
            self.diff_failed(e)?;
            return Ok(None);
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
                return Ok(None);
            },
        };
        edits.keep_not_chosen(&self.state, now);
        if let SyncRequest::AddRecovery(add) = request {
            edits.add_recovery(add.recipient.clone(), add.value.clone());
        }
        let write_id = edits.record(&mut self.state, session, now);
        if write_id.is_some() {
            self.mark_changed();
        }
        Ok(write_id)
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
        if !self.state.context.should_publish(
            &self.local.published_context,
            last_publish,
            own_files,
        ) {
            return Ok(());
        }
        let vault_id = self.vault_id();
        if self.local.staged_context.as_ref() == Some(&self.state.context)
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
    /// failed upload copies no state file.
    pub(crate) fn publish(&mut self, transport: &dyn SyncTransport) {
        let Some(staged) = self.staged.take() else {
            return;
        };
        let vault_id = self.vault_id();
        let replica = self.replica();
        if let Some(store) = &self.blob_store
            && let Err(e) = blobs::upload(transport, vault_id, store, &self.local.staged_blobs)
        {
            log::warn!("Failed to upload the file blobs of vault {vault_id}: {e}");
            self.found.publish_failed = Some(e.to_string());
            return;
        }
        self.blobs_uploaded = self.blob_store.is_some();
        let own_files = self.own_files.take().unwrap_or_default();
        if let Err(e) = staged.copy(transport, vault_id, replica, &own_files) {
            log::warn!("Failed to publish the staged file of vault {vault_id}: {e}");
            self.found.publish_failed = Some(e.to_string());
            return;
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

    /// Record the paused causes this transaction found in the sidecar, in
    /// place of those of the last transaction that synced. A cause that was
    /// not found again clears. A stopped sync found no causes, so the
    /// sidecar is unchanged.
    pub(crate) fn settle_status(&mut self) {
        if self.is_stopped() {
            return;
        }
        let causes = self.found.causes();
        if self.sidecar.paused != causes {
            self.sidecar.paused = causes;
            self.sidecar_changed = true;
        }
    }

    /// Sync status after this transaction.
    pub(crate) fn status(&self) -> SyncStatus {
        SyncStatus::of_trusted(
            self.local.stopped_build.as_deref(),
            self.local.override_build.as_deref(),
            &self.sidecar.paused,
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
