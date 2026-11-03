//! Sync state in the write transaction of a synced vault.
//!
//! A transaction on a vault with a trusted sync state joins this replica's
//! own state files first, then the local state files of the other replicas,
//! before any write id is minted (`sync/join.rs`). If the join changed the
//! state, the view is applied to the vault without a diff. The requested
//! change then runs, and its local edits are recorded under one write id of
//! the session. `s` advances if and only if the vault file changes. The sync
//! state is saved if it or `s` changed, always before the vault.
//!
//! A transaction that publishes writes the staged file before the sync state,
//! and copies it to the synced folder after the vault (`sync/publish.rs`).
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

use std::path::Path;

use jiff::Timestamp;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::crdt::{CausalState, OwnFile, ReplicaId, Session, WriteId};
use super::diff::LocalEdits;
use super::join::StateJoin;
use super::keys::SyncKeyring;
use super::load::TrustedState;
use super::local_state::LocalSyncState;
use super::model::SyncState;
use super::publish::Staged;
use super::rebuild::Rebuild;
use super::repair::Repair;
use super::sidecar::Sidecar;
use super::state_file::StateHash;
use super::state_file::padded::PaddedBody;
use super::status::{BUILD_ID, FoundCauses, SyncStatus};
use super::transport::{FileName, SyncTransport};
use super::view::VaultView;
use crate::secrets::vaults::errors::Error;
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
    /// Whether the publish fields of the header changed since it was loaded.
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
    /// Paused causes found by this transaction.
    found: FoundCauses,
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
            found: FoundCauses::default(),
        }
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
        self.newer_vault.is_some()
    }

    pub(crate) fn keyring(&self) -> &SyncKeyring {
        &self.keyring
    }

    /// Whether the sync state needs a save with no change to `s`: a join or a
    /// mint changed the state, or the publish fields of the header changed.
    pub(crate) fn needs_save(&self) -> bool {
        self.changed || self.header_changed
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
        for hash in &listed {
            let file = join.file(transport, replica, *hash);
            changed |= file.changed();
            own_files.push(OwnFile {
                hash: *hash,
                state: file.into(),
            });
        }
        join.retain(replica, &listed);
        self.own_files = Some(own_files);
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
    /// transaction. A folder or a replica directory that cannot be listed
    /// stops no other directory.
    pub(crate) fn join_peers(
        &mut self,
        transport: &dyn SyncTransport,
        session: &mut Session,
    ) -> bool {
        let own = self.replica();
        let changed = self.join(session).peers(transport, own);
        self.changed |= changed;
        changed
    }

    /// Join of state files into the state, as received by `session`.
    fn join<'a>(&'a mut self, session: &'a mut Session) -> StateJoin<'a> {
        StateJoin {
            vault_id: self.local.vault_id,
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
    pub(crate) fn rebuilt_vault(
        &self,
        key: String,
        file_key: &UnlockedKey,
    ) -> Result<Vault, Error> {
        Rebuild::build(&VaultView::of(&self.state), &self.local, key, file_key)
    }

    /// Apply the view of the state to `vault`, without a diff.
    pub(crate) fn apply(&self, vault: &mut Vault) -> Result<(), Error> {
        VaultView::of(&self.state).apply(vault).map(|_| ())
    }

    /// Whether sync is stopped by drift.
    pub(crate) fn is_stopped(&self) -> bool {
        self.local.stopped_build.is_some()
    }

    /// No-edit guard: diff the vault as loaded, `vault`, against the view of
    /// the state as loaded, before any join and before the requested change.
    /// If the diff finds edits, sync stops with `stopped_build` set to this
    /// build, and no edit is recorded. A sync that is already stopped stays
    /// stopped.
    pub(crate) fn guard(&mut self, vault: &Vault) -> Result<(), Error> {
        if self.is_stopped() {
            return Ok(());
        }
        let edits = self.find(vault)?;
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
    pub(crate) fn record_repair(
        &mut self,
        vault: &Vault,
        session: &mut Session,
        now: i64,
    ) -> Result<Option<WriteId>, Error> {
        let edits = LocalEdits::find_repair(&self.state, vault, self.replica())?;
        let count = edits.len();
        let write_id = edits.record_repair(&mut self.state, session, now);
        if write_id.is_some() {
            let vault_id = self.vault_id();
            log::warn!("Vault {vault_id} sync repair added {count} differences as conflicts");
            self.mark_changed();
        }
        Ok(write_id)
    }

    /// Record the local edits of `vault` against the view of the state, under
    /// one write id of `session` minted at `now`, in Unix seconds. Returns
    /// the write id, or `None` if the vault has no edits. For a `restore`,
    /// an item or credential the vault lacks is moved to the trash, not
    /// removed.
    pub(crate) fn record(
        &mut self,
        vault: &Vault,
        session: &mut Session,
        now: i64,
        restore: bool,
    ) -> Result<Option<WriteId>, Error> {
        let edits = if restore {
            let trashed_at = Timestamp::now().as_second();
            LocalEdits::find_restore(&self.state, vault, self.replica(), trashed_at)?
        } else {
            self.find(vault)?
        };
        let write_id = edits.record(&mut self.state, session, now);
        if write_id.is_some() {
            self.mark_changed();
        }
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
        self.header_changed = true;
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

    /// Copy the staged file to the synced folder through `transport`, after
    /// the vault is saved. On success the sidecar records its hash as the
    /// last publish and as joined, and each older own file that was joined is
    /// deleted. A failed copy is logged and leaves the staged file in place,
    /// named by `staged_hash`, for the next transaction to copy.
    pub(crate) fn publish(&mut self, transport: &dyn SyncTransport) {
        let Some(staged) = self.staged.take() else {
            return;
        };
        let vault_id = self.vault_id();
        let replica = self.replica();
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
                let name = name.file_name(vault_id);
                log::warn!("Failed to delete own state file {name} of vault {vault_id}: {e}");
            }
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
