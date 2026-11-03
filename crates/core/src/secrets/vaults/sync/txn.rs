//! Sync state in the write transaction of a synced vault.
//!
//! A transaction on a vault with a trusted sync state joins this replica's
//! own state files first, before any write id is minted. If the join changed
//! the state, the view is applied to the vault without a diff. The requested
//! change then runs, and its local edits are recorded under one write id of
//! the session. `s` advances if and only if the vault file changes. The sync
//! state is saved if it or `s` changed, always before the vault.
//!
//! A transaction that publishes writes the staged file before the sync state,
//! and copies it to the synced folder after the vault (`sync/publish.rs`).

use std::path::Path;

use uuid::Uuid;
use zeroize::Zeroizing;

use super::crdt::{
    CausalState, JoinAction, JoinOutcome, OwnFile, OwnFileState, ReplicaId, Session, WriteId,
};
use super::diff::{DiffError, LocalEdits};
use super::keys::SyncKeyring;
use super::load::TrustedState;
use super::local_state::LocalSyncState;
use super::model::SyncState;
use super::publish::Staged;
use super::rebuild::Rebuild;
use super::sidecar::Sidecar;
use super::state_file::padded::PaddedBody;
use super::state_file::{StateFile, StateFileError, StateHash, StateSource};
use super::transport::{FileName, ReadResult, SyncTransport};
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
            changed: false,
            header_changed: false,
            padded: None,
            own_files: None,
            staged: None,
            sidecar,
            sidecar_changed: false,
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
                return false;
            },
        };
        let mut changed = false;
        let mut own_files = Vec::with_capacity(listed.len());
        for hash in &listed {
            let state = if self.sidecar.is_joined(replica, *hash) {
                OwnFileState::Joined
            } else {
                let (state, joined) = self.join_file(transport, replica, *hash, session);
                changed |= joined;
                state
            };
            own_files.push(OwnFile { hash: *hash, state });
        }
        self.sidecar_changed |= self.sidecar.retain_joined(replica, &listed);
        self.own_files = Some(own_files);
        self.changed |= changed;
        changed
    }

    /// Join the state file with hash `hash` of `replica`. Returns the state of
    /// the file for the publish rules, and whether the state changed.
    fn join_file(
        &mut self,
        transport: &dyn SyncTransport,
        replica: ReplicaId,
        hash: StateHash,
        session: &mut Session,
    ) -> (OwnFileState, bool) {
        let not_joined = (OwnFileState::NotJoined, false);
        let vault_id = self.vault_id();
        let name = FileName::State(hash);
        let file_name = name.file_name(vault_id);
        let bytes = match transport.read(vault_id, replica, name) {
            Ok(ReadResult::Local(bytes)) => bytes,
            Ok(ReadResult::Remote) => return (OwnFileState::Remote, false),
            Ok(ReadResult::Missing) => return not_joined,
            Err(e) => {
                log::warn!("Failed to read state file {file_name} of vault {vault_id}: {e}");
                return not_joined;
            },
        };
        let content_hash = StateHash::of(&bytes);
        if self
            .sidecar
            .is_quarantined(replica, &file_name, content_hash)
        {
            return not_joined;
        }
        let source = StateSource {
            vault_id,
            replica_id: replica,
            hash,
        };
        let state = match StateFile::decode(&bytes, &source, &self.keyring) {
            Ok((_, state)) => state,
            Err(StateFileError::Quarantine(damage)) => {
                self.quarantine(replica, file_name, content_hash, damage.to_string());
                return not_joined;
            },
            Err(e) => {
                log::info!("State file {file_name} of vault {vault_id} is not joined: {e}");
                return not_joined;
            },
        };
        match self.state.try_join(state, session) {
            Ok(outcome) => {
                self.sidecar.record_joined(replica, hash);
                self.sidecar_changed = true;
                (OwnFileState::Joined, outcome == JoinOutcome::Joined)
            },
            Err(e) => {
                match e.action() {
                    JoinAction::Refuse => {
                        log::warn!("State file {file_name} of vault {vault_id} is refused: {e}");
                    },
                    JoinAction::Quarantine => {
                        self.quarantine(replica, file_name, content_hash, e.to_string());
                    },
                }
                not_joined
            },
        }
    }

    /// Quarantine the file `name` of `replica` with content hash `hash`.
    fn quarantine(&mut self, replica: ReplicaId, name: String, hash: StateHash, reason: String) {
        let vault_id = self.vault_id();
        log::warn!("State file {name} of vault {vault_id} is quarantined: {reason}");
        self.sidecar.quarantine(replica, name, hash, reason);
        self.sidecar_changed = true;
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

    /// Record the local edits of `vault` against the view of the state, under
    /// one write id of `session` minted at `now`, in Unix seconds. Returns
    /// the write id, or `None` if the vault has no edits.
    pub(crate) fn record(
        &mut self,
        vault: &Vault,
        session: &mut Session,
        now: i64,
    ) -> Result<Option<WriteId>, Error> {
        let edits = LocalEdits::find(&self.state, vault, self.replica()).map_err(|e| match e {
            DiffError::Vault(e) => e,
            e => Error::SyncDiffError(e.to_string()),
        })?;
        let write_id = edits.record(&mut self.state, session, now);
        if write_id.is_some() {
            self.changed = true;
            self.padded = None;
        }
        Ok(write_id)
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
    /// `root`, at the next generation if `advance` is set. A state that did
    /// not change keeps its body, sealed again at a new generation. Returns
    /// the SHA-256 of the file bytes.
    pub(crate) fn save(
        &mut self,
        root: &Path,
        signer: &dyn VaultSigner,
        advance: bool,
    ) -> Result<StateHash, Error> {
        let generation = self.local.generation + u64::from(advance);
        if self.changed {
            let padded = self.padded()?;
            self.local.generation = generation;
            self.local.seal(&padded, &self.keyring)?;
        } else if advance {
            self.local.reseal(generation, &self.keyring)?;
        }
        self.local.save(root, signer)
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
