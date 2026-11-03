//! Sync state in the write transaction of a synced vault.
//!
//! A transaction on a vault with a trusted sync state joins this replica's
//! own state files first, before any write id is minted. If the join changed
//! the state, the view is applied to the vault without a diff. The requested
//! change then runs, and its local edits are recorded under one write id of
//! the session. `s` advances if and only if the vault file changes. The sync
//! state is saved if it or `s` changed, always before the vault.

use std::path::Path;

use uuid::Uuid;

use super::crdt::{CausalState, JoinAction, JoinOutcome, ReplicaId, Session, WriteId};
use super::diff::{DiffError, LocalEdits};
use super::keys::SyncKeyring;
use super::load::TrustedState;
use super::local_state::LocalSyncState;
use super::model::SyncState;
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

    /// Whether a join or a mint changed the state since it was loaded.
    pub(crate) fn changed(&self) -> bool {
        self.changed
    }

    /// Join each own state file listed by `transport` that the sidecar does
    /// not record as joined, as received by `session`. Returns whether the
    /// state changed.
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
        for hash in &listed {
            if !self.sidecar.is_joined(replica, *hash) {
                changed |= self.join_file(transport, replica, *hash, session);
            }
        }
        self.sidecar_changed |= self.sidecar.retain_joined(replica, &listed);
        self.changed |= changed;
        changed
    }

    /// Join the state file with hash `hash` of `replica`. Returns whether the
    /// state changed.
    fn join_file(
        &mut self,
        transport: &dyn SyncTransport,
        replica: ReplicaId,
        hash: StateHash,
        session: &mut Session,
    ) -> bool {
        let vault_id = self.vault_id();
        let name = FileName::State(hash);
        let file_name = name.file_name(vault_id);
        let bytes = match transport.read(vault_id, replica, name) {
            Ok(ReadResult::Local(bytes)) => bytes,
            Ok(ReadResult::Missing | ReadResult::Remote) => return false,
            Err(e) => {
                log::warn!("Failed to read state file {file_name} of vault {vault_id}: {e}");
                return false;
            },
        };
        let content_hash = StateHash::of(&bytes);
        if self
            .sidecar
            .is_quarantined(replica, &file_name, content_hash)
        {
            return false;
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
                return false;
            },
            Err(e) => {
                log::info!("State file {file_name} of vault {vault_id} is not joined: {e}");
                return false;
            },
        };
        match self.state.try_join(state, session) {
            Ok(outcome) => {
                self.sidecar.record_joined(replica, hash);
                self.sidecar_changed = true;
                outcome == JoinOutcome::Joined
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
                false
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
        self.changed |= write_id.is_some();
        Ok(write_id)
    }

    /// Save the sync state, signed by `signer`, under the app data directory
    /// `root`, at the next generation if `advance` is set. A state that did
    /// not change keeps its body, sealed again. Returns the SHA-256 of the
    /// file bytes.
    pub(crate) fn save(
        &mut self,
        root: &Path,
        signer: &dyn VaultSigner,
        advance: bool,
    ) -> Result<StateHash, Error> {
        let generation = self.local.generation + u64::from(advance);
        if self.changed {
            let padded = PaddedBody::of(&self.state)?;
            self.local.generation = generation;
            self.local.seal(&padded, &self.keyring)?;
        } else {
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
