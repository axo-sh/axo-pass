//! Join of the local state files of a vault into the sync state.
//!
//! Each file, own or peer, takes steps 2 to 7 of "Join" in the plan: a joined
//! hash is skipped, the bytes are checked against the hash in the name, the
//! header is checked, the body is decrypted, and the state is checked and
//! joined. Each file is joined, left, or quarantined on its own, so one bad
//! file never stops another. Own files are joined first, then the files of
//! every other replica directory. Rules for removed replicas and lower key
//! ids are milestone 13.

use uuid::Uuid;

use super::crdt::{CausalState, JoinAction, JoinOutcome, OwnFileState, ReplicaId, Session};
use super::keys::SyncKeyring;
use super::model::SyncState;
use super::sidecar::Sidecar;
use super::state_file::{StateFile, StateFileError, StateHash, StateSource};
use super::transport::{FileName, ReadResult, SyncTransport};

/// Result of the join of one state file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FileJoin {
    /// Decrypted and passed the checks. `changed` is set if the state
    /// changed. A state that the local context covers is skipped and changes
    /// nothing.
    Joined { changed: bool },
    /// Listed and not local yet.
    Remote,
    /// Missing, unreadable, under a key the keyring lacks or holds under
    /// another fingerprint, of a newer format, refused, or quarantined.
    NotJoined,
}

impl FileJoin {
    /// Whether the join changed the state.
    pub(crate) fn changed(self) -> bool {
        self == Self::Joined { changed: true }
    }
}

impl From<FileJoin> for OwnFileState {
    fn from(join: FileJoin) -> Self {
        match join {
            FileJoin::Joined { .. } => Self::Joined,
            FileJoin::Remote => Self::Remote,
            FileJoin::NotJoined => Self::NotJoined,
        }
    }
}

/// Join of the state files of vault `vault_id` into `state`, as received by
/// `session`. Joined and quarantined files are recorded in `sidecar`.
pub(crate) struct StateJoin<'a> {
    pub vault_id: Uuid,
    pub state: &'a mut CausalState<SyncState>,
    pub keyring: &'a SyncKeyring,
    pub sidecar: &'a mut Sidecar,
    /// Set if the sidecar changed.
    pub sidecar_changed: &'a mut bool,
    pub session: &'a mut Session,
}

impl StateJoin<'_> {
    /// Join the state file with hash `hash` of `replica`, unless the sidecar
    /// records it as joined.
    ///
    /// A file that is missing, `Remote`, under a key the keyring lacks, under
    /// another fingerprint for its key id, or of a newer format is left and
    /// read again in a later transaction. A file that fails a context check
    /// is refused and read again. A damaged file, and a state that fails the
    /// closure or duplicate write id check, is quarantined by path and
    /// content hash.
    pub(crate) fn file(
        &mut self,
        transport: &dyn SyncTransport,
        replica: ReplicaId,
        hash: StateHash,
    ) -> FileJoin {
        if self.sidecar.is_joined(replica, hash) {
            return FileJoin::Joined { changed: false };
        }
        let vault_id = self.vault_id;
        let name = FileName::State(hash);
        let file_name = name.file_name(vault_id);
        let bytes = match transport.read(vault_id, replica, name) {
            Ok(ReadResult::Local(bytes)) => bytes,
            Ok(ReadResult::Remote) => return FileJoin::Remote,
            Ok(ReadResult::Missing) => return FileJoin::NotJoined,
            Err(e) => {
                log::warn!("Failed to read state file {file_name} of vault {vault_id}: {e}");
                return FileJoin::NotJoined;
            },
        };
        let content_hash = StateHash::of(&bytes);
        if self
            .sidecar
            .is_quarantined(replica, &file_name, content_hash)
        {
            return FileJoin::NotJoined;
        }
        let source = StateSource {
            vault_id,
            replica_id: replica,
            hash,
        };
        let state = match StateFile::decode(&bytes, &source, self.keyring) {
            Ok((_, state)) => state,
            Err(StateFileError::Quarantine(damage)) => {
                self.quarantine(replica, file_name, content_hash, damage.to_string());
                return FileJoin::NotJoined;
            },
            Err(e @ StateFileError::VersionSkew(_)) => {
                log::warn!("State file {file_name} of vault {vault_id} is not joined: {e}");
                return FileJoin::NotJoined;
            },
            Err(e) => {
                log::info!("State file {file_name} of vault {vault_id} is not joined: {e}");
                return FileJoin::NotJoined;
            },
        };
        match self.state.try_join(state, self.session) {
            Ok(outcome) => {
                self.sidecar.record_joined(replica, hash);
                *self.sidecar_changed = true;
                FileJoin::Joined {
                    changed: outcome == JoinOutcome::Joined,
                }
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
                FileJoin::NotJoined
            },
        }
    }

    /// Keep only the joined hashes of `replica` in `listed`.
    pub(crate) fn retain(&mut self, replica: ReplicaId, listed: &[StateHash]) {
        *self.sidecar_changed |= self.sidecar.retain_joined(replica, listed);
    }

    /// Join the state files of every replica directory that `transport`
    /// lists, other than the directory of `own`. Returns whether the state
    /// changed.
    ///
    /// A folder that cannot be listed joins no peer file. A replica directory
    /// that cannot be listed is left, and its joined hashes are kept. The
    /// joined hashes of a replica whose directory is not listed are dropped.
    pub(crate) fn peers(&mut self, transport: &dyn SyncTransport, own: ReplicaId) -> bool {
        let vault_id = self.vault_id;
        let replicas = match transport.list_replicas(vault_id) {
            Ok(replicas) => replicas,
            Err(e) => {
                log::warn!("Failed to list the replicas of vault {vault_id}: {e}");
                return false;
            },
        };
        let mut changed = false;
        for &replica in replicas.iter().filter(|replica| **replica != own) {
            let listed = match transport.list_states(vault_id, replica) {
                Ok(listed) => listed,
                Err(e) => {
                    let replica = replica.0;
                    log::warn!(
                        "Failed to list state files of replica {replica} of vault {vault_id}: {e}"
                    );
                    continue;
                },
            };
            for hash in &listed {
                changed |= self.file(transport, replica, *hash).changed();
            }
            self.retain(replica, &listed);
        }
        *self.sidecar_changed |= self.sidecar.retain_replicas(own, &replicas);
        changed
    }

    /// Quarantine the file `name` of `replica` with content hash `hash`.
    fn quarantine(&mut self, replica: ReplicaId, name: String, hash: StateHash, reason: String) {
        let vault_id = self.vault_id;
        log::warn!("State file {name} of vault {vault_id} is quarantined: {reason}");
        self.sidecar.quarantine(replica, name, hash, reason);
        *self.sidecar_changed = true;
    }
}
