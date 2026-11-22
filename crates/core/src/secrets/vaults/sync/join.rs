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
use super::local_state::LocalSyncState;
use super::model::{KeyId, SyncState};
use super::sidecar::Sidecar;
use super::state_file::{StateFile, StateFileError, StateHash, StateSource};
use super::status::FoundCauses;
use super::sync_log;
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
    /// another fingerprint, of a newer format, or refused.
    NotJoined,
    /// Quarantined now or by an earlier transaction.
    Quarantined,
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
            FileJoin::NotJoined | FileJoin::Quarantined => Self::NotJoined,
        }
    }
}

/// Result of the join of the peer state files.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PeerJoin {
    /// Whether the state changed.
    pub changed: bool,
    /// Whether the replica directories and every peer directory were listed.
    pub listed: bool,
    /// Count of listed peer files that are not local yet.
    pub remote: usize,
}

/// Join of the state files of vault `vault_id` into `state`, as received by
/// `session`. Joined and quarantined files are recorded in `sidecar`.
/// Listing failures, quarantined files, files of a newer format, and files of
/// a separate enable are recorded in `found`.
pub(crate) struct StateJoin<'a> {
    pub vault_id: Uuid,
    /// Sync state that holds `state`, for its key id, replica id, and pins.
    pub local: &'a LocalSyncState,
    pub state: &'a mut CausalState<SyncState>,
    pub keyring: &'a SyncKeyring,
    pub sidecar: &'a mut Sidecar,
    /// Set if the sidecar changed.
    pub sidecar_changed: &'a mut bool,
    pub session: &'a mut Session,
    pub found: &'a mut FoundCauses,
}

impl StateJoin<'_> {
    /// Join the state file with hash `hash` of `replica`, unless the sidecar
    /// records it as joined.
    ///
    /// A file that is missing, `Remote`, under a key the keyring lacks, under
    /// another fingerprint for its key id, or of a newer format is left and
    /// read again in a later transaction. A file under another fingerprint
    /// is counted if [`Self::is_separate`] holds. A file that fails a
    /// context check is refused and read again. A damaged file, and a state
    /// that fails the closure or duplicate write id check, is quarantined by
    /// path and content hash.
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
        let file_name = name.file_name();
        let bytes = match transport.read(vault_id, replica, name) {
            Ok(ReadResult::Local(bytes)) => bytes,
            Ok(ReadResult::Remote) => return FileJoin::Remote,
            Ok(ReadResult::Missing) => return FileJoin::NotJoined,
            Err(e) => {
                sync_log::warn(
                    vault_id,
                    "Failed to read a state file",
                    &format!("{file_name}: {e}"),
                );
                return FileJoin::NotJoined;
            },
        };
        let content_hash = StateHash::of(&bytes);
        if self
            .sidecar
            .is_quarantined(replica, &file_name, content_hash)
        {
            self.found.quarantined += 1;
            return FileJoin::Quarantined;
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
                return FileJoin::Quarantined;
            },
            Err(e @ StateFileError::VersionSkew(_)) => {
                sync_log::warn(
                    vault_id,
                    "State file from a newer version is not joined",
                    &format!("{file_name}: {e}"),
                );
                self.found.version_skew += 1;
                return FileJoin::NotJoined;
            },
            Err(e @ StateFileError::OtherKey(key_id)) => {
                log::info!("State file {file_name} of vault {vault_id} is not joined: {e}");
                if self.is_separate(replica, key_id) {
                    self.found.separate.insert(replica);
                }
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
            Err(e) => match e.action() {
                JoinAction::Refuse => {
                    sync_log::warn(
                        vault_id,
                        "State file is refused",
                        &format!("{file_name}: {e}"),
                    );
                    FileJoin::NotJoined
                },
                JoinAction::Quarantine => {
                    self.quarantine(replica, file_name, content_hash, e.to_string());
                    FileJoin::Quarantined
                },
            },
        }
    }

    /// Whether a file of `replica` under key id `key_id` with another
    /// fingerprint is from a Mac that enabled sync separately (D10 of doc
    /// 18). The key id is the current key id, and the replica is not this
    /// replica, has no pin, and is not in `replica_keys` of the state. A
    /// pinned replica under another fingerprint is the re-link case of
    /// milestone 13 and is not counted.
    fn is_separate(&self, replica: ReplicaId, key_id: KeyId) -> bool {
        key_id == self.local.key_id
            && replica != self.local.replica_id
            && !self.local.pinned_keys.contains_key(&replica)
            && self.state.store.replica_keys.get(&replica).is_none()
    }

    /// Keep only the joined hashes of `replica` in `listed`.
    pub(crate) fn retain(&mut self, replica: ReplicaId, listed: &[StateHash]) {
        *self.sidecar_changed |= self.sidecar.retain_joined(replica, listed);
    }

    /// Join the state files of every replica directory that `transport`
    /// lists, other than the directory of `own`.
    ///
    /// A folder that cannot be listed joins no peer file. A replica directory
    /// that cannot be listed is left, and its joined hashes are kept. The
    /// joined hashes of a replica whose directory is not listed are dropped.
    pub(crate) fn peers(&mut self, transport: &dyn SyncTransport, own: ReplicaId) -> PeerJoin {
        let vault_id = self.vault_id;
        let mut join = PeerJoin::default();
        let replicas = match transport.list_replicas(vault_id) {
            Ok(replicas) => replicas,
            Err(e) => {
                sync_log::warn(vault_id, "Failed to list the replicas", &e);
                self.found.unreachable(e);
                return join;
            },
        };
        join.listed = true;
        for &replica in replicas.iter().filter(|replica| **replica != own) {
            let listed = match transport.list_states(vault_id, replica) {
                Ok(listed) => listed,
                Err(e) => {
                    let replica = replica.0;
                    sync_log::warn(
                        vault_id,
                        "Failed to list the state files of a replica",
                        &format!("{replica}: {e}"),
                    );
                    self.found.unreachable(e);
                    join.listed = false;
                    continue;
                },
            };
            for hash in &listed {
                match self.file(transport, replica, *hash) {
                    FileJoin::Remote => join.remote += 1,
                    file => join.changed |= file.changed(),
                }
            }
            self.retain(replica, &listed);
        }
        *self.sidecar_changed |= self.sidecar.retain_replicas(own, &replicas);
        join
    }

    /// Quarantine the file `name` of `replica` with content hash `hash`.
    fn quarantine(&mut self, replica: ReplicaId, name: String, hash: StateHash, reason: String) {
        let vault_id = self.vault_id;
        sync_log::warn(
            vault_id,
            "State file is quarantined",
            &format!("{name}: {reason}"),
        );
        self.sidecar.quarantine(replica, name, hash, reason);
        *self.sidecar_changed = true;
        self.found.quarantined += 1;
    }
}
