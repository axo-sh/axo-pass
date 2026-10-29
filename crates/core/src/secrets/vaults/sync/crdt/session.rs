//! Sessions, the writers that mint write ids.

use std::fmt;

use uuid::Uuid;

use super::CausalStore;
use super::ids::{ActorId, ReplicaId, WriteId};
use super::register::{MAX_COUNTER, Mint};
use super::state::{ActorInfo, CausalState};

/// Writer of one replica. Owned by the caller.
///
/// The actor is created at the first mint, so a session that mints nothing
/// adds no actor. An actor mints only while the state holds its last write
/// id as the context entry of the actor. Otherwise the next mint starts a new
/// actor, so a replaced state never reuses a write id.
pub struct Session {
    pub replica: ReplicaId,
    /// Last write id of the actor. None before the first mint and after
    /// [`Session::end`].
    last_write: Option<WriteId>,
    /// Source of new actor ids.
    new_actor_id: Box<dyn FnMut() -> Uuid + Send>,
}

impl Session {
    /// Session of `replica` with random actor ids.
    pub fn new(replica: ReplicaId) -> Self {
        Self::with_actor_ids(replica, Uuid::new_v4)
    }

    /// Session of `replica` that takes actor ids from `new_actor_id`. Used
    /// for seeded ids in tests.
    pub fn with_actor_ids(
        replica: ReplicaId,
        new_actor_id: impl FnMut() -> Uuid + Send + 'static,
    ) -> Self {
        Self {
            replica,
            last_write: None,
            new_actor_id: Box::new(new_actor_id),
        }
    }

    /// Current actor, if it has minted.
    pub fn actor(&self) -> Option<ActorId> {
        self.last_write.map(|id| id.actor)
    }

    /// Last write id minted by the current actor.
    pub fn last_write(&self) -> Option<WriteId> {
        self.last_write
    }

    /// Mint the write id of one transaction at `now`, in Unix seconds.
    ///
    /// The context of `state` advances by one write id. The current actor
    /// takes its next sequence number if the context entry of the actor
    /// equals its last sequence number. Otherwise a new actor starts at 1 and
    /// is recorded in `actors`. The counter is one above the highest counter
    /// in the store, at least 2, and at most [`MAX_COUNTER`].
    pub fn mint<S: CausalStore>(&mut self, state: &mut CausalState<S>, now: i64) -> Mint {
        let counter = state
            .store
            .highest_counter()
            .saturating_add(1)
            .clamp(2, MAX_COUNTER);
        let write_id = match self.last_write {
            Some(last) if state.context.get(last.actor) == last.seq => WriteId {
                actor: last.actor,
                seq: last.seq + 1,
            },
            _ => {
                let actor = ActorId((self.new_actor_id)());
                state.actors.insert(
                    actor,
                    ActorInfo {
                        replica: self.replica,
                        started_at: now,
                    },
                );
                WriteId { actor, seq: 1 }
            },
        };
        state.context.record(write_id);
        self.last_write = Some(write_id);
        Mint {
            write_id,
            counter,
            written_at: now,
        }
    }

    /// End the current actor. The next mint starts a new actor.
    pub fn end(&mut self) {
        self.last_write = None;
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("replica", &self.replica)
            .field("last_write", &self.last_write)
            .finish_non_exhaustive()
    }
}
