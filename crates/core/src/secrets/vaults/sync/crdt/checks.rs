//! Checks on a state before it is joined.
//!
//! Context checks refuse a state. The causal closure check and the duplicate
//! write id check quarantine it. Every check reads the states and changes
//! neither, so a refused or quarantined state leaves the local state
//! unchanged.

use thiserror::Error;

use super::CausalStore;
use super::ids::{ActorId, WriteId};
use super::register::MAX_COUNTER;
use super::session::Session;
use super::state::CausalState;

/// Result of a join that passed the checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinOutcome {
    /// State was joined.
    Joined,
    /// Local context covers the context of the state, so it was not joined.
    Skipped,
}

/// Handling of a state that failed a check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinAction {
    /// Not joined and not quarantined. Retried in each later transaction.
    Refuse,
    /// Quarantined by path and content hash.
    Quarantine,
}

/// Check that a state failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum JoinError {
    /// Write id or context entry of the session's actor above its last
    /// sequence number. `claim` is the claimed write id and `last` the last
    /// write id of the session.
    #[error("state claims write {claim:?} of this session's actor, which last wrote {last:?}")]
    SessionActorClaimed { claim: WriteId, last: WriteId },
    /// Counter above [`MAX_COUNTER`].
    #[error("state holds counter {counter} at {write_id:?}, above the maximum counter")]
    CounterAboveMax { write_id: WriteId, counter: u64 },
    /// Write id that the context of its own state does not cover.
    #[error("state holds write {write_id:?}, which its context does not cover")]
    NotCausallyClosed { write_id: WriteId },
    /// One write id in one register with a value that differs from the local
    /// value.
    #[error("state holds write {write_id:?} with a value that differs from the local value")]
    DuplicateWriteId { write_id: WriteId },
    /// Actor with info that differs from the local info.
    #[error("state holds actor {actor:?} with info that differs from the local info")]
    DuplicateActorInfo { actor: ActorId },
}

impl JoinError {
    /// Handling of the state. Context checks refuse. The causal closure check
    /// and the duplicate write id check quarantine.
    pub fn action(&self) -> JoinAction {
        match self {
            Self::SessionActorClaimed { .. } | Self::CounterAboveMax { .. } => JoinAction::Refuse,
            Self::NotCausallyClosed { .. }
            | Self::DuplicateWriteId { .. }
            | Self::DuplicateActorInfo { .. } => JoinAction::Quarantine,
        }
    }
}

impl<S: CausalStore> CausalState<S> {
    /// Context checks of this state as received by `session`.
    ///
    /// Refuse a write id or context entry of the session's actor above its
    /// last sequence number. Only the session mints those write ids. Earlier
    /// actors of the replica are not checked. Refuse a counter above
    /// [`MAX_COUNTER`]. No check compares the counter with the local highest
    /// counter.
    pub fn check_context(&self, session: &Session) -> Result<(), JoinError> {
        if let Some(last) = session.last_write() {
            let seq = self.context.get(last.actor);
            if seq > last.seq {
                let claim = WriteId {
                    actor: last.actor,
                    seq,
                };
                return Err(JoinError::SessionActorClaimed { claim, last });
            }
            let claimed = self
                .store
                .find_value(&mut |id, _| id.actor == last.actor && id.seq > last.seq);
            if let Some((claim, _)) = claimed {
                return Err(JoinError::SessionActorClaimed { claim, last });
            }
        }
        let above = self
            .store
            .find_value(&mut |_, counter| counter > MAX_COUNTER);
        if let Some((write_id, counter)) = above {
            return Err(JoinError::CounterAboveMax { write_id, counter });
        }
        Ok(())
    }

    /// Causal closure check. Every write id of the store is covered by the
    /// context of this state.
    pub fn check_closure(&self) -> Result<(), JoinError> {
        match self.store.find_value(&mut |id, _| !self.context.covers(id)) {
            Some((write_id, _)) => Err(JoinError::NotCausallyClosed { write_id }),
            None => Ok(()),
        }
    }

    /// Duplicate write id check of `other` against this state.
    ///
    /// A write id held in one register by both states must hold equal
    /// [`Versioned`](super::Versioned) values. An actor in both `actors` maps
    /// must hold equal info.
    pub fn check_duplicates(&self, other: &Self) -> Result<(), JoinError> {
        if let Some(write_id) = self.store.find_duplicate_write_id(&other.store) {
            return Err(JoinError::DuplicateWriteId { write_id });
        }
        let actor = other
            .actors
            .iter()
            .find(|(actor, info)| self.actors.get(actor).is_some_and(|local| local != *info));
        match actor {
            Some((actor, _)) => Err(JoinError::DuplicateActorInfo { actor: *actor }),
            None => Ok(()),
        }
    }
}
