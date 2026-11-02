//! Store with its causal context and actors, and the top-level join.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::CausalStore;
use super::checks::{JoinError, JoinOutcome};
use super::context::CausalContext;
use super::ids::{ActorId, ReplicaId};
use super::or_map::UniqueMap;
use super::session::Session;

/// Replica and start time of an actor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorInfo {
    pub replica: ReplicaId,
    /// Writer's clock at the first write id of the actor. Display only.
    pub started_at: i64,
}

/// Full state of one replica: the store, its causal context, and the actors
/// that wrote it.
///
/// The serde form is a map of the three fields. An actor listed twice fails.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CausalState<S: CausalStore> {
    pub context: CausalContext,
    #[serde(deserialize_with = "UniqueMap::deserialize")]
    pub actors: BTreeMap<ActorId, ActorInfo>,
    pub store: S,
}

impl<S: CausalStore> CausalState<S> {
    /// Check `other` and join it into this state, as received by `session`.
    ///
    /// Steps 5 to 7 of "Join" in the plan. Context checks run first, then
    /// the causal closure check, then the duplicate write id check. A state
    /// that fails a check is not joined. A claim on the session's actor also
    /// ends the actor, so the next mint starts a new actor. A state whose
    /// context the local context covers is skipped. The checks run before
    /// the skip, since the skip is correct only for a causally closed state.
    pub fn try_join(
        &mut self,
        other: Self,
        session: &mut Session,
    ) -> Result<JoinOutcome, JoinError> {
        if let Err(err) = other.check_context(session) {
            if matches!(err, JoinError::SessionActorClaimed { .. }) {
                session.end();
            }
            return Err(err);
        }
        other.check_closure()?;
        self.check_duplicates(&other)?;
        if !other.context.is_ahead_of(&self.context) {
            return Ok(JoinOutcome::Skipped);
        }
        self.join(other);
        Ok(JoinOutcome::Joined)
    }

    /// Join `other` into this state.
    ///
    /// The store joins under both contexts as they were before the join. Then
    /// the contexts join, then `actors` is united. An actor in both sides
    /// keeps the local info.
    pub fn join(&mut self, other: Self) {
        let Self {
            context,
            actors,
            store,
        } = other;
        self.store.join(&self.context, store, &context);
        self.context.join(context);
        for (actor, info) in actors {
            self.actors.entry(actor).or_insert(info);
        }
    }
}
