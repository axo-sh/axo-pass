//! Store with its causal context and actors, and the top-level join.

use std::collections::BTreeMap;

use super::CausalStore;
use super::context::CausalContext;
use super::ids::{ActorId, ReplicaId};

/// Replica and start time of an actor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActorInfo {
    pub replica: ReplicaId,
    /// Writer's clock at the first write id of the actor. Display only.
    pub started_at: i64,
}

/// Full state of one replica: the store, its causal context, and the actors
/// that wrote it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CausalState<S: CausalStore> {
    pub context: CausalContext,
    pub actors: BTreeMap<ActorId, ActorInfo>,
    pub store: S,
}

impl<S: CausalStore> CausalState<S> {
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
