//! Causal context of a state.

use std::collections::BTreeMap;

use super::ids::{ActorId, WriteId};

/// Highest sequence number seen per actor.
///
/// A state built only by joining full states has seen every write id at or
/// below these numbers. An actor with no entry is at 0.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CausalContext(BTreeMap<ActorId, u64>);

impl CausalContext {
    /// Highest sequence number seen of `actor`, or 0.
    pub fn get(&self, actor: ActorId) -> u64 {
        self.0.get(&actor).copied().unwrap_or(0)
    }

    /// Whether write `id` was seen. Looks up the stored seq for
    /// the `id.actor` and compares it with `id.seq`.
    pub fn covers(&self, id: WriteId) -> bool {
        id.seq <= self.get(id.actor)
    }

    /// Record write `id` as seen. A sequence number below the current entry
    /// leaves the entry unchanged.
    pub fn record(&mut self, id: WriteId) {
        let seq = self.0.entry(id.actor).or_insert(0);
        // take the greater of the current sequence number and the new one
        *seq = (*seq).max(id.seq);
    }

    /// Whether this context holds a higher sequence number than `other` for
    /// any actor.
    pub fn is_ahead_of(&self, other: &Self) -> bool {
        self.0.iter().any(|(actor, seq)| *seq > other.get(*actor))
    }

    /// Join `other` into this context. Each actor takes the higher sequence
    /// number.
    pub fn join(&mut self, other: Self) {
        for (actor, seq) in other.0 {
            self.record(WriteId { actor, seq });
        }
    }
}
