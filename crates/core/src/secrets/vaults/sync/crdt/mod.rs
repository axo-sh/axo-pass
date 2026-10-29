//! State-based CRDT primitives and their join.

mod context;
mod ids;
mod or_map;
mod publish;
mod register;
mod session;
mod state;

#[cfg(test)]
mod tests;

pub use context::CausalContext;
pub use ids::{ActorId, ReplicaId, WriteId};
pub use or_map::OrMap;
pub use publish::{OwnFile, OwnFileState};
pub use register::{
    Ask, MAX_COUNTER, Merge, Mint, MvRegister, Order, OrderKey, Own, Policy, PolicyKind, Rotation,
    Stop, Trash, Versioned,
};
pub use session::Session;
pub use state::{ActorInfo, CausalState};

/// Trait for a value that holds write ids. Implemented by [`OrMap`] and
/// [`MvRegister`]
pub trait CausalStore: Default {
    /// Whether the store holds no value.
    fn is_empty(&self) -> bool;

    /// Call `f` with the write id and counter of each value.
    fn each_value(&self, f: &mut dyn FnMut(WriteId, u64));

    /// Highest counter of any value, or 0 if the store is empty.
    fn highest_counter(&self) -> u64 {
        let mut highest = 0;
        self.each_value(&mut |_, counter| highest = highest.max(counter));
        highest
    }

    /// Join `other` into this store. `ctx` is the context of this store and
    /// `other_ctx` the context of `other`, both as they were before the join.
    fn join(&mut self, ctx: &CausalContext, other: Self, other_ctx: &CausalContext);
}
