use uuid::Uuid;

use super::crdt::{ReplicaId, Session};

mod apply;
mod diff;
mod failures;
mod generators;
mod guard;
mod join;
mod keys;
mod load;
mod local_state;
mod model;
mod publish;
mod rebuild;
mod repair;
mod resolve;
mod round_trip;
mod sidecar;
mod simulator;
mod state_file;
mod status;
mod sync_keys;
mod transport;
mod txn;
mod view;

/// Time of every mint in the tests.
const NOW: i64 = 1_000;

/// Session of replica `n` with seeded actor ids. Actor `k` of replica `n` is
/// `n << 64 | k`, with `k` from 1.
fn session(n: u128) -> Session {
    let mut next = n << 64;
    Session::with_actor_ids(ReplicaId(Uuid::from_u128(n)), move || {
        next += 1;
        Uuid::from_u128(next)
    })
}

/// Entry id `n`.
fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}
