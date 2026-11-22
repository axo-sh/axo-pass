use uuid::Uuid;

use super::crdt::{ReplicaId, Session};
use crate::secrets::vaults::{Error, VaultHandle};

mod apply;
mod audit_events;
mod diff;
mod disable;
mod edit_rule;
mod failures;
mod faults;
mod files;
mod folder;
mod generators;
mod guard;
mod import;
mod join;
mod join_sync;
mod keys;
mod load;
mod local_state;
mod manager;
mod meta;
mod model;
mod pairing;
mod pins;
mod publish;
mod reads;
mod rebuild;
mod recovery;
mod repair;
mod report;
mod resolve;
mod round_trip;
mod s3;
mod separate;
mod setup;
mod sidecar;
mod simulator;
mod state_file;
mod status;
mod sync_keys;
mod transport;
mod txn;
mod view;
mod wrapping;

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

/// `edit` declared as a writer outside the UI, so a write to an Ask register
/// is not refused (`sync/edit_check.rs`).
fn as_writer<R>(
    edit: impl FnOnce(&mut VaultHandle) -> Result<R, Error>,
) -> impl FnOnce(&mut VaultHandle) -> Result<R, Error> {
    move |vh| {
        vh.write_outside_ui();
        edit(vh)
    }
}
