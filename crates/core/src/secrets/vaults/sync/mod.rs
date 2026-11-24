//! Vault sync between the Macs of one user.

pub mod apply;
pub(crate) mod audit_events;
pub(crate) mod blobs;
pub mod cleanup;
pub mod crdt;
pub mod diff;
pub mod edit_check;
pub mod join;
pub mod join_sync;
pub mod keys;
pub mod listing;
pub mod load;
pub mod local_state;
pub mod manager;
pub mod meta;
pub mod model;
pub mod pairing;
pub mod pins;
pub mod publish;
pub mod rebuild;
pub mod recovery;
pub mod repair;
pub mod report;
pub mod resolve;
pub mod rotation;
pub mod scan_status;
pub mod setup;
pub mod sidecar;
pub mod state_file;
pub mod status;
pub mod sync_log;
pub mod transport;
pub mod txn;
pub mod view;
pub mod wrapping;

#[cfg(test)]
mod tests;
