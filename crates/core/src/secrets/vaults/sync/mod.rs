//! Vault sync between the Macs of one user.

pub mod apply;
pub mod crdt;
pub mod diff;
pub mod model;
pub mod view;

#[cfg(test)]
mod tests;
