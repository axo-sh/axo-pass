//! State files, the published form of a replica's sync state.
//!
//! The decrypted body is the CBOR encoding of the sync state, built by
//! [`body::StateBody`].

pub mod body;
