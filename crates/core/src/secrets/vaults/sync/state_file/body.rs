//! State file body: the CBOR encoding of `CausalState<SyncState>`.
//!
//! The body is a map of `context`, `actors`, and `store`, in the serde forms
//! of the CRDT and model types. Ids are written in full, as 16-byte byte
//! strings. Decoding refuses a state whose context holds an actor with no
//! actor info, or that holds a write id its context does not cover.

use thiserror::Error;

use crate::secrets::vaults::sync::crdt::{ActorId, CausalState, JoinError, WriteId};
use crate::secrets::vaults::sync::model::SyncState;

/// Start of the serde error message of an unknown field.
const UNKNOWN_FIELD: &str = "unknown field";

/// Failure to encode or decode a body.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum BodyError {
    /// Field this build does not know, from a newer format.
    #[error("state body holds a field this build does not know: {0}")]
    VersionSkew(String),
    /// Body that is not CBOR of the sync state.
    #[error("state body is malformed: {0}")]
    Malformed(String),
    #[error("state holds actor {0:?} in its context with no actor info")]
    ActorWithoutInfo(ActorId),
    #[error("state body holds write {0:?}, which its context does not cover")]
    NotCausallyClosed(WriteId),
    #[error("state body cannot be encoded: {0}")]
    Encode(String),
}

impl BodyError {
    /// Whether the body comes from a newer format.
    pub fn is_version_skew(&self) -> bool {
        matches!(self, Self::VersionSkew(_))
    }

    /// Error of a failed CBOR decode. An unknown field is version skew. Any
    /// other failure is a malformed body.
    fn of_cbor(error: ciborium::de::Error<std::io::Error>) -> Self {
        match error {
            ciborium::de::Error::Semantic(_, message) if message.starts_with(UNKNOWN_FIELD) => {
                Self::VersionSkew(message)
            },
            error => Self::Malformed(error.to_string()),
        }
    }
}

/// Encoding and decoding of the body.
pub struct StateBody;

impl StateBody {
    /// CBOR body of `state`. Fails if the context holds an actor with no
    /// actor info.
    pub fn encode(state: &CausalState<SyncState>) -> Result<Vec<u8>, BodyError> {
        Self::check_actors(state)?;
        let mut bytes = Vec::new();
        ciborium::into_writer(state, &mut bytes).map_err(|e| BodyError::Encode(e.to_string()))?;
        Ok(bytes)
    }

    /// State of the CBOR body `bytes`. Bytes after the body fail as a
    /// malformed body.
    pub fn decode(bytes: &[u8]) -> Result<CausalState<SyncState>, BodyError> {
        let mut reader = bytes;
        let state: CausalState<SyncState> =
            ciborium::from_reader(&mut reader).map_err(BodyError::of_cbor)?;
        if !reader.is_empty() {
            let trailing = reader.len();
            return Err(BodyError::Malformed(format!(
                "{trailing} bytes after the body"
            )));
        }
        Self::check_actors(&state)?;
        state.check_closure().map_err(|error| match error {
            JoinError::NotCausallyClosed { write_id } => BodyError::NotCausallyClosed(write_id),
            error => BodyError::Malformed(error.to_string()),
        })?;
        Ok(state)
    }

    /// Every actor of the context has actor info.
    fn check_actors(state: &CausalState<SyncState>) -> Result<(), BodyError> {
        match state
            .context
            .iter()
            .find(|(actor, _)| !state.actors.contains_key(actor))
        {
            Some((actor, _)) => Err(BodyError::ActorWithoutInfo(actor)),
            None => Ok(()),
        }
    }
}
