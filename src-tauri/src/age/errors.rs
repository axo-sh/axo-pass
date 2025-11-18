use std::io;

use thiserror::Error;

use crate::secrets::keychain::errors::KeychainError;

#[derive(Error, Debug)]
pub enum AgeError {
    #[error("{0}")]
    InputReadError(#[from] crate::core::read_input::ReadError),

    #[error("Failed to parse recipient {0}: {1}")]
    FailedToParseRecipient(String, &'static str),

    #[error("Failed to parse identity {0}: {1}")]
    FailedToParseIdentity(String, &'static str),

    #[error("Recipient {0} not found in keychain")]
    RecipientNotFound(String),

    #[error("Failed to retrieve recipient {0} from keychain: {1}")]
    FailedToRetrieveRecipient(String, #[source] KeychainError),

    #[error("Failed to delete recipient {0} from keychain: {1}")]
    FailedToDeleteRecipient(String, #[source] anyhow::Error),

    #[error("Age encryption error: {0}")]
    AgeEncryptError(#[from] age::EncryptError),

    #[error("Age decryption error: {0}")]
    AgeDecryptError(#[from] age::DecryptError),

    #[error("Error writing output: {0}")]
    WriteError(#[source] io::Error),
}
