use thiserror::Error;

use crate::secrets::keychain::errors::KeychainError;

#[derive(Error, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[error("Vault {0} not found")]
    VaultNotFound(String),

    #[error("Vault is locked")]
    VaultLocked,

    #[error("Failed to create vault directory: {0}")]
    VaultDirCreateError(#[source] std::io::Error),

    #[error("Failed to read vault: {0}")]
    VaultReadError(#[source] std::io::Error),

    #[error("Failed to deserialize vault: {0}")]
    VaultDeserializationError(#[source] serde_json::Error),

    #[error("Failed to encrypt vault file key")]
    VaultFileKeyEncryptionError,

    #[error("Failed to decrypt vault file key")]
    VaultFileKeyDecryptionError,

    #[error("Failed to encrypt secret")]
    VaultSecretEncryptionError,

    #[error("Failed to decrypt secret")]
    VaultSecretDecryptionError,

    #[error("Failed to serialize vault: {0}")]
    VaultSerializationError(#[source] serde_json::Error),

    #[error("Failed to save vault: {0}")]
    VaultWriteError(#[source] std::io::Error),

    #[error("Failed to update vault key: {0}")]
    VaultKeyUpdateFailed(#[source] std::io::Error),

    #[error("Failed to delete vault: {0}")]
    VaultDeleteError(#[source] std::io::Error),

    #[error("Invalid vault item reference: {0}")]
    InvalidVaultItemReference(String),

    #[error("Failed to create new encryption: {0}")]
    KeyCreationFailed(KeychainError),

    #[error("Could not retrieve key from keychain: {0}")]
    KeyRetrievalFailed(KeychainError),

    #[error("Could not retrieve secret {0} from vault: {1}")]
    SecretRetrievalFailed(String, #[source] anyhow::Error),

    #[error("Invalid vault key, only a-zA-Z0-9-_ allowed: {0}")]
    InvalidVaultKey(String),

    #[error("Invalid item key, only a-zA-Z0-9-_ allowed: {0}")]
    InvalidItemKey(String),

    #[error("Invalid credential key, only a-zA-Z0-9-_ allowed: {0}")]
    InvalidCredentialKey(String),
}

impl From<Error> for String {
    fn from(err: Error) -> Self {
        err.to_string()
    }
}
