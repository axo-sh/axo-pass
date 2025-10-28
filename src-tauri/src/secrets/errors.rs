use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Vault not found")]
    VaultNotFound,

    #[error("Failed to create vault directory: {0}")]
    VaultDirCreateError(#[source] std::io::Error),

    #[error("Failed to read vault: {0}")]
    VaultReadError(#[source] std::io::Error),

    #[error("Failed to deserialize vault: {0}")]
    VaultDeserializationError(#[source] serde_json::Error),

    #[error("Failed to encrypt vault file key")]
    VaultFileKeyEncryptionError,

    #[error("Failed to serialize vault: {0}")]
    VaultSerializationError(#[source] serde_json::Error),

    #[error("Failed to save vault: {0}")]
    VaultWriteError(#[source] std::io::Error),

    #[error("Keychain error: {0}")]
    KeychainError(#[source] anyhow::Error),

    #[error("Failed to add secret to vault: {0}")]
    VaultAddSecretError(anyhow::Error),
}
