use thiserror::Error;

use crate::secrets::keychain::errors::KeychainError;

#[derive(Error, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[error("Vault {0} not found")]
    VaultNotFound(String),

    #[error("Vault is locked")]
    VaultLocked,

    #[error("Vault unlocked but got {0}")]
    VaultInvalidAuth(#[source] KeychainError),

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

    #[error("The vault file key changed while the vault was being opened")]
    VaultFileKeyChanged,

    #[error("Two vault files have the same vault id: {0}")]
    DuplicateVaultId(String),

    #[error("Failed to lock vault: {0}")]
    VaultLockError(#[source] std::io::Error),

    #[error("Passkey operation failed: {0}")]
    Passkey(String),

    #[error("Failed to create new encryption: {0}")]
    KeyCreationFailed(KeychainError),

    #[error("Could not retrieve key from keychain: {0}")]
    KeyRetrievalFailed(KeychainError),

    #[error("Invalid vault key, only a-zA-Z0-9-_ allowed: {0}")]
    InvalidVaultKey(String),

    #[error("Invalid item key, only a-zA-Z0-9-_ allowed: {0}")]
    InvalidItemKey(String),

    #[error("An item with key {0} already exists")]
    DuplicateItemKey(String),

    #[error("Deleted item {0} not found")]
    DeletedItemNotFound(String),

    #[error("Invalid credential key, only a-zA-Z0-9-_ allowed: {0}")]
    InvalidCredentialKey(String),

    #[error("Previous value {0} not found")]
    InvalidHistoryEntry(String),

    #[error("A credential with key {0} already exists")]
    DuplicateCredentialKey(String),

    #[error("Reorder must list every credential of item {0} exactly once")]
    InvalidCredentialOrder(String),

    #[error("Folder {0} not found")]
    InvalidFolder(String),

    #[error("Reorder must list every folder exactly once")]
    InvalidFolderOrder,

    #[error("Section {0} not found")]
    InvalidSection(String),

    #[error("Reorder must list every section of item {0} exactly once")]
    InvalidSectionOrder(String),

    #[error("Invalid autofill settings: {0}")]
    InvalidAutofill(String),

    #[error("Invalid one-time code: {0}")]
    InvalidOneTimeCode(String),

    #[error("Vault index parsing error: {0}")]
    VaultIndexParsingError(String),

    #[error("Failed to export vault: {0}")]
    VaultExportError(String),

    #[error("Failed to import vault: {0}")]
    VaultImportError(String),
}

impl From<Error> for String {
    fn from(err: Error) -> Self {
        err.to_string()
    }
}
