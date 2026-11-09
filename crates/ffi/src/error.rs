use axo_pass_core::age::errors::AgeError;
use axo_pass_core::secrets::keychain::errors::KeychainError;
use axo_pass_core::secrets::vaults::Error as VaultError;
use axo_pass_core::ssh::agent_client::{self};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    /// Touch ID / password prompt was dismissed by the user.
    #[error("Authentication cancelled")]
    AuthCancelled,

    /// A previously-granted auth context expired before the operation
    /// completed.
    #[error("Authentication expired")]
    AuthExpired,

    #[error("Not found: {0}")]
    NotFound(String),

    /// The request itself was invalid (e.g. a malformed vault/item/credential
    /// key, or a value that fails a precondition like "already exists").
    #[error("{0}")]
    InvalidInput(String),

    /// Anything else — message is the Debug repr of the underlying error.
    #[error("{0}")]
    Internal(String),

    #[error("State corrupted (mutex poisoned)")]
    Poisoned,
}

impl From<VaultError> for FfiError {
    fn from(e: VaultError) -> Self {
        match e {
            VaultError::VaultNotFound(k) => FfiError::NotFound(k),
            VaultError::VaultInvalidAuth(k) => FfiError::from(k),
            VaultError::KeyRetrievalFailed(k) => FfiError::from(k),
            VaultError::KeyCreationFailed(k) => FfiError::from(k),
            VaultError::InvalidVaultKey(k) => {
                FfiError::InvalidInput(format!("Invalid vault key: {k}"))
            },
            VaultError::InvalidItemKey(k) => {
                FfiError::InvalidInput(format!("Invalid item key: {k}"))
            },
            VaultError::InvalidCredentialKey(k) => {
                FfiError::InvalidInput(format!("Invalid credential key: {k}"))
            },
            VaultError::InvalidHistoryEntry(id) => {
                FfiError::NotFound(format!("Previous value {id}"))
            },
            VaultError::InvalidFolder(id) => FfiError::NotFound(format!("Folder {id}")),
            VaultError::InvalidSection(id) => FfiError::NotFound(format!("Section {id}")),
            VaultError::DeletedItemNotFound(id) => FfiError::NotFound(format!("Deleted item {id}")),
            other @ (VaultError::InvalidFolderOrder
            | VaultError::DuplicateCredentialKey(_)
            | VaultError::DuplicateItemKey(_)
            | VaultError::InvalidSectionOrder(_)
            | VaultError::InvalidCredentialOrder(_)) => FfiError::InvalidInput(other.to_string()),
            // Sync, pairing, recovery kit, and re-sign requests refused by the
            // state of the vault, the synced folder, or the kit. Nothing was
            // written.
            other @ (VaultError::SyncAlreadyEnabled
            | VaultError::SyncDisableInProgress
            | VaultError::SyncNotEnabled
            | VaultError::SyncFolderHasVault
            | VaultError::SyncFolderLacksVault
            | VaultError::SyncRootNotSet(_)
            | VaultError::SyncMetaFileError(_)
            | VaultError::SyncOverrideNotOffered
            | VaultError::PairingNoVaults
            | VaultError::PairingVaultNotOffered(_)
            | VaultError::RecoveryKitMalformed(_)
            | VaultError::RecoveryKitNotAdded(_)
            | VaultError::VaultIdExists(_)
            | VaultError::ResignNotOffered) => FfiError::InvalidInput(other.to_string()),
            other => FfiError::Internal(other.to_string()),
        }
    }
}

impl From<KeychainError> for FfiError {
    fn from(e: KeychainError) -> Self {
        match e {
            KeychainError::UserCancelled => FfiError::AuthCancelled,
            KeychainError::AuthenticationExpired => FfiError::AuthExpired,
            other => FfiError::Internal(other.to_string()),
        }
    }
}

impl From<anyhow::Error> for FfiError {
    fn from(e: anyhow::Error) -> Self {
        FfiError::Internal(e.to_string())
    }
}

impl From<axo_pass_core::gpg::GpgError> for FfiError {
    fn from(e: axo_pass_core::gpg::GpgError) -> Self {
        FfiError::Internal(e.to_string())
    }
}

impl From<AgeError> for FfiError {
    fn from(e: AgeError) -> Self {
        match e {
            AgeError::KeyAlreadyExists(_) => FfiError::InvalidInput(e.to_string()),
            AgeError::RecipientNotFound(_) => FfiError::NotFound(e.to_string()),
            other => FfiError::Internal(other.to_string()),
        }
    }
}

impl From<agent_client::SshAgentClientError> for FfiError {
    fn from(e: agent_client::SshAgentClientError) -> Self {
        FfiError::Internal(e.to_string())
    }
}
