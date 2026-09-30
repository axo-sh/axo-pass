use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeychainError {
    #[error("User cancelled the keychain access")]
    UserCancelled,

    #[error("Authentication expired")]
    AuthenticationExpired,

    /// `LAError::SystemCancel`. The system cancels a prompt when another
    /// process starts one, and also when the screen locks or the prompt's
    /// application loses focus.
    #[error(
        "Authentication was canceled by the system (another prompt, the screen locking, or a focus change)"
    )]
    SystemCancelled,

    #[error("Item exists but access is not allowed without user authentication")]
    ItemNotAccessible,

    #[error("Failed to add to keychain: {0}")]
    AddFailed(String),

    #[error("Keychain error: {0}")]
    Generic(#[from] anyhow::Error),

    #[error("Key creation failed with unexpected error")]
    KeyCreationFailed,

    #[error("Public key creation failed: {0}")]
    PublicKeyCreationFailed(anyhow::Error),

    #[error("Public key unavailable: {0}")]
    PublicKeyUnavailable(String),

    #[error("Signing failed: {0}")]
    SigningFailed(String),
}
