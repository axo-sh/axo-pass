use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeychainError {
    #[error("User cancelled the keychain access")]
    UserCancelled,

    #[error("Item exists but access is not allowed without user authentication")]
    ItemNotAccessible,

    #[error("Keychain error: {0}")]
    Generic(#[from] anyhow::Error),
}
