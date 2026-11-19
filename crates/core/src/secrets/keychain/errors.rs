#[cfg(target_os = "macos")]
use std::ptr::{self, NonNull};

#[cfg(target_os = "macos")]
use objc2_core_foundation::{CFError, CFRetained};
use thiserror::Error;

/// Receives the `CFError` a Security call reports through its out-parameter,
/// and releases it on drop.
#[cfg(target_os = "macos")]
pub struct CFErrorOut(*mut CFError);

#[cfg(target_os = "macos")]
impl Default for CFErrorOut {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "macos")]
impl CFErrorOut {
    pub fn new() -> Self {
        Self(ptr::null_mut())
    }

    /// The out-parameter to pass to the Security call.
    pub fn out(&mut self) -> &mut *mut CFError {
        &mut self.0
    }

    /// The error the call reported, if any.
    pub fn get(&self) -> Option<&CFError> {
        unsafe { self.0.as_ref() }
    }
}

#[cfg(target_os = "macos")]
impl Drop for CFErrorOut {
    fn drop(&mut self) {
        if let Some(error) = NonNull::new(self.0) {
            drop(unsafe { CFRetained::from_raw(error) });
        }
    }
}

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

    /// The operation needs the macOS keychain. Linux builds have no
    /// implementation of it yet.
    #[error("Not supported on this platform")]
    Unsupported,
}
