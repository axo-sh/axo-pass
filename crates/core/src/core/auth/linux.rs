//! Linux stub of the authentication API in `auth.rs`.
//!
//! The names and signatures match the macOS module, except that the work
//! closures take an [`AuthSession`] where macOS passes an `LAContext`. Running
//! work fails with [`KeychainError::Unsupported`]. The unlocked session handle
//! of the TPM key store replaces these types.

use ssh_key::Signature;

use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::managed_key::KeyPolicy;

/// A session handed to authenticated work. It carries no state yet.
#[derive(Debug)]
pub struct AuthSession;

/// A session the caller owns, handed to the broker so the app draws the
/// prompt. It carries no state yet.
#[derive(Debug, Clone)]
pub struct ForeignContext;

impl ForeignContext {
    /// Invalidate the context.
    pub fn invalidate(&self) {}

    /// A context that nothing has unlocked, for tests that pass a context
    /// through.
    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        ForeignContext
    }
}

#[derive(Debug, Clone)]
pub enum AuthContext {
    SharedThreadLocal,
    OneTime,
    Foreign(ForeignContext),
}

pub enum AuthMethod {
    /// Run the work with the session as it stands.
    None,
    Policy {
        reason: String,
    },
}

pub fn run_on_auth_thread<F, R>(
    _auth_context: AuthContext,
    _auth_method: AuthMethod,
    _work_fn: F,
) -> Result<R, KeychainError>
where
    F: FnOnce(AuthSession) -> R + Send + 'static,
    R: Send + 'static,
{
    Err(KeychainError::Unsupported)
}

/// Invalidate every cached session, requiring a new unlock.
pub fn invalidate_auth() {}

/// Reason string shown in the authentication prompt for an SSH signature.
pub fn signing_reason(managed_key_label: &str, caller: Option<&str>) -> String {
    match caller {
        Some(c) => format!("sign with SSH key {managed_key_label} for {c}"),
        None => format!("sign with SSH key {managed_key_label}"),
    }
}

pub fn sign_with_managed_key_on(
    _auth_context: AuthContext,
    _managed_key_label: &str,
    _policy: KeyPolicy,
    _data: &[u8],
    _caller: Option<&str>,
) -> Result<Signature, KeychainError> {
    Err(KeychainError::Unsupported)
}

pub fn sign_with_managed_key_preapproved(
    _managed_key_label: &str,
    _data: &[u8],
) -> Result<Signature, KeychainError> {
    Err(KeychainError::Unsupported)
}
