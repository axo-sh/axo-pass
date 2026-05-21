use std::sync::{Arc, Mutex};

use axo_pass_core::secrets::keychain::errors::KeychainError;
use axo_pass_core::secrets::vaults::Error as VaultError;
use axo_pass_core::secrets::vaults::VaultsManager;

uniffi::setup_scaffolding!();

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    /// Touch ID / password prompt was dismissed by the user.
    #[error("Authentication cancelled")]
    AuthCancelled,

    /// A previously-granted auth context expired before the operation completed.
    #[error("Authentication expired")]
    AuthExpired,

    /// The vault exists but is locked; call unlock() first.
    #[error("Vault locked")]
    VaultLocked,

    #[error("Not found: {0}")]
    NotFound(String),

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
            VaultError::VaultLocked => FfiError::VaultLocked,
            VaultError::VaultInvalidAuth(k) => FfiError::from(k),
            VaultError::KeyRetrievalFailed(k) => FfiError::from(k),
            VaultError::KeyCreationFailed(k) => FfiError::from(k),
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

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

#[derive(uniffi::Record)]
pub struct VaultInfo {
    pub key: String,
    pub name: Option<String>,
}

// ---------------------------------------------------------------------------
// AxoPass object
// ---------------------------------------------------------------------------

#[derive(uniffi::Object)]
pub struct AxoPass {
    // Arc so async methods can move a cheap clone into spawn_blocking.
    manager: Arc<Mutex<VaultsManager>>,
}

#[uniffi::export]
impl AxoPass {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            manager: Arc::new(Mutex::new(VaultsManager::new())),
        })
    }

    /// List all known vaults. Does not require authentication.
    pub fn list_vaults(&self) -> Result<Vec<VaultInfo>, FfiError> {
        let manager = self.manager.lock().map_err(|_| FfiError::Poisoned)?;
        let mut vaults: Vec<VaultInfo> = manager
            .iter_vaults()
            .map(|(key, vw)| VaultInfo {
                key: key.clone(),
                name: vw.vault_name().map(|s| s.to_string()),
            })
            .collect();
        vaults.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(vaults)
    }

    /// Unlock a vault. Triggers a Touch ID / password prompt.
    /// Call this before any operation that reads secrets.
    pub async fn unlock_vault(&self, vault_key: String) -> Result<(), FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            m.get_or_create_vault_mut(&vault_key)
                .map_err(FfiError::from)?
                .unlock()
                .map_err(FfiError::from)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }
}
