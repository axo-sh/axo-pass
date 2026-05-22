use std::sync::{Arc, Mutex};

use secrecy::ExposeSecret;

use axo_pass_core::core::auth::{AuthContext, AuthMethod, invalidate_auth, run_on_auth_thread};
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

#[derive(uniffi::Record)]
pub struct CredentialInfo {
    pub key: String,
    pub title: String,
}

#[derive(uniffi::Record)]
pub struct ItemInfo {
    pub key: String,
    pub title: String,
    pub credentials: Vec<CredentialInfo>,
}

// ---------------------------------------------------------------------------
// AxoPass object
// ---------------------------------------------------------------------------

#[derive(uniffi::Object)]
pub struct AxoPass {
    manager: Arc<Mutex<VaultsManager>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl AxoPass {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            manager: Arc::new(Mutex::new(VaultsManager::new())),
        })
    }

    /// Authenticate globally via Touch ID / password. One prompt covers all
    /// subsequent vault operations for the lifetime of the LAContext.
    /// Mirrors `unlock_axo` in the Tauri app.
    pub async fn unlock(&self) -> Result<(), FfiError> {
        tokio::task::spawn_blocking(|| {
            run_on_auth_thread(
                AuthContext::SharedThreadLocal,
                AuthMethod::Policy {
                    reason: "unlock Axo Pass".to_string(),
                },
                |_| {},
            )
            .map_err(FfiError::from)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Invalidate the shared LAContext, requiring re-authentication.
    /// Mirrors `lock_axo` in the Tauri app.
    pub fn lock(&self) {
        invalidate_auth();
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

    /// List items for a vault. Decrypts the vault from disk using the
    /// shared LAContext — no additional Touch ID prompt if `unlock` has
    /// already been called. Triggers auth if called before `unlock`.
    pub async fn list_items(&self, vault_key: String) -> Result<Vec<ItemInfo>, FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vault = m
                .get_or_create_vault_mut(&vault_key)
                .map_err(FfiError::from)?;

            // Decrypt from disk if not already in memory. Uses the shared
            // LAContext so no re-prompt after a successful unlock().
            if let Err(e) = vault.list_items() {
                if matches!(e, VaultError::VaultLocked) {
                    vault.unlock().map_err(FfiError::from)?;
                } else {
                    return Err(FfiError::from(e));
                }
            }

            let items = vault.list_items().map_err(FfiError::from)?;
            let mut result: Vec<ItemInfo> = items
                .into_iter()
                .map(|item| {
                    let mut credentials: Vec<CredentialInfo> = item
                        .credentials
                        .values()
                        .map(|c| CredentialInfo {
                            key: c.key.clone(),
                            title: c.title.clone(),
                        })
                        .collect();
                    credentials.sort_by(|a, b| a.title.cmp(&b.title));
                    ItemInfo {
                        key: item.key.clone(),
                        title: item.title.clone(),
                        credentials,
                    }
                })
                .collect();
            result.sort_by(|a, b| a.title.cmp(&b.title));
            Ok(result)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Retrieve a credential secret as raw bytes.
    ///
    /// Swift callers should immediately wrap the returned `Data` in a
    /// `CryptoKit.SymmetricKey` and zero the `Data` buffer:
    ///
    ///   var raw = try await axoPass.getCredentialSecret(...)
    ///   let key = SymmetricKey(data: raw)
    ///   raw.resetBytes(in: raw.indices)
    pub async fn get_credential_secret(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
    ) -> Result<Vec<u8>, FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vault = m
                .get_vault(&vault_key)
                .ok_or_else(|| FfiError::NotFound(vault_key.clone()))?;
            match vault.get_secret(&item_key, &cred_key).map_err(FfiError::from)? {
                Some(secret) => Ok(secret.expose_secret().as_bytes().to_vec()),
                None => Err(FfiError::NotFound(format!("{vault_key}/{item_key}/{cred_key}"))),
            }
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }
}
