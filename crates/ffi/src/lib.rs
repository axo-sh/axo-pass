use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use axo_pass_core::core::auth::{
    AuthContext, AuthMethod, ForeignContext, adopt_shared_context, external_auth_lock,
    invalidate_auth, run_on_auth_thread,
};
use axo_pass_core::core::sign_broker;
use axo_pass_core::secrets::keychain::errors::KeychainError;
use axo_pass_core::secrets::keychain::generic_password::{
    PasswordEntry, PasswordEntryType as CorePasswordEntryType,
};
use axo_pass_core::secrets::keychain::managed_key::ManagedSshKey;
use axo_pass_core::secrets::vaults::{Error as VaultError, VaultsManager};
use axo_pass_core::shell_integration;
use axo_pass_core::ssh::agent_client::{self, AgentStatus as CoreAgentStatus, default_socket_path};
use axo_pass_core::ssh::key_overview::{
    SshKeyAgentKind as CoreSshKeyAgent, SshKeyLocation as CoreSshKeyLocation, SshKeyOverview,
};
use axo_pass_core::ssh::ssh_keys::SshKeyType as CoreSshKeyType;
use secrecy::{ExposeSecret, SecretString};

uniffi::setup_scaffolding!();

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

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
            VaultError::InvalidEmptyCredentialValue => {
                FfiError::InvalidInput("Credential secret cannot be empty".to_string())
            },
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

impl From<agent_client::SshAgentClientError> for FfiError {
    fn from(e: agent_client::SshAgentClientError) -> Self {
        FfiError::Internal(e.to_string())
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

#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum SshKeyLocation {
    Vault,
    Transient,
    SshDir,
}

#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SshKeyAgent {
    SystemAgent,
    AxoPassAgent,
}

#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum SshKeyType {
    Rsa,
    Ed25519,
    Ecdsa,
    Dsa,
    Unknown,
}

impl From<CoreSshKeyType> for SshKeyType {
    fn from(t: CoreSshKeyType) -> Self {
        match t {
            CoreSshKeyType::Rsa => SshKeyType::Rsa,
            CoreSshKeyType::Ed25519 => SshKeyType::Ed25519,
            CoreSshKeyType::Ecdsa => SshKeyType::Ecdsa,
            CoreSshKeyType::Dsa => SshKeyType::Dsa,
            CoreSshKeyType::Unknown => SshKeyType::Unknown,
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct SshKeyEntry {
    pub name: String,
    pub location: SshKeyLocation,
    pub path: Option<String>,
    pub public_key: Option<String>,
    pub comment: Option<String>,
    pub key_type: SshKeyType,
    pub fingerprint_sha256: String,
    pub fingerprint_md5: String,
    pub has_saved_password: bool,
    pub is_managed: bool,
    pub agents: Vec<SshKeyAgent>,
}

impl From<CoreSshKeyLocation> for SshKeyLocation {
    fn from(l: CoreSshKeyLocation) -> Self {
        match l {
            CoreSshKeyLocation::Vault => SshKeyLocation::Vault,
            CoreSshKeyLocation::Transient => SshKeyLocation::Transient,
            CoreSshKeyLocation::SshDir => SshKeyLocation::SshDir,
        }
    }
}

impl From<CoreSshKeyAgent> for SshKeyAgent {
    fn from(a: CoreSshKeyAgent) -> Self {
        match a {
            CoreSshKeyAgent::SystemAgent => SshKeyAgent::SystemAgent,
            CoreSshKeyAgent::AxoPassAgent => SshKeyAgent::AxoPassAgent,
        }
    }
}

impl From<SshKeyOverview> for SshKeyEntry {
    fn from(overview: SshKeyOverview) -> Self {
        SshKeyEntry {
            name: overview.name,
            location: overview.location.into(),
            path: overview.path,
            public_key: overview.public_key,
            comment: overview.comment,
            key_type: overview.key_type.into(),
            fingerprint_sha256: overview.fingerprint_sha256,
            fingerprint_md5: overview.fingerprint_md5,
            has_saved_password: overview.has_saved_password,
            is_managed: overview.is_managed,
            agents: overview.agents.into_iter().map(SshKeyAgent::from).collect(),
        }
    }
}

#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum SshAgentStatus {
    Running,
    NotRunning,
    StaleSocket,
}

impl From<CoreAgentStatus> for SshAgentStatus {
    fn from(status: CoreAgentStatus) -> Self {
        match status {
            CoreAgentStatus::Running => SshAgentStatus::Running,
            CoreAgentStatus::NotRunning => SshAgentStatus::NotRunning,
            CoreAgentStatus::StaleSocket => SshAgentStatus::StaleSocket,
        }
    }
}

#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum SshAgentType {
    Axo,
    System,
}

#[derive(uniffi::Record)]
pub struct SshAgentStatusResponse {
    pub status: SshAgentStatus,
    pub socket_path: Option<String>,
}

#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum PasswordEntryType {
    GpgKey,
    SshKey,
    AgeKey,
    Other,
}

impl From<CorePasswordEntryType> for PasswordEntryType {
    fn from(t: CorePasswordEntryType) -> Self {
        match t {
            CorePasswordEntryType::GPGKey => PasswordEntryType::GpgKey,
            CorePasswordEntryType::SSHKey => PasswordEntryType::SshKey,
            CorePasswordEntryType::AgeKey => PasswordEntryType::AgeKey,
            CorePasswordEntryType::Other => PasswordEntryType::Other,
        }
    }
}

impl From<PasswordEntryType> for CorePasswordEntryType {
    fn from(t: PasswordEntryType) -> Self {
        match t {
            PasswordEntryType::GpgKey => CorePasswordEntryType::GPGKey,
            PasswordEntryType::SshKey => CorePasswordEntryType::SSHKey,
            PasswordEntryType::AgeKey => CorePasswordEntryType::AgeKey,
            PasswordEntryType::Other => CorePasswordEntryType::Other,
        }
    }
}

#[derive(uniffi::Record)]
pub struct ShellIntegrationStatus {
    /// Whether the `ap` shell integration block is present in `.zshrc`.
    pub configured: bool,
    /// Absolute path to the `.zshrc` file that was checked / written.
    pub zshrc_path: String,
}

#[derive(uniffi::Record)]
pub struct PasswordEntryInfo {
    pub password_type: PasswordEntryType,
    pub key_id: String,
}

impl From<PasswordEntry> for PasswordEntryInfo {
    fn from(entry: PasswordEntry) -> Self {
        PasswordEntryInfo {
            password_type: entry.password_type.into(),
            key_id: entry.key_id,
        }
    }
}

// ---------------------------------------------------------------------------
// AxoPass object
// ---------------------------------------------------------------------------

#[derive(uniffi::Object)]
pub struct AxoPass {
    manager: Arc<Mutex<VaultsManager>>,
    /// Held between `begin_embedded_auth` and `end_embedded_auth` so a
    /// UI-driven prompt still serializes against other processes.
    embedded_auth_lock: Mutex<Option<std::fs::File>>,
    /// Shuts the signing broker down; `Some` while it is serving.
    sign_broker: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl AxoPass {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        axo_pass_core::logging::init("app.log");
        Arc::new(Self {
            manager: Arc::new(Mutex::new(VaultsManager::new())),
            embedded_auth_lock: Mutex::new(None),
            sign_broker: Mutex::new(None),
        })
    }

    /// Take the cross-process auth lock ahead of a UI-driven prompt (see
    /// `adopt_auth_context`). Blocks until no other process is prompting. Pair
    /// every call with `end_embedded_auth`.
    pub async fn begin_embedded_auth(&self) -> Result<(), FfiError> {
        let file = tokio::task::spawn_blocking(external_auth_lock)
            .await
            .map_err(|e| FfiError::Internal(e.to_string()))?;
        *self
            .embedded_auth_lock
            .lock()
            .map_err(|_| FfiError::Poisoned)? = Some(file);
        Ok(())
    }

    /// Release the lock taken by `begin_embedded_auth`.
    pub fn end_embedded_auth(&self) -> Result<(), FfiError> {
        self.embedded_auth_lock
            .lock()
            .map_err(|_| FfiError::Poisoned)?
            .take();
        Ok(())
    }

    /// Adopt an `LAContext` the UI created and authenticated, making it the
    /// shared context for subsequent vault operations.
    ///
    /// The UI owns the context so it can attach an `LAAuthenticationView` and
    /// draw the biometric prompt inline. `context_ptr` is the address of a live
    /// `LAContext`; the caller keeps its own reference across the call.
    pub fn adopt_auth_context(&self, context_ptr: u64) -> Result<(), FfiError> {
        if context_ptr == 0 {
            return Err(FfiError::InvalidInput("null LAContext pointer".into()));
        }
        unsafe { adopt_shared_context(context_ptr as *mut std::ffi::c_void) }
            .map_err(FfiError::from)
    }

    /// Authenticate globally via Touch ID / password, showing the system
    /// dialog. One prompt covers all subsequent vault operations for the
    /// lifetime of the LAContext. Mirrors `unlock_axo` in the Tauri app.
    ///
    /// The macOS app unlocks through `adopt_auth_context` instead so it can
    /// draw the prompt inline. This remains for callers with no UI, such as the
    /// `ap` CLI.
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

    /// Drop every decrypted vault from memory and invalidate the shared
    /// LAContext. Reading items again costs a decryption and a fresh prompt.
    /// Mirrors `lock_axo` in the Tauri app.
    pub fn lock(&self) -> Result<(), FfiError> {
        self.manager
            .lock()
            .map_err(|_| FfiError::Poisoned)?
            .lock_all();
        invalidate_auth();
        Ok(())
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
            match vault
                .get_secret(&item_key, &cred_key)
                .map_err(FfiError::from)?
            {
                Some(secret) => Ok(secret.expose_secret().as_bytes().to_vec()),
                None => Err(FfiError::NotFound(format!(
                    "{vault_key}/{item_key}/{cred_key}"
                ))),
            }
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Retrieve a credential secret's decrypted title as raw bytes (same
    /// zeroing convention as `get_credential_secret`). `None` if not found.
    pub async fn get_decrypted_credential(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
    ) -> Result<Option<Vec<u8>>, FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vault = m
                .get_vault(&vault_key)
                .ok_or_else(|| FfiError::NotFound(vault_key.clone()))?;
            match vault
                .get_secret(&item_key, &cred_key)
                .map_err(FfiError::from)?
            {
                Some(secret) => Ok(Some(secret.expose_secret().as_bytes().to_vec())),
                None => Ok(None),
            }
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    // -----------------------------------------------------------------------
    // Vault CRUD
    // -----------------------------------------------------------------------

    /// Create a new vault. Mirrors `add_vault` in the Tauri app.
    pub async fn add_vault(
        &self,
        name: Option<String>,
        vault_key: String,
    ) -> Result<VaultInfo, FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vw = m.add_vault(name, &vault_key).map_err(FfiError::from)?;
            Ok(VaultInfo {
                key: vw.key.clone(),
                name: vw.vault_name().map(|s| s.to_string()),
            })
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Rename a vault and/or change its key. Does not require the vault to be
    /// unlocked. Mirrors `update_vault` in the Tauri app.
    pub async fn update_vault(
        &self,
        vault_key: String,
        new_vault_key: Option<String>,
        new_name: Option<String>,
    ) -> Result<(), FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vw = m
                .get_or_create_vault_mut(&vault_key)
                .map_err(FfiError::from)?;

            if new_name.as_deref() != vw.vault_name()
                && let Some(new_name) = new_name
            {
                vw.set_vault_name(new_name).map_err(FfiError::from)?;
                vw.save().map_err(FfiError::from)?;
            }

            if new_vault_key.as_deref() != Some(vault_key.as_str())
                && let Some(new_vault_key) = new_vault_key
            {
                m.update_vault_key(&vault_key, &new_vault_key)
                    .map_err(FfiError::from)?;
            }

            Ok(())
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Delete a vault (moved to Trash, not permanently deleted). Mirrors
    /// `delete_vault` in the Tauri app.
    pub async fn delete_vault(&self, vault_key: String) -> Result<(), FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            m.delete_vault(&vault_key).map_err(FfiError::from)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Create or rename an item within a vault.
    pub async fn add_or_update_item(
        &self,
        vault_key: String,
        item_key: String,
        item_title: String,
    ) -> Result<(), FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            m.with_unlocked_vault(&vault_key, |vw| {
                vw.add_item(&item_key, &item_title)
                    .map_err(FfiError::from)?;
                Ok(())
            })
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Delete an item (and all its credentials) from a vault.
    pub async fn delete_item(&self, vault_key: String, item_key: String) -> Result<(), FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            m.with_unlocked_vault(&vault_key, |vw| {
                vw.delete_item(&item_key).map_err(FfiError::from)
            })
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Create or update a credential's title/value within an item.
    pub async fn add_or_update_credential(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
        title: String,
        value: String,
    ) -> Result<(), FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            m.with_unlocked_vault(&vault_key, |vw| {
                vw.add_secret(&item_key, &cred_key, &title, SecretString::from(value))
                    .map_err(FfiError::from)
            })
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Delete a single credential from an item.
    pub async fn delete_credential(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
    ) -> Result<(), FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            m.with_unlocked_vault(&vault_key, |vw| {
                vw.delete_item_credential(&item_key, &cred_key)
                    .map_err(FfiError::from)
            })
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    // -----------------------------------------------------------------------
    // SSH pane
    // -----------------------------------------------------------------------

    /// Create a new Secure Enclave-backed managed SSH key.
    pub async fn add_managed_ssh_key(&self) -> Result<SshKeyEntry, FfiError> {
        let managed_key = ManagedSshKey::create().await.map_err(FfiError::from)?;
        let overview: SshKeyOverview = managed_key.into();
        Ok(overview.into())
    }

    /// Delete a managed SSH key by its sha256 fingerprint.
    pub async fn delete_managed_ssh_key(&self, fingerprint_sha256: String) -> Result<(), FfiError> {
        tokio::task::spawn_blocking(move || {
            let keys = ManagedSshKey::list().map_err(FfiError::from)?;
            let key = keys
                .into_iter()
                .find(|k| k.fingerprint_sha256() == fingerprint_sha256)
                .ok_or_else(|| FfiError::NotFound(fingerprint_sha256.clone()))?;
            key.delete().map_err(FfiError::from)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// List all known SSH keys: on-disk (`~/.ssh`), Secure Enclave-managed,
    /// and transient identities currently loaded into the system or Axo Pass
    /// SSH agents.
    pub async fn list_ssh_keys(&self) -> Result<Vec<SshKeyEntry>, FfiError> {
        let overviews = axo_pass_core::ssh::key_overview::list_all_ssh_keys()
            .await
            .map_err(FfiError::from)?;
        Ok(overviews.into_iter().map(SshKeyEntry::from).collect())
    }

    /// Check whether the Axo Pass or system SSH agent is reachable over its
    /// Unix socket. Mirrors `get_ssh_agent_status` in the Tauri app.
    pub fn get_ssh_agent_status(&self, agent_type: SshAgentType) -> SshAgentStatusResponse {
        let (status, socket_path) = match agent_type {
            SshAgentType::Axo => {
                let path = default_socket_path();
                let status = agent_client::get_agent_status_for_socket(&path);
                (status, Some(path.to_string_lossy().to_string()))
            },
            SshAgentType::System => {
                let path = agent_client::get_system_socket_path();
                let status = match &path {
                    Some(p) => agent_client::get_agent_status_for_socket(p),
                    None => CoreAgentStatus::NotRunning,
                };
                (status, path)
            },
        };
        SshAgentStatusResponse {
            status: status.into(),
            socket_path,
        }
    }

    /// Save a password for an SSH key to the Keychain, keyed by fingerprint.
    /// Errors with `InvalidInput` if a password is already saved.
    pub async fn save_ssh_key_password(
        &self,
        fingerprint: String,
        password: String,
    ) -> Result<(), FfiError> {
        tokio::task::spawn_blocking(move || {
            let entry = PasswordEntry::ssh(&fingerprint);
            if entry.exists().map_err(FfiError::from)? {
                return Err(FfiError::InvalidInput(
                    "Password already exists for this key".to_string(),
                ));
            }
            entry
                .save_password(SecretString::from(password))
                .map_err(FfiError::from)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    // -----------------------------------------------------------------------
    // GPG / Keys pane
    // -----------------------------------------------------------------------

    /// Reload gpg-agent and run a test signing operation, to confirm GPG
    /// signing works end-to-end. Mirrors `gpg_test_integration` in the Tauri
    /// app.
    pub async fn gpg_test_integration(&self) -> Result<(), FfiError> {
        tokio::task::spawn_blocking(axo_pass_core::gpg::test_integration)
            .await
            .map_err(|e| FfiError::Internal(e.to_string()))?
            .map_err(FfiError::from)
    }

    /// List generic keychain-managed passwords (GPG/SSH/age keys with a saved
    /// password). Mirrors `list_passwords` in the Tauri app.
    pub async fn list_passwords(&self) -> Result<Vec<PasswordEntryInfo>, FfiError> {
        tokio::task::spawn_blocking(PasswordEntry::list)
            .await
            .map_err(|e| FfiError::Internal(e.to_string()))?
            .map_err(FfiError::from)
            .map(|entries| entries.into_iter().map(PasswordEntryInfo::from).collect())
    }

    /// Delete a generic keychain-managed password entry.
    pub async fn delete_password(
        &self,
        password_type: PasswordEntryType,
        key_id: String,
    ) -> Result<(), FfiError> {
        tokio::task::spawn_blocking(move || {
            let entry = PasswordEntry {
                password_type: password_type.into(),
                key_id,
            };
            entry.delete().map_err(FfiError::from)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    // -----------------------------------------------------------------------
    // Shell integration (Setup pane)
    // -----------------------------------------------------------------------

    /// Report whether the `ap` shell integration block is present in `.zshrc`.
    /// Mirrors `get_shell_integration_status` in the Tauri app.
    pub fn check_shell_integration(&self) -> ShellIntegrationStatus {
        let (configured, path) = shell_integration::check_status();
        ShellIntegrationStatus {
            configured,
            zshrc_path: path.to_string_lossy().to_string(),
        }
    }

    /// Append the `ap` shell integration block to `.zshrc` if not already
    /// present. Mirrors `configure_shell_integration` in the Tauri app.
    pub async fn write_shell_integration(&self) -> Result<ShellIntegrationStatus, FfiError> {
        tokio::task::spawn_blocking(|| {
            let path = shell_integration::write_integration().map_err(FfiError::Internal)?;
            Ok(ShellIntegrationStatus {
                configured: true,
                zshrc_path: path.to_string_lossy().to_string(),
            })
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    // -----------------------------------------------------------------------
    // Signing broker
    // -----------------------------------------------------------------------

    /// Serve SSH signing requests from the agent, prompting through `delegate`
    /// so the app draws the prompt instead of the agent raising the system
    /// dialog. Returns once the socket is bound; serving continues in the
    /// background until [`Self::stop_sign_broker`] or app exit.
    pub async fn start_sign_broker(
        &self,
        delegate: Arc<dyn SignPromptDelegate>,
    ) -> Result<(), FfiError> {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        {
            let mut slot = self.sign_broker.lock().map_err(|_| FfiError::Poisoned)?;
            if slot.is_some() {
                return Err(FfiError::InvalidInput(
                    "Signing broker is already running".to_string(),
                ));
            }
            *slot = Some(shutdown_tx);
        }

        let authorizer = Arc::new(DelegatingAuthorizer { delegate });
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            // `serve` binds before it accepts and only returns at shutdown, so
            // readiness is reported before awaiting it. Bind failures surface
            // in the log.
            let _ = ready_tx.send(());
            if let Err(e) = sign_broker::serve(authorizer, shutdown_rx).await {
                log::error!("Signing broker stopped: {e}");
            }
        });
        let _ = ready_rx.await;
        Ok(())
    }

    /// Stop serving signing requests and remove the socket, so the agent falls
    /// back to the system dialog.
    pub fn stop_sign_broker(&self) -> Result<(), FfiError> {
        if let Some(shutdown) = self
            .sign_broker
            .lock()
            .map_err(|_| FfiError::Poisoned)?
            .take()
        {
            let _ = shutdown.send(());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Signing broker delegate
// ---------------------------------------------------------------------------

/// How a signing attempt ended, as the app sees it.
#[derive(uniffi::Enum, Clone)]
pub enum SignOutcome {
    /// The user approved, or a still-valid approval was reused.
    Succeeded,
    /// The user dismissed the prompt. Nothing was authorized.
    Cancelled,
    Failed {
        message: String,
    },
}

impl From<sign_broker::SignOutcome> for SignOutcome {
    fn from(outcome: sign_broker::SignOutcome) -> Self {
        match outcome {
            sign_broker::SignOutcome::Succeeded => Self::Succeeded,
            sign_broker::SignOutcome::Cancelled => Self::Cancelled,
            sign_broker::SignOutcome::Failed(message) => Self::Failed { message },
        }
    }
}

/// Implemented by the app. `begin_authorization` prepares an `LAContext` with
/// an `LAAuthenticationView` attached and puts the prompt on screen;
/// `end_authorization` takes it down again.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait SignPromptDelegate: Send + Sync {
    /// Return the address of a live `LAContext` to sign on. The app must keep
    /// its own reference to that context until `end_authorization`.
    async fn begin_authorization(
        &self,
        key_label: String,
        caller: Option<String>,
    ) -> Result<u64, FfiError>;

    /// The attempt finished. Called once for every `begin_authorization`.
    async fn end_authorization(&self, key_label: String, outcome: SignOutcome);
}

struct DelegatingAuthorizer {
    delegate: Arc<dyn SignPromptDelegate>,
}

impl sign_broker::SignAuthorizer for DelegatingAuthorizer {
    fn begin(
        &self,
        prompt: sign_broker::SignPrompt,
    ) -> Pin<Box<dyn Future<Output = Result<ForeignContext, String>> + Send>> {
        let delegate = self.delegate.clone();
        Box::pin(async move {
            let context_ptr = delegate
                .begin_authorization(prompt.key_label, prompt.caller)
                .await
                .map_err(|e| e.to_string())?;
            if context_ptr == 0 {
                return Err("null LAContext pointer".to_string());
            }
            // SAFETY: the app holds a reference to the context until
            // `end_authorization`, which the broker calls after signing.
            unsafe { ForeignContext::from_ptr(context_ptr as *mut std::ffi::c_void) }
                .map_err(|e| e.to_string())
        })
    }

    fn end(
        &self,
        prompt: sign_broker::SignPrompt,
        outcome: sign_broker::SignOutcome,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let delegate = self.delegate.clone();
        Box::pin(async move {
            delegate
                .end_authorization(prompt.key_label, outcome.into())
                .await;
        })
    }
}
