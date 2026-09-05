use std::sync::{Arc, Mutex};

use axo_pass_core::core::app_broker;
use axo_pass_core::core::auth::{
    AuthContext, AuthMethod, ForeignContext, adopt_shared_context, external_auth_lock,
    invalidate_auth, run_on_auth_thread,
};
use axo_pass_core::gpg::agent_conf::{self, State as CoreAgentConfState};
use axo_pass_core::secrets::keychain::errors::KeychainError;
use axo_pass_core::secrets::keychain::generic_password::{
    PasswordEntry, PasswordEntryType as CorePasswordEntryType,
};
use axo_pass_core::secrets::keychain::managed_key::ManagedSshKey;
use axo_pass_core::secrets::vaults::{Error as VaultError, VaultsManager};
use axo_pass_core::shell_integration;
use axo_pass_core::ssh::agent_client::{self, AgentStatus as CoreAgentStatus, default_socket_path};
use axo_pass_core::ssh::agent_conf::{self as ssh_agent_conf, State as CoreSshAgentConfState};
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

/// Whether gpg-agent's `pinentry-program` points at this app's helper.
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum GpgPinentryState {
    Configured,
    NotConfigured,
    OtherProgram,
}

impl From<CoreAgentConfState> for GpgPinentryState {
    fn from(s: CoreAgentConfState) -> Self {
        match s {
            CoreAgentConfState::Configured => GpgPinentryState::Configured,
            CoreAgentConfState::NotConfigured => GpgPinentryState::NotConfigured,
            CoreAgentConfState::OtherProgram => GpgPinentryState::OtherProgram,
        }
    }
}

#[derive(uniffi::Record)]
pub struct GpgAgentConfStatus {
    pub state: GpgPinentryState,
    /// Absolute path to the `gpg-agent.conf` that was read, whether or not it
    /// exists.
    pub conf_path: String,
    /// The `pinentry-program` line this app writes. `None` when the bundled
    /// helper cannot be located, meaning setup is unavailable.
    pub expected_line: Option<String>,
    /// The currently configured program, when it is not this app's helper.
    pub current_program: Option<String>,
}

impl From<agent_conf::Status> for GpgAgentConfStatus {
    fn from(s: agent_conf::Status) -> Self {
        GpgAgentConfStatus {
            state: s.state.into(),
            conf_path: s.conf_path.to_string_lossy().to_string(),
            expected_line: s.expected_line,
            current_program: s.current_program,
        }
    }
}

/// Whether ssh's `IdentityAgent` resolves to this app's agent socket.
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum SshIdentityAgentState {
    Configured,
    NotConfigured,
    OtherAgent,
}

impl From<CoreSshAgentConfState> for SshIdentityAgentState {
    fn from(s: CoreSshAgentConfState) -> Self {
        match s {
            CoreSshAgentConfState::Configured => SshIdentityAgentState::Configured,
            CoreSshAgentConfState::NotConfigured => SshIdentityAgentState::NotConfigured,
            CoreSshAgentConfState::OtherAgent => SshIdentityAgentState::OtherAgent,
        }
    }
}

#[derive(uniffi::Record)]
pub struct SshAgentConfStatus {
    pub state: SshIdentityAgentState,
    /// Absolute path to `~/.ssh/config`, whether or not it exists.
    pub config_path: String,
    /// The socket path this app writes.
    pub expected_agent: String,
    /// The currently effective `IdentityAgent`, when it is not this app's socket.
    pub current_agent: Option<String>,
}

impl From<ssh_agent_conf::Status> for SshAgentConfStatus {
    fn from(s: ssh_agent_conf::Status) -> Self {
        SshAgentConfStatus {
            state: s.state.into(),
            config_path: s.config_path.to_string_lossy().to_string(),
            expected_agent: s.expected_agent,
            current_agent: s.current_agent,
        }
    }
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
    /// Shuts the app broker down; `Some` while it is serving.
    app_broker: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl AxoPass {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        axo_pass_core::logging::init("app.log");
        Arc::new(Self {
            manager: Arc::new(Mutex::new(VaultsManager::new())),
            embedded_auth_lock: Mutex::new(None),
            app_broker: Mutex::new(None),
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

    /// Start the Axo Pass SSH agent. Mirrors `ap ssh-agent start`.
    pub async fn start_ssh_agent(&self) -> Result<(), FfiError> {
        tokio::task::spawn_blocking(agent_client::start_agent)
            .await
            .map_err(|e| FfiError::Internal(e.to_string()))?
            .map_err(FfiError::Internal)
    }

    /// Stop the Axo Pass SSH agent. Mirrors `ap ssh-agent stop`.
    pub async fn stop_ssh_agent(&self) -> Result<(), FfiError> {
        tokio::task::spawn_blocking(agent_client::stop_agent)
            .await
            .map_err(|e| FfiError::Internal(e.to_string()))?
            .map_err(FfiError::Internal)
    }

    /// Report whether ssh's `IdentityAgent` resolves to this app's agent
    /// socket.
    pub fn check_ssh_agent_conf(&self) -> SshAgentConfStatus {
        ssh_agent_conf::check_status().into()
    }

    /// Point `IdentityAgent` at this app's agent socket for all hosts,
    /// commenting out any line naming another agent. Takes effect immediately
    /// since ssh reads its config fresh on every invocation.
    pub async fn configure_ssh_agent_conf(&self) -> Result<SshAgentConfStatus, FfiError> {
        tokio::task::spawn_blocking(ssh_agent_conf::configure)
            .await
            .map_err(|e| FfiError::Internal(e.to_string()))?
            .map(SshAgentConfStatus::from)
            .map_err(FfiError::Internal)
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

    /// Report whether `gpg-agent.conf` points `pinentry-program` at this app's
    /// helper.
    pub fn check_gpg_agent_conf(&self) -> GpgAgentConfStatus {
        agent_conf::check_status().into()
    }

    /// Point `pinentry-program` at this app's helper, commenting out any line
    /// naming another program. gpg-agent keeps using the old program until it
    /// is reloaded, which [`Self::gpg_test_integration`] does.
    pub async fn configure_gpg_agent_conf(&self) -> Result<GpgAgentConfStatus, FfiError> {
        tokio::task::spawn_blocking(agent_conf::configure)
            .await
            .map_err(|e| FfiError::Internal(e.to_string()))?
            .map(GpgAgentConfStatus::from)
            .map_err(FfiError::Internal)
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
    // App broker
    // -----------------------------------------------------------------------

    /// Serve the CLI's requests: SSH signatures for the agent, and GPG
    /// passphrases for `ap pinentry`. Each prompts through its delegate, so the
    /// app draws the prompt instead of a headless process raising the system
    /// dialog. Returns once the socket is bound; serving continues in the
    /// background until [`Self::stop_app_broker`] or app exit.
    pub async fn start_app_broker(
        &self,
        sign_delegate: Arc<dyn SignPromptDelegate>,
        passphrase_delegate: Arc<dyn PassphrasePromptDelegate>,
    ) -> Result<(), FfiError> {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        {
            let mut slot = self.app_broker.lock().map_err(|_| FfiError::Poisoned)?;
            if slot.is_some() {
                return Err(FfiError::InvalidInput(
                    "App broker is already running".to_string(),
                ));
            }
            *slot = Some(shutdown_tx);
        }

        let authorizers = app_broker::Authorizers {
            sign: Arc::new(DelegatingAuthorizer {
                delegate: sign_delegate,
            }),
            passphrase: Arc::new(DelegatingPassphraseAuthorizer {
                delegate: passphrase_delegate,
            }),
        };
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            // `serve` binds before it accepts and only returns at shutdown, so
            // readiness is reported before awaiting it. Bind failures surface
            // in the log.
            let _ = ready_tx.send(());
            if let Err(e) = app_broker::serve(authorizers, shutdown_rx).await {
                log::error!("App broker stopped: {e}");
            }
        });
        let _ = ready_rx.await;
        Ok(())
    }

    /// Stop serving and remove the socket, so the agent falls back to the
    /// system dialog and pinentry reports an error rather than hanging.
    pub fn stop_app_broker(&self) -> Result<(), FfiError> {
        if let Some(shutdown) = self
            .app_broker
            .lock()
            .map_err(|_| FfiError::Poisoned)?
            .take()
        {
            let _ = shutdown.send(());
        }
        Ok(())
    }

    /// Whether this launch or reopen came from the broker starting the app to
    /// serve a request, rather than from a person opening it. Consumes the
    /// marker, so a second call reports false.
    pub fn take_broker_launch_request(&self) -> bool {
        app_broker::take_launch_request()
    }
}

// ---------------------------------------------------------------------------
// App broker delegates
// ---------------------------------------------------------------------------

/// How a prompt ended, as the app sees it.
#[derive(uniffi::Enum, Clone)]
pub enum PromptOutcome {
    /// The user approved, or a still-valid approval was reused.
    Succeeded,
    /// The user dismissed the prompt. Nothing was authorized.
    Cancelled,
    Failed {
        message: String,
    },
}

impl From<app_broker::PromptOutcome> for PromptOutcome {
    fn from(outcome: app_broker::PromptOutcome) -> Self {
        match outcome {
            app_broker::PromptOutcome::Succeeded => Self::Succeeded,
            app_broker::PromptOutcome::Cancelled => Self::Cancelled,
            app_broker::PromptOutcome::Failed(message) => Self::Failed { message },
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
    async fn end_authorization(&self, key_label: String, outcome: PromptOutcome);
}

struct DelegatingAuthorizer {
    delegate: Arc<dyn SignPromptDelegate>,
}

#[async_trait::async_trait]
impl app_broker::SignAuthorizer for DelegatingAuthorizer {
    async fn begin(&self, prompt: app_broker::SignPrompt) -> Result<ForeignContext, String> {
        let context_ptr = self
            .delegate
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
    }

    async fn end(&self, prompt: app_broker::SignPrompt, outcome: app_broker::PromptOutcome) {
        self.delegate
            .end_authorization(prompt.key_label, outcome.into())
            .await;
    }
}

/// Which agent a [`PassphrasePrompt`] is on behalf of. Mirrors
/// [`app_broker::PassphraseKind`].
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum PassphraseKind {
    Gpg,
    Ssh,
}

impl From<app_broker::PassphraseKind> for PassphraseKind {
    fn from(kind: app_broker::PassphraseKind) -> Self {
        match kind {
            app_broker::PassphraseKind::Gpg => Self::Gpg,
            app_broker::PassphraseKind::Ssh => Self::Ssh,
        }
    }
}

/// A passphrase prompt, as the app sees it. Mirrors
/// [`app_broker::PassphrasePrompt`]; for GPG the strings are gpg's own
/// wording, for SSH they are ssh/ssh-add's.
#[derive(uniffi::Record, Clone)]
pub struct PassphrasePrompt {
    pub kind: PassphraseKind,
    /// The key grip (GPG) or key fingerprint (SSH) naming the keychain entry.
    /// Absent when nothing identifies a key, in which case nothing can be
    /// saved or read back.
    pub key_id: Option<String>,
    pub description: Option<String>,
    pub prompt: Option<String>,
    /// gpg's report of the previous attempt. Set means the saved passphrase is
    /// wrong, so the app asks for a new one rather than unlocking. Always
    /// `None` for SSH.
    pub error_message: Option<String>,
    pub caller: Option<String>,
}

impl From<app_broker::PassphrasePrompt> for PassphrasePrompt {
    fn from(prompt: app_broker::PassphrasePrompt) -> Self {
        Self {
            kind: prompt.kind.into(),
            key_id: prompt.key_id,
            description: prompt.description,
            prompt: prompt.prompt,
            error_message: prompt.error_message,
            caller: prompt.caller,
        }
    }
}

/// A passphrase the user typed. The value crosses as bytes, never a `String`,
/// so the app can zero the buffer it came from.
#[derive(uniffi::Record)]
pub struct CollectedPassphrase {
    pub value: Vec<u8>,
    pub save_to_keychain: bool,
}

/// Implemented by the app. `begin_authorization` prepares an `LAContext` with
/// an `LAAuthenticationView` attached so the saved passphrase can be unlocked
/// inline; `collect_passphrase` asks the user to type one.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait PassphrasePromptDelegate: Send + Sync {
    /// Return the address of a live `LAContext` to read the keychain on. The
    /// app must keep its own reference to that context until
    /// `end_authorization`.
    async fn begin_authorization(&self, prompt: PassphrasePrompt) -> Result<u64, FfiError>;

    /// Ask the user for the passphrase. `None` means they dismissed the prompt.
    async fn collect_passphrase(
        &self,
        prompt: PassphrasePrompt,
    ) -> Result<Option<CollectedPassphrase>, FfiError>;

    /// The attempt finished. Called once for every `begin_authorization`.
    async fn end_authorization(&self, prompt: PassphrasePrompt, outcome: PromptOutcome);

    /// Put gpg's `CONFIRM` question to the user.
    async fn confirm(&self, description: Option<String>) -> bool;

    /// Show gpg's `MESSAGE` and wait for the user to dismiss it.
    async fn message(&self, description: Option<String>);
}

struct DelegatingPassphraseAuthorizer {
    delegate: Arc<dyn PassphrasePromptDelegate>,
}

#[async_trait::async_trait]
impl app_broker::PassphraseAuthorizer for DelegatingPassphraseAuthorizer {
    async fn begin(&self, prompt: app_broker::PassphrasePrompt) -> Result<ForeignContext, String> {
        let context_ptr = self
            .delegate
            .begin_authorization(prompt.into())
            .await
            .map_err(|e| e.to_string())?;
        if context_ptr == 0 {
            return Err("null LAContext pointer".to_string());
        }
        // SAFETY: the app holds a reference to the context until
        // `end_authorization`, which the broker calls after the read.
        unsafe { ForeignContext::from_ptr(context_ptr as *mut std::ffi::c_void) }
            .map_err(|e| e.to_string())
    }

    async fn collect(
        &self,
        prompt: app_broker::PassphrasePrompt,
    ) -> Result<Option<app_broker::CollectedPassphrase>, String> {
        let collected = self
            .delegate
            .collect_passphrase(prompt.into())
            .await
            .map_err(|e| e.to_string())?;
        collected
            .map(|collected| {
                let value = String::from_utf8(collected.value)
                    .map_err(|_| "Passphrase is not valid UTF-8".to_string())?;
                Ok(app_broker::CollectedPassphrase {
                    value: SecretString::from(value),
                    save_to_keychain: collected.save_to_keychain,
                })
            })
            .transpose()
    }

    async fn end(&self, prompt: app_broker::PassphrasePrompt, outcome: app_broker::PromptOutcome) {
        self.delegate
            .end_authorization(prompt.into(), outcome.into())
            .await;
    }

    async fn confirm(&self, description: Option<String>) -> bool {
        self.delegate.confirm(description).await
    }

    async fn message(&self, description: Option<String>) {
        self.delegate.message(description).await
    }
}
