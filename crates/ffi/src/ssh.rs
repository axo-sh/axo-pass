use axo_pass_core::audit;
use axo_pass_core::core::app_broker;
use axo_pass_core::secrets::keychain::generic_password::PasswordEntry;
use axo_pass_core::secrets::keychain::managed_key::{KeyPolicy, ManagedSshKey};
use axo_pass_core::ssh::agent_client::{self, AgentStatus as CoreAgentStatus, default_socket_path};
use axo_pass_core::ssh::agent_conf::{self as ssh_agent_conf, State as CoreSshAgentConfState};
use axo_pass_core::ssh::key_overview::{
    SshKeyAgentKind as CoreSshKeyAgent, SshKeyLocation as CoreSshKeyLocation, SshKeyOverview,
};
use axo_pass_core::ssh::related_hosts::{self, RelatedHost};
use axo_pass_core::ssh::ssh_keys::SshKeyType as CoreSshKeyType;
use axo_pass_core::ssh::{app_grants, autoload};
use secrecy::SecretString;

use crate::*;

#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum SshKeyLocation {
    Vault,
    Transient,
    SshDir,
}

/// Mirrors [`KeyPolicy`].
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum SshKeyPolicy {
    Default,
    AlwaysRequireAuth,
}

impl From<KeyPolicy> for SshKeyPolicy {
    fn from(p: KeyPolicy) -> Self {
        match p {
            KeyPolicy::Default => SshKeyPolicy::Default,
            KeyPolicy::AlwaysRequireAuth => SshKeyPolicy::AlwaysRequireAuth,
        }
    }
}

/// Mirrors [`app_broker::SignPurpose`].
#[derive(uniffi::Enum, Clone, PartialEq, Eq)]
pub enum SshSignPurpose {
    Login {
        user: Option<String>,
        host: Option<String>,
    },
    Sshsig {
        namespace: String,
    },
}

impl From<app_broker::SignPurpose> for SshSignPurpose {
    fn from(p: app_broker::SignPurpose) -> Self {
        match p {
            app_broker::SignPurpose::Login { user, host } => SshSignPurpose::Login { user, host },
            app_broker::SignPurpose::Sshsig { namespace } => SshSignPurpose::Sshsig { namespace },
        }
    }
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
    /// Path to the `.pub` file, when the key has one on disk.
    pub public_key: Option<String>,
    /// The public key in OpenSSH format, available even when the `.pub` file
    /// is missing.
    pub public_key_openssh: Option<String>,
    pub comment: Option<String>,
    pub key_type: SshKeyType,
    pub fingerprint_sha256: String,
    pub fingerprint_md5: String,
    pub has_saved_password: bool,
    pub is_managed: bool,
    /// Set for managed keys only.
    pub policy: Option<SshKeyPolicy>,
    pub agents: Vec<SshKeyAgent>,
    /// The Axo agent advertises this `~/.ssh` key and loads it on first use.
    pub autoload: bool,
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
            public_key_openssh: overview.public_key_openssh,
            comment: overview.comment,
            key_type: overview.key_type.into(),
            fingerprint_sha256: overview.fingerprint_sha256,
            fingerprint_md5: overview.fingerprint_md5,
            has_saved_password: overview.has_saved_password,
            is_managed: overview.is_managed,
            policy: overview.policy.map(SshKeyPolicy::from),
            agents: overview.agents.into_iter().map(SshKeyAgent::from).collect(),
            autoload: overview.autoload,
        }
    }
}

/// An app that can hold lasting access to an SSH key. Mirrors
/// [`app_grants::GrantApp`].
#[derive(uniffi::Record, Clone)]
pub struct SshGrantApp {
    pub team_id: String,
    pub bundle_id: String,
    pub display_name: String,
}

impl From<app_grants::GrantApp> for SshGrantApp {
    fn from(app: app_grants::GrantApp) -> Self {
        SshGrantApp {
            team_id: app.team_id,
            bundle_id: app.bundle_id,
            display_name: app.display_name,
        }
    }
}

impl From<SshGrantApp> for app_grants::GrantApp {
    fn from(app: SshGrantApp) -> Self {
        app_grants::GrantApp {
            team_id: app.team_id,
            bundle_id: app.bundle_id,
            display_name: app.display_name,
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct SshAppGrant {
    pub app: SshGrantApp,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds. `None` for a grant with no expiration.
    pub expires_at: Option<i64>,
}

impl From<app_grants::AppGrant> for SshAppGrant {
    fn from(grant: app_grants::AppGrant) -> Self {
        SshAppGrant {
            app: grant.app.into(),
            created_at: grant.created_at.unix_timestamp(),
            expires_at: grant.expires_at.map(|t| t.unix_timestamp()),
        }
    }
}

/// A host an SSH key signed in to. Mirrors [`RelatedHost`].
#[derive(uniffi::Record, Clone)]
pub struct SshRelatedHost {
    /// `None` when the host key is not in `known_hosts` or only in a hashed
    /// entry.
    pub host: Option<String>,
    /// `SHA256:...` of the server's host key.
    pub hostkey_fingerprint: String,
    pub user: Option<String>,
    /// Unix seconds.
    pub last_used: i64,
    /// Unix seconds. The oldest signature counted in `use_count`.
    pub first_used: i64,
    pub use_count: u32,
}

impl From<RelatedHost> for SshRelatedHost {
    fn from(host: RelatedHost) -> Self {
        SshRelatedHost {
            host: host.host,
            hostkey_fingerprint: host.hostkey_fingerprint,
            user: host.user,
            last_used: host.last_used.unix_timestamp(),
            first_used: host.first_used.unix_timestamp(),
            use_count: host.use_count,
        }
    }
}

/// The canonical `SHA256:...` form of a fingerprint that may arrive without
/// the prefix.
fn canonical_ssh_fingerprint(fingerprint: &str) -> String {
    if fingerprint.starts_with("SHA256:") {
        fingerprint.to_string()
    } else {
        format!("SHA256:{fingerprint}")
    }
}

/// Record an `ssh.app_grant_add` or `ssh.app_grant_remove` event.
/// `expires_in_seconds` is the added grant's expiration, if it has one.
fn record_app_grant_event(
    action: audit::Action,
    fingerprint: &str,
    bundle_id: &str,
    expires_in_seconds: Option<u32>,
    peer: Option<RequestActor>,
    result: &Result<(), FfiError>,
) {
    let mut event = audit::AuditEvent::new(
        audit::process_source(),
        action,
        if result.is_ok() {
            audit::Outcome::Succeeded
        } else {
            audit::Outcome::Failed
        },
    )
    .subject(
        audit::Subject::new(audit::SubjectKind::SshKey, fingerprint.to_string())
            .fingerprint(fingerprint.to_string()),
    )
    .detail("grant", format!("app:{bundle_id}"))
    .maybe_actor(peer.map(audit::Actor::from));
    if let Some(seconds) = expires_in_seconds {
        event = event.detail("expires_in", seconds.to_string());
    }
    if let Err(e) = result {
        event = event.message(e.to_string());
    }
    audit::record(event);
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

/// How the running Axo Pass agent was started.
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum SshAgentLauncher {
    /// Run by the launchd service. launchd restarts it if it exits.
    Launchd,
    /// Started by `ap agent start`. Nothing restarts it.
    Detached,
}

impl From<agent_client::Launcher> for SshAgentLauncher {
    fn from(launcher: agent_client::Launcher) -> Self {
        match launcher {
            agent_client::Launcher::Launchd => SshAgentLauncher::Launchd,
            agent_client::Launcher::Detached => SshAgentLauncher::Detached,
        }
    }
}

#[derive(uniffi::Record)]
pub struct SshAgentInfo {
    pub version: String,
    pub launcher: SshAgentLauncher,
    /// Whether the agent's version matches the `ap` bundled with this app.
    pub is_current: bool,
}

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
    /// The currently effective `IdentityAgent`, when it is not this app's
    /// socket.
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

/// One age identity, for the Age pane.
#[uniffi::export(async_runtime = "tokio")]
impl AxoPass {
    /// Create a new Secure Enclave-backed managed SSH key. With
    /// `always_require_auth`, the Secure Enclave requires authentication for
    /// every use and the key cannot be granted to an app.
    pub async fn add_managed_ssh_key(
        &self,
        always_require_auth: bool,
    ) -> Result<SshKeyEntry, FfiError> {
        let policy = if always_require_auth {
            KeyPolicy::AlwaysRequireAuth
        } else {
            KeyPolicy::Default
        };
        let result = ManagedSshKey::create(policy).await.map_err(FfiError::from);

        let mut event = audit::AuditEvent::new(
            audit::process_source(),
            audit::Action::SshManagedKeyCreate,
            match &result {
                Ok(_) => audit::Outcome::Succeeded,
                Err(_) => audit::Outcome::Failed,
            },
        )
        .detail(
            "always_require_auth",
            if always_require_auth { "true" } else { "false" },
        );
        match &result {
            Ok(key) => {
                event = event.subject(
                    audit::Subject::new(
                        audit::SubjectKind::SshKey,
                        format!("SHA256:{}", key.fingerprint_sha256()),
                    )
                    .label(key.label())
                    .fingerprint(format!("SHA256:{}", key.fingerprint_sha256())),
                );
            },
            Err(e) => event = event.message(e.to_string()),
        }
        audit::record(event);

        let overview: SshKeyOverview = result?.into();
        Ok(overview.into())
    }

    /// Delete a managed SSH key by its sha256 fingerprint.
    pub async fn delete_managed_ssh_key(&self, fingerprint_sha256: String) -> Result<(), FfiError> {
        let result = tokio::task::spawn_blocking(move || {
            let keys = ManagedSshKey::list().map_err(FfiError::from)?;
            let key = keys
                .into_iter()
                .find(|k| k.fingerprint_sha256() == fingerprint_sha256)
                .ok_or_else(|| FfiError::NotFound(fingerprint_sha256.clone()))?;
            key.delete_capturing().map_err(FfiError::from)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?;

        let audit_result = result
            .as_ref()
            .map(|captured| captured.clone())
            .map_err(ToString::to_string);
        audit::record_managed_key_delete(None, &audit_result);

        result.map(|_| ())
    }

    /// The apps with lasting access to an SSH key.
    pub async fn list_ssh_app_grants(
        &self,
        fingerprint_sha256: String,
    ) -> Result<Vec<SshAppGrant>, FfiError> {
        let fingerprint = canonical_ssh_fingerprint(&fingerprint_sha256);
        tokio::task::spawn_blocking(move || app_grants::list_for(&fingerprint))
            .await
            .map_err(|e| FfiError::Internal(e.to_string()))?
            .map(|grants| grants.into_iter().map(Into::into).collect())
            .map_err(FfiError::from)
    }

    /// Give `app` lasting access to an SSH key. Fails for a managed key that
    /// always requires authentication. For a key the agent holds, the grant
    /// applies while the key is auto-loaded, and never to a key added with
    /// `ssh-add -c`. `peer` is the requester the grant was given from, for the
    /// audit event.
    pub async fn add_ssh_app_grant(
        &self,
        fingerprint_sha256: String,
        app: SshGrantApp,
        // Seconds until the grant expires, from 30 seconds to 30 days. `None`
        // for a grant with no expiration.
        expires_in_seconds: Option<u32>,
        peer: Option<RequestActor>,
    ) -> Result<(), FfiError> {
        let fingerprint = canonical_ssh_fingerprint(&fingerprint_sha256);
        let bundle_id = app.bundle_id.clone();
        let fp = fingerprint.clone();
        let result = tokio::task::spawn_blocking(move || {
            let expires_in = expires_in_seconds
                .map(app_grants::expiration_from_seconds)
                .transpose()
                .map_err(FfiError::InvalidInput)?;
            let managed = ManagedSshKey::list()
                .map_err(FfiError::from)?
                .into_iter()
                .find(|k| format!("SHA256:{}", k.fingerprint_sha256()) == fp);
            if managed.is_some_and(|key| key.policy() != KeyPolicy::Default) {
                return Err(FfiError::InvalidInput(
                    "This key always requires authentication and cannot be granted to an app."
                        .to_string(),
                ));
            }
            app_grants::add(&fp, app.into(), expires_in)
                .map(|_| ())
                .map_err(FfiError::from)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?;

        record_app_grant_event(
            audit::Action::SshAppGrantAdd,
            &fingerprint,
            &bundle_id,
            expires_in_seconds,
            peer,
            &result,
        );
        result
    }

    /// Remove an app's lasting access to an SSH key.
    pub async fn remove_ssh_app_grant(
        &self,
        fingerprint_sha256: String,
        team_id: String,
        bundle_id: String,
    ) -> Result<(), FfiError> {
        let fingerprint = canonical_ssh_fingerprint(&fingerprint_sha256);
        let (fp, bid) = (fingerprint.clone(), bundle_id.clone());
        let result = tokio::task::spawn_blocking(move || {
            app_grants::remove(&fp, &team_id, &bid)
                .map(|_| ())
                .map_err(FfiError::from)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?;

        record_app_grant_event(
            audit::Action::SshAppGrantRemove,
            &fingerprint,
            &bundle_id,
            None,
            None,
            &result,
        );
        result
    }

    /// Turn auto-load on or off for the `~/.ssh` key at `path`. The Axo agent
    /// picks up the change on its next request. The key's app grants are kept,
    /// and apply only while auto-load is on.
    pub async fn set_ssh_autoload(
        &self,
        fingerprint_sha256: String,
        path: String,
        enabled: bool,
    ) -> Result<(), FfiError> {
        let fingerprint = canonical_ssh_fingerprint(&fingerprint_sha256);
        tokio::task::spawn_blocking(move || {
            autoload::set(&fingerprint, std::path::Path::new(&path), enabled)
                .map_err(|e| FfiError::InvalidInput(format!("{e:#}")))
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Hosts an SSH key signed in to, from the audit log.
    pub async fn related_ssh_hosts(
        &self,
        fingerprint_sha256: String,
    ) -> Result<Vec<SshRelatedHost>, FfiError> {
        let fingerprint = canonical_ssh_fingerprint(&fingerprint_sha256);
        tokio::task::spawn_blocking(move || related_hosts::related_hosts(&fingerprint))
            .await
            .map_err(|e| FfiError::Internal(e.to_string()))?
            .map(|hosts| hosts.into_iter().map(Into::into).collect())
            .map_err(FfiError::from)
    }

    /// Rewrite a managed SSH key's public key file from the Secure Enclave,
    /// for a key whose `~/.ssh/id_se_*.pub` was deleted. Returns its path.
    pub async fn write_managed_ssh_key_pubkey(
        &self,
        fingerprint_sha256: String,
    ) -> Result<String, FfiError> {
        tokio::task::spawn_blocking(move || {
            let keys = ManagedSshKey::list().map_err(FfiError::from)?;
            let key = keys
                .into_iter()
                .find(|k| k.fingerprint_sha256() == fingerprint_sha256)
                .ok_or_else(|| FfiError::NotFound(fingerprint_sha256.clone()))?;
            let path = key.write_pubkey_file().map_err(FfiError::from)?;
            Ok(path.to_string_lossy().to_string())
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

    /// Ask the running Axo Pass agent for its version and launcher. `None` if
    /// no agent answers, or if it is too old to know the request.
    pub async fn get_ssh_agent_info(&self) -> Option<SshAgentInfo> {
        let info = agent_client::request_agent_info()
            .await
            .inspect_err(|e| log::debug!("agent info unavailable: {e}"))
            .ok()?;
        Some(SshAgentInfo {
            is_current: info.version == env!("CARGO_PKG_VERSION"),
            version: info.version,
            launcher: info.launcher.into(),
        })
    }

    /// Make the running agent exit so it can start again on the bundled `ap`.
    /// Returns once the socket stops answering. launchd starts a launchd agent
    /// again. A detached agent stays down until `start_ssh_agent`.
    pub async fn restart_ssh_agent(&self) -> Result<(), FfiError> {
        agent_client::restart_agent()
            .await
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
}
