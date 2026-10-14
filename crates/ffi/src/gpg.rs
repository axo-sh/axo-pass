use axo_pass_core::age::recipients::delete_recipient as delete_age_recipient;
use axo_pass_core::audit;
use axo_pass_core::gpg::agent_conf::{self, State as CoreAgentConfState};
use axo_pass_core::gpg::key_overview::{
    GpgCapability as CoreGpgCapability, GpgKeyOverview, GpgSecretState as CoreGpgSecretState,
    GpgSubkey as CoreGpgSubkey, GpgTrust as CoreGpgTrust, GpgUserId as CoreGpgUserId,
};
use axo_pass_core::secrets::keychain::generic_password::{
    PasswordEntry, PasswordEntryType as CorePasswordEntryType,
};
use secrecy::{ExposeSecret, SecretString};

use crate::*;
use crate::ssh::canonical_ssh_fingerprint;

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

#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum GpgCapability {
    Sign,
    Certify,
    Encrypt,
    Authenticate,
}

impl From<CoreGpgCapability> for GpgCapability {
    fn from(c: CoreGpgCapability) -> Self {
        match c {
            CoreGpgCapability::Sign => GpgCapability::Sign,
            CoreGpgCapability::Certify => GpgCapability::Certify,
            CoreGpgCapability::Encrypt => GpgCapability::Encrypt,
            CoreGpgCapability::Authenticate => GpgCapability::Authenticate,
        }
    }
}

/// Owner trust in a GPG key.
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum GpgTrust {
    Unknown,
    Undefined,
    Never,
    Marginal,
    Full,
    Ultimate,
    Expired,
    Revoked,
    Invalid,
    Disabled,
}

impl From<CoreGpgTrust> for GpgTrust {
    fn from(t: CoreGpgTrust) -> Self {
        match t {
            CoreGpgTrust::Unknown => GpgTrust::Unknown,
            CoreGpgTrust::Undefined => GpgTrust::Undefined,
            CoreGpgTrust::Never => GpgTrust::Never,
            CoreGpgTrust::Marginal => GpgTrust::Marginal,
            CoreGpgTrust::Full => GpgTrust::Full,
            CoreGpgTrust::Ultimate => GpgTrust::Ultimate,
            CoreGpgTrust::Expired => GpgTrust::Expired,
            CoreGpgTrust::Revoked => GpgTrust::Revoked,
            CoreGpgTrust::Invalid => GpgTrust::Invalid,
            CoreGpgTrust::Disabled => GpgTrust::Disabled,
        }
    }
}

/// Whether the private key material is present, and in what form.
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum GpgSecretState {
    /// No private key in the keyring: this is a public-only key.
    None,
    /// The private key is in the GnuPG private key directory.
    Present,
    /// A stub pointing at a smartcard or token.
    Card,
    /// A stub for a key kept offline.
    Offline,
}

impl From<CoreGpgSecretState> for GpgSecretState {
    fn from(s: CoreGpgSecretState) -> Self {
        match s {
            CoreGpgSecretState::None => GpgSecretState::None,
            CoreGpgSecretState::Present => GpgSecretState::Present,
            CoreGpgSecretState::Card => GpgSecretState::Card,
            CoreGpgSecretState::Offline => GpgSecretState::Offline,
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct GpgUserId {
    /// The full uid string, e.g. `Dana Reyes <dana@example.com>`.
    pub uid: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub trust: GpgTrust,
    pub is_revoked: bool,
}

impl From<CoreGpgUserId> for GpgUserId {
    fn from(u: CoreGpgUserId) -> Self {
        GpgUserId {
            uid: u.uid,
            name: u.name,
            email: u.email,
            trust: u.trust.into(),
            is_revoked: u.is_revoked,
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct GpgSubkeyEntry {
    pub key_id: String,
    pub fingerprint: Option<String>,
    pub keygrip: Option<String>,
    pub algorithm: String,
    pub key_length: u32,
    pub curve: Option<String>,
    pub capabilities: Vec<GpgCapability>,
    /// Unix seconds.
    pub created_at: Option<i64>,
    /// Unix seconds. `None` means the subkey does not expire.
    pub expires_at: Option<i64>,
    pub is_expired: bool,
    pub is_revoked: bool,
    pub secret_state: GpgSecretState,
    /// Whether a passphrase for this subkey's keygrip is saved in the keychain.
    pub has_saved_password: bool,
    /// Whether gpg-agent holds this subkey encrypted, so using it needs a
    /// passphrase.
    pub requires_passphrase: bool,
}

impl From<CoreGpgSubkey> for GpgSubkeyEntry {
    fn from(s: CoreGpgSubkey) -> Self {
        GpgSubkeyEntry {
            key_id: s.key_id,
            fingerprint: s.fingerprint,
            keygrip: s.keygrip,
            algorithm: s.algorithm,
            key_length: s.key_length,
            curve: s.curve,
            capabilities: s
                .capabilities
                .into_iter()
                .map(GpgCapability::from)
                .collect(),
            created_at: s.created_at,
            expires_at: s.expires_at,
            is_expired: s.is_expired,
            is_revoked: s.is_revoked,
            secret_state: s.secret_state.into(),
            has_saved_password: s.has_saved_password,
            requires_passphrase: s.requires_passphrase,
        }
    }
}

/// A GPG key, merged from the public and secret keyring listings.
#[derive(uniffi::Record, Clone)]
pub struct GpgKeyEntry {
    /// Long key id of the primary key.
    pub key_id: String,
    pub fingerprint: String,
    pub keygrip: Option<String>,
    /// First uid's name, falling back to the whole uid string.
    pub name: String,
    /// First uid's email, when it has one.
    pub email: Option<String>,
    pub user_ids: Vec<GpgUserId>,
    pub algorithm: String,
    pub key_length: u32,
    pub curve: Option<String>,
    pub capabilities: Vec<GpgCapability>,
    pub trust: GpgTrust,
    /// Unix seconds.
    pub created_at: Option<i64>,
    /// Unix seconds. `None` means the key does not expire.
    pub expires_at: Option<i64>,
    pub is_expired: bool,
    pub is_revoked: bool,
    pub is_disabled: bool,
    pub secret_state: GpgSecretState,
    /// Whether a passphrase for the primary key's keygrip is saved in the
    /// keychain. Subkeys carry their own.
    pub has_saved_password: bool,
    /// Whether gpg-agent holds the primary key encrypted, so using it needs a
    /// passphrase.
    pub requires_passphrase: bool,
    /// Directory holding the private key files, when a secret key is present.
    pub secret_key_dir: Option<String>,
    pub subkeys: Vec<GpgSubkeyEntry>,
}

impl From<GpgKeyOverview> for GpgKeyEntry {
    fn from(k: GpgKeyOverview) -> Self {
        GpgKeyEntry {
            key_id: k.key_id,
            fingerprint: k.fingerprint,
            keygrip: k.keygrip,
            name: k.name,
            email: k.email,
            user_ids: k.user_ids.into_iter().map(GpgUserId::from).collect(),
            algorithm: k.algorithm,
            key_length: k.key_length,
            curve: k.curve,
            capabilities: k
                .capabilities
                .into_iter()
                .map(GpgCapability::from)
                .collect(),
            trust: k.trust.into(),
            created_at: k.created_at,
            expires_at: k.expires_at,
            is_expired: k.is_expired,
            is_revoked: k.is_revoked,
            is_disabled: k.is_disabled,
            secret_state: k.secret_state.into(),
            has_saved_password: k.has_saved_password,
            requires_passphrase: k.requires_passphrase,
            secret_key_dir: k.secret_key_dir,
            subkeys: k.subkeys.into_iter().map(GpgSubkeyEntry::from).collect(),
        }
    }
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

#[uniffi::export(async_runtime = "tokio")]
impl AxoPass {
    /// Reload gpg-agent and run a test signing operation, to confirm GPG
    /// signing works end-to-end. Mirrors `gpg_test_integration` in the Tauri
    /// app.
    pub async fn gpg_test_integration(&self) -> Result<(), FfiError> {
        tokio::task::spawn_blocking(axo_pass_core::gpg::test_integration)
            .await
            .map_err(|e| FfiError::Internal(e.to_string()))?
            .map_err(FfiError::from)
    }

    /// List the keys in the GPG public keyring, with secret key state merged
    /// in from the secret keyring.
    pub async fn list_gpg_keys(&self) -> Result<Vec<GpgKeyEntry>, FfiError> {
        let overviews =
            tokio::task::spawn_blocking(axo_pass_core::gpg::key_overview::list_gpg_keys)
                .await
                .map_err(|e| FfiError::Internal(e.to_string()))?
                .map_err(FfiError::from)?;
        Ok(overviews.into_iter().map(GpgKeyEntry::from).collect())
    }

    /// Save the passphrase for one GPG keygrip to the keychain, after checking
    /// it with gpg. gpg-agent asks per keygrip, and each secret half carries
    /// its own passphrase, so a primary key and each subkey are saved
    /// separately. `key_id` names the key that keygrip belongs to.
    pub async fn save_gpg_key_password(
        &self,
        key_id: String,
        keygrip: String,
        password: String,
    ) -> Result<(), FfiError> {
        tokio::task::spawn_blocking(move || {
            axo_pass_core::gpg::key_overview::save_passphrase(
                &key_id,
                &keygrip,
                SecretString::from(password),
            )
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
        .map_err(FfiError::from)
    }

    /// Export a key's public half in ASCII armor, for sharing or uploading to
    /// a keyserver.
    pub async fn export_gpg_public_key(&self, fingerprint: String) -> Result<String, FfiError> {
        tokio::task::spawn_blocking(move || {
            axo_pass_core::gpg::key_overview::export_public_key(&fingerprint)
        })
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

    /// Delete a generic keychain-managed password entry. Records a
    /// `gpg.passphrase_deleted`, `ssh.passphrase_deleted`, or `age.key_delete`
    /// audit event. Entries of type `Other` are not recorded.
    pub async fn delete_password(
        &self,
        password_type: PasswordEntryType,
        key_id: String,
    ) -> Result<(), FfiError> {
        if password_type == PasswordEntryType::AgeKey {
            return tokio::task::spawn_blocking(move || delete_age_recipient(&key_id, None))
                .await
                .map_err(|e| FfiError::Internal(e.to_string()))?
                .map_err(FfiError::from);
        }

        let id = key_id.clone();
        let result = tokio::task::spawn_blocking(move || {
            let entry = PasswordEntry {
                password_type: password_type.into(),
                key_id: id,
            };
            entry.delete().map_err(FfiError::from)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?;

        let (action, subject) = match password_type {
            PasswordEntryType::GpgKey => (
                audit::Action::GpgPassphraseDeleted,
                audit::Subject::new(audit::SubjectKind::GpgKey, key_id),
            ),
            PasswordEntryType::SshKey => {
                let fingerprint = canonical_ssh_fingerprint(&key_id);
                (
                    audit::Action::SshPassphraseDeleted,
                    audit::Subject::new(audit::SubjectKind::SshKey, fingerprint.clone())
                        .fingerprint(fingerprint),
                )
            },
            PasswordEntryType::AgeKey | PasswordEntryType::Other => return result,
        };
        let mut event = audit::AuditEvent::new(
            audit::process_source(),
            action,
            if result.is_ok() {
                audit::Outcome::Succeeded
            } else {
                audit::Outcome::Failed
            },
        )
        .subject(subject);
        if let Err(e) = &result {
            event = event.message(e.to_string());
        }
        audit::record(event);
        result
    }

    /// Read a saved key passphrase back from the keychain, prompting for Touch
    /// ID. Errors with `NotFound` when no passphrase is saved for the key.
    pub async fn reveal_key_password(
        &self,
        password_type: PasswordEntryType,
        key_id: String,
    ) -> Result<String, FfiError> {
        tokio::task::spawn_blocking(move || {
            let entry = PasswordEntry {
                password_type: password_type.into(),
                key_id,
            };
            match entry.get_password().map_err(FfiError::from)? {
                Some(secret) => Ok(secret.expose_secret().to_string()),
                None => Err(FfiError::NotFound(
                    "No saved passphrase for this key".to_string(),
                )),
            }
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }
}
