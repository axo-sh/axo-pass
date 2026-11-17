use std::collections::HashMap;
use std::fs;
use std::path::Path;

use ssh_agent_lib::proto::Identity;
use ssh_key::PublicKey;
use uuid::Uuid;

use crate::core::app_broker::ssh::vault_keys::{self, VaultKeyEntry};
use crate::core::app_broker::ssh::vault_keys_path;
use crate::core::config::APP_CONFIG;
use crate::secrets::keychain::generic_password::PasswordEntry;
use crate::secrets::keychain::managed_key::{KeyPolicy, ManagedSshKey};
use crate::ssh::agent_client::{list_axo_agent_identities, list_system_agent_identities};
use crate::ssh::ssh_keys::{SshKeyType, SystemSshKey};
use crate::ssh::utils::{compute_md5_fingerprint, compute_sha256_fingerprint, ssh_dir_path};
use crate::ssh::vault_pubkeys;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshKeyLocation {
    /// Secure Enclave key.
    SecureEnclave,
    /// SSH key credential in a vault.
    VaultKey,
    Transient,
    SshDir,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SshKeyAgentKind {
    SystemAgent,
    AxoPassAgent,
}

/// A unified view of an SSH key, merged from whichever of these sources it's
/// known to: on-disk (`~/.ssh`), Secure Enclave-managed, and/or currently
/// loaded into the system or Axo Pass SSH agents.
#[derive(Debug, Clone)]
pub struct SshKeyOverview {
    pub name: String,
    pub location: SshKeyLocation,
    pub path: Option<String>,
    /// Path to the `.pub` file, when the key has one on disk.
    pub public_key: Option<String>,
    /// The public key in OpenSSH format, read from the `.pub` file when there
    /// is one so it carries the comment the file carries, and derived from the
    /// key itself otherwise.
    pub public_key_openssh: Option<String>,
    pub comment: Option<String>,
    pub key_type: SshKeyType,
    pub fingerprint_sha256: String,
    pub fingerprint_md5: String,
    pub has_saved_password: bool,
    pub is_managed: bool,
    /// Set for managed keys only.
    pub policy: Option<KeyPolicy>,
    pub agents: Vec<SshKeyAgentKind>,
    /// The Axo agent advertises this key and loads it on first use.
    pub autoload: bool,
    /// Where the key is stored. Set for vault keys only.
    pub vault_key: Option<VaultKeyLocation>,
}

/// Credential that holds a vault SSH key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultKeyLocation {
    pub vault_key: String,
    pub item_key: String,
    pub credential_key: String,
    /// Identifier of the credential, stable across renames.
    pub credential_id: Option<Uuid>,
}

/// Read a `.pub` file's single line, ignoring an unreadable or empty file.
fn read_pubkey_file(path: &Path) -> Option<String> {
    let contents = fs::read_to_string(path).ok()?;
    let trimmed = contents.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

impl From<SystemSshKey> for SshKeyOverview {
    fn from(system_key: SystemSshKey) -> Self {
        let has_saved_password = system_key.has_saved_password();
        SshKeyOverview {
            name: system_key.name,
            location: SshKeyLocation::SshDir,
            path: Some(system_key.path.to_string_lossy().to_string()),
            public_key: system_key
                .public_key_path
                .as_ref()
                .map(|p| format!("{}", p.display())),
            public_key_openssh: system_key
                .public_key_path
                .as_deref()
                .and_then(read_pubkey_file)
                .or_else(|| system_key.public_key.to_openssh().ok()),
            comment: Some(system_key.comment),
            key_type: system_key.key_type,
            fingerprint_sha256: system_key.fingerprint_sha256,
            fingerprint_md5: system_key.fingerprint_md5,
            has_saved_password,
            is_managed: false,
            policy: None,
            agents: Vec::new(),
            autoload: false,
            vault_key: None,
        }
    }
}

impl From<ManagedSshKey> for SshKeyOverview {
    fn from(managed_key: ManagedSshKey) -> Self {
        let pubkey_path = managed_key.pubkey_path().ok().filter(|p| p.exists());
        SshKeyOverview {
            name: managed_key.name(),
            location: SshKeyLocation::SecureEnclave,
            path: None,
            key_type: SshKeyType::Ecdsa, // Managed keys are always ECDSA
            public_key: pubkey_path.as_ref().map(|p| format!("{}", p.display())),
            public_key_openssh: pubkey_path
                .as_deref()
                .and_then(read_pubkey_file)
                .or_else(|| managed_key.public_key_openssh().ok()),
            comment: None,
            fingerprint_sha256: managed_key.fingerprint_sha256(),
            fingerprint_md5: managed_key.fingerprint_md5(),
            has_saved_password: false,
            is_managed: true,
            policy: Some(managed_key.policy()),
            agents: Vec::new(),
            autoload: false,
            vault_key: None,
        }
    }
}

impl From<VaultKeyEntry> for SshKeyOverview {
    fn from(entry: VaultKeyEntry) -> Self {
        let pubkey_path = entry
            .credential_id
            .zip(ssh_dir_path().ok())
            .map(|(id, dir)| vault_pubkeys::path_for(&dir, id))
            .filter(|path| path.exists());
        let public_key = PublicKey::from_openssh(&entry.public_key).ok();
        let key_type = public_key
            .as_ref()
            .map_or(SshKeyType::Unknown, |key| key.algorithm().into());
        let fingerprint_sha256 = entry
            .fingerprint
            .strip_prefix("SHA256:")
            .unwrap_or(&entry.fingerprint)
            .to_string();
        let fingerprint_md5 = public_key
            .as_ref()
            .map(|key| compute_md5_fingerprint(key.key_data()))
            .unwrap_or_default();
        // Named like the public key file, as `~/.ssh` keys are named by their
        // file. The comment is shown separately.
        let name = entry
            .credential_id
            .map_or_else(|| entry.item_key.clone(), vault_pubkeys::key_name);
        SshKeyOverview {
            name,
            location: SshKeyLocation::VaultKey,
            path: None,
            public_key: pubkey_path.map(|path| path.display().to_string()),
            public_key_openssh: Some(entry.public_key),
            comment: Some(entry.comment),
            key_type,
            fingerprint_sha256,
            fingerprint_md5,
            has_saved_password: false,
            is_managed: false,
            policy: None,
            agents: Vec::new(),
            autoload: false,
            vault_key: Some(VaultKeyLocation {
                vault_key: entry.vault_key,
                item_key: entry.item_key,
                credential_key: entry.credential_key,
                credential_id: entry.credential_id,
            }),
        }
    }
}

impl From<Identity> for SshKeyOverview {
    fn from(identity: Identity) -> Self {
        let key_data = identity.credential.key_data();
        let fingerprint_sha256 = compute_sha256_fingerprint(key_data);
        let fingerprint_md5 = compute_md5_fingerprint(key_data);
        let has_saved_password = PasswordEntry::ssh(&fingerprint_sha256)
            .exists()
            .unwrap_or(false);
        SshKeyOverview {
            name: identity.comment.clone(),
            location: SshKeyLocation::Transient,
            path: Some(identity.comment.clone()),
            public_key: None,
            public_key_openssh: ssh_key::PublicKey::new(key_data.clone(), identity.comment.clone())
                .to_openssh()
                .ok(),
            comment: Some(identity.comment),
            key_type: key_data.algorithm().into(),
            fingerprint_sha256,
            fingerprint_md5,
            has_saved_password,
            is_managed: false,
            policy: None,
            agents: Vec::new(),
            autoload: false,
            vault_key: None,
        }
    }
}

/// Merge on-disk, Secure Enclave-managed, and transient agent-loaded SSH
/// keys into one deduplicated, fingerprint-keyed view.
pub async fn list_all_ssh_keys() -> anyhow::Result<Vec<SshKeyOverview>> {
    let mut keys_map: HashMap<String, SshKeyOverview> = HashMap::new();

    let system_ssh_keys = SystemSshKey::load_from_user_ssh_dir()?;
    for system_key in system_ssh_keys {
        let key_entry: SshKeyOverview = system_key.into();
        keys_map.insert(key_entry.fingerprint_sha256.clone(), key_entry);
    }

    let managed_ssh_keys = ManagedSshKey::list()?;
    for managed_key in managed_ssh_keys {
        let key_entry: SshKeyOverview = managed_key.into();
        keys_map.insert(key_entry.fingerprint_sha256.clone(), key_entry);
    }

    for entry in vault_keys::load(&vault_keys_path()) {
        let key_entry: SshKeyOverview = entry.into();
        keys_map.insert(key_entry.fingerprint_sha256.clone(), key_entry);
    }

    if let Ok(system_identities) = list_system_agent_identities().await {
        for identity in system_identities {
            let fingerprint_sha256 = compute_sha256_fingerprint(identity.credential.key_data());
            if let Some(key_entry) = keys_map.get_mut(&fingerprint_sha256) {
                key_entry.agents.push(SshKeyAgentKind::SystemAgent);
            } else {
                let mut key_entry: SshKeyOverview = identity.into();
                key_entry.agents.push(SshKeyAgentKind::SystemAgent);
                keys_map.insert(fingerprint_sha256, key_entry);
            }
        }
    }

    if let Ok(axo_identities) = list_axo_agent_identities().await {
        for identity in axo_identities {
            let fingerprint_sha256 = compute_sha256_fingerprint(identity.credential.key_data());
            if let Some(key_entry) = keys_map.get_mut(&fingerprint_sha256) {
                key_entry.agents.push(SshKeyAgentKind::AxoPassAgent);
            } else {
                let mut key_entry: SshKeyOverview = identity.into();
                key_entry.agents.push(SshKeyAgentKind::AxoPassAgent);
                keys_map.insert(fingerprint_sha256, key_entry);
            }
        }
    }

    let autoload = APP_CONFIG
        .lock()
        .map(|config| config.ssh_autoload.clone())
        .unwrap_or_default();
    for key_entry in keys_map.values_mut() {
        key_entry.autoload =
            autoload.contains_key(&format!("SHA256:{}", key_entry.fingerprint_sha256));
    }

    let mut keys: Vec<SshKeyOverview> = keys_map.into_values().collect();
    keys.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(keys)
}
