use std::collections::HashMap;

use ssh_agent_lib::proto::Identity;

use crate::secrets::keychain::generic_password::PasswordEntry;
use crate::secrets::keychain::managed_key::ManagedSshKey;
use crate::ssh::agent_client::{list_axo_agent_identities, list_system_agent_identities};
use crate::ssh::ssh_keys::{SshKeyType, SystemSshKey};
use crate::ssh::utils::{compute_md5_fingerprint, compute_sha256_fingerprint};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshKeyLocation {
    Vault,
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
    pub public_key: Option<String>,
    pub comment: Option<String>,
    pub key_type: SshKeyType,
    pub fingerprint_sha256: String,
    pub fingerprint_md5: String,
    pub has_saved_password: bool,
    pub is_managed: bool,
    pub agents: Vec<SshKeyAgentKind>,
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
            comment: Some(system_key.comment),
            key_type: system_key.key_type,
            fingerprint_sha256: system_key.fingerprint_sha256,
            fingerprint_md5: system_key.fingerprint_md5,
            has_saved_password,
            is_managed: false,
            agents: Vec::new(),
        }
    }
}

impl From<ManagedSshKey> for SshKeyOverview {
    fn from(managed_key: ManagedSshKey) -> Self {
        SshKeyOverview {
            name: managed_key.name(),
            location: SshKeyLocation::Vault,
            path: None,
            key_type: SshKeyType::Ecdsa, // Managed keys are always ECDSA
            public_key: managed_key
                .pubkey_path()
                .ok()
                .filter(|p| p.exists())
                .map(|p| format!("{}", p.display())),
            comment: None,
            fingerprint_sha256: managed_key.fingerprint_sha256(),
            fingerprint_md5: managed_key.fingerprint_md5(),
            has_saved_password: false,
            is_managed: true,
            agents: Vec::new(),
        }
    }
}

impl From<Identity> for SshKeyOverview {
    fn from(identity: Identity) -> Self {
        let fingerprint_sha256 = compute_sha256_fingerprint(&identity.pubkey);
        let fingerprint_md5 = compute_md5_fingerprint(&identity.pubkey);
        let has_saved_password = PasswordEntry::ssh(&fingerprint_sha256)
            .exists()
            .unwrap_or(false);
        SshKeyOverview {
            name: identity.comment.clone(),
            location: SshKeyLocation::Transient,
            path: Some(identity.comment.clone()),
            public_key: None,
            comment: Some(identity.comment),
            key_type: identity.pubkey.algorithm().into(),
            fingerprint_sha256,
            fingerprint_md5,
            has_saved_password,
            is_managed: false,
            agents: Vec::new(),
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

    if let Ok(system_identities) = list_system_agent_identities().await {
        for identity in system_identities {
            let fingerprint_sha256 = compute_sha256_fingerprint(&identity.pubkey);
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
            let fingerprint_sha256 = compute_sha256_fingerprint(&identity.pubkey);
            if let Some(key_entry) = keys_map.get_mut(&fingerprint_sha256) {
                key_entry.agents.push(SshKeyAgentKind::AxoPassAgent);
            } else {
                let mut key_entry: SshKeyOverview = identity.into();
                key_entry.agents.push(SshKeyAgentKind::AxoPassAgent);
                keys_map.insert(fingerprint_sha256, key_entry);
            }
        }
    }

    let mut keys: Vec<SshKeyOverview> = keys_map.into_values().collect();
    keys.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(keys)
}
