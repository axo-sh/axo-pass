use std::collections::{BTreeSet, HashSet};

use serde::Serialize;
use typeshare::typeshare;

use crate::app::handlers::ssh::get_ssh_agent_status::SshKeyTag;
use crate::cli::commands::ssh_agent::{list_axo_agent_identities, list_system_agent_identities};
use crate::secrets::keychain::managed_key::ManagedSshKey;
use crate::ssh::ssh_keys::{SshKeyType, SystemSshKey};
use crate::ssh::utils::{compute_md5_fingerprint, compute_sha256_fingerprint};

#[derive(Debug, Clone, Serialize)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub struct SshKeyEntry {
    pub name: String,
    pub path: Option<String>,
    pub public_key: Option<String>,
    pub comment: Option<String>,
    pub key_type: SshKeyType,
    pub fingerprint_sha256: String,
    pub fingerprint_md5: String,
    pub has_saved_password: bool,
    pub is_managed: bool,
    #[typeshare(typescript(type = "SshKeyTag[]"))]
    pub tags: BTreeSet<SshKeyTag>,
}

#[derive(Debug, Clone, Serialize)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub struct ListSshKeysResponse {
    pub keys: Vec<SshKeyEntry>,
}

#[tauri::command]
pub async fn list_ssh_keys() -> Result<ListSshKeysResponse, String> {
    let mut keys_map: std::collections::HashMap<String, SshKeyEntry> =
        std::collections::HashMap::new();

    // Get known SSH keys (system + managed)
    let system_ssh_keys = SystemSshKey::load_from_user_ssh_dir()
        .inspect_err(|e| log::error!("Failed to find system SSH keys: {e}"))
        .unwrap_or_default();

    for system_key in system_ssh_keys {
        let path_str = system_key.path.to_string_lossy().to_string();
        let has_saved_password = system_key.has_saved_password();
        let fingerprint_sha256 = system_key.fingerprint_sha256.clone();
        keys_map.insert(
            fingerprint_sha256.clone(),
            SshKeyEntry {
                name: system_key.name,
                path: Some(path_str),
                public_key: system_key
                    .public_key_path
                    .as_ref()
                    .map(|p| format!("{}", p.display())),
                comment: Some(system_key.comment),
                key_type: system_key.key_type,
                fingerprint_sha256,
                fingerprint_md5: system_key.fingerprint_md5,
                has_saved_password,
                is_managed: false,
                tags: BTreeSet::new(),
            },
        );
    }

    let managed_ssh_keys = ManagedSshKey::list()
        .inspect_err(|e| log::debug!("Failed to list managed SSH keys: {e}"))
        .unwrap_or_default();
    for managed_key in managed_ssh_keys {
        let fingerprint = managed_key.fingerprint_sha256().to_string();
        keys_map.insert(
            fingerprint.clone(),
            SshKeyEntry {
                name: managed_key.name(),
                path: None,
                key_type: SshKeyType::Ecdsa, // Managed keys are always ECDSA
                public_key: managed_key
                    .pubkey_path()
                    .ok()
                    .filter(|p| p.exists())
                    .map(|p| format!("{}", p.display())),
                comment: None,
                fingerprint_sha256: fingerprint,
                fingerprint_md5: managed_key.fingerprint_md5().to_string(),
                has_saved_password: false,
                is_managed: true,
                tags: BTreeSet::new(),
            },
        );
    }

    let known_fingerprints: HashSet<String> = keys_map.keys().cloned().collect();

    // Get system agent identities
    if let Ok(system_identities) = list_system_agent_identities().await {
        for identity in system_identities {
            let fingerprint_sha256 = compute_sha256_fingerprint(&identity.pubkey);
            if let Some(key) = keys_map.get_mut(&fingerprint_sha256) {
                key.tags.insert(SshKeyTag::SystemAgent);
            } else {
                // Transient key - in agent but not known
                keys_map.insert(
                    fingerprint_sha256.clone(),
                    SshKeyEntry {
                        name: identity.comment.clone(),
                        path: None,
                        public_key: None,
                        comment: Some(identity.comment.to_string()),
                        key_type: identity.pubkey.algorithm().into(),
                        fingerprint_sha256,
                        fingerprint_md5: compute_md5_fingerprint(&identity.pubkey),
                        has_saved_password: false,
                        is_managed: false,
                        tags: BTreeSet::from([SshKeyTag::Transient, SshKeyTag::SystemAgent]),
                    },
                );
            }
        }
    }

    // Get our agent identities
    if let Ok(our_identities) = list_axo_agent_identities().await {
        for identity in our_identities {
            let fingerprint_sha256 = compute_sha256_fingerprint(&identity.pubkey);
            if let Some(key) = keys_map.get_mut(&fingerprint_sha256) {
                key.tags.insert(SshKeyTag::AxoPassAgent);
            } else if !known_fingerprints.contains(&fingerprint_sha256) {
                // Transient key - in agent but not known
                keys_map.insert(
                    fingerprint_sha256.clone(),
                    SshKeyEntry {
                        name: identity.comment.clone(),
                        path: None,
                        public_key: None,
                        comment: Some(identity.comment.to_string()),
                        key_type: identity.pubkey.algorithm().into(),
                        fingerprint_sha256,
                        fingerprint_md5: compute_md5_fingerprint(&identity.pubkey),
                        has_saved_password: false,
                        is_managed: false,
                        tags: BTreeSet::from([SshKeyTag::Transient, SshKeyTag::AxoPassAgent]),
                    },
                );
            }
        }
    }

    let mut keys: Vec<SshKeyEntry> = keys_map.into_values().collect();
    keys.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(ListSshKeysResponse { keys })
}
