use std::collections::HashMap;

use serde::Serialize;
use typeshare::typeshare;

use crate::app::handlers::app_errors::{AppError, ErrorContext};
use crate::app::handlers::ssh::schema::ssh_key_entry::{SshKeyAgent, SshKeyEntry};
use crate::cli::commands::ssh_agent::{list_axo_agent_identities, list_system_agent_identities};
use crate::secrets::keychain::generic_password::PasswordEntry;
use crate::secrets::keychain::managed_key::ManagedSshKey;
use crate::ssh::ssh_keys::SystemSshKey;
use crate::ssh::utils::compute_sha256_fingerprint;

#[derive(Debug, Clone, Serialize)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub struct ListSshKeysResponse {
    pub keys: Vec<SshKeyEntry>,
}

#[tauri::command]
pub async fn list_ssh_keys() -> Result<ListSshKeysResponse, AppError> {
    let mut keys_map: HashMap<String, SshKeyEntry> = HashMap::new();

    // Get known system SSH keys (from .ssh)
    let system_ssh_keys =
        SystemSshKey::load_from_user_ssh_dir().error_context("Failed to find system SSH keys")?;
    for system_key in system_ssh_keys {
        let has_saved_password = system_key.has_saved_password();
        let mut key_entry: SshKeyEntry = system_key.into();
        key_entry.has_saved_password = has_saved_password;
        keys_map.insert(key_entry.fingerprint_sha256.clone(), key_entry);
    }

    // Get managed SSH keys
    let managed_ssh_keys =
        ManagedSshKey::list().error_context("Failed to list managed SSH keys")?;
    for managed_key in managed_ssh_keys {
        let key_entry: SshKeyEntry = managed_key.into();
        keys_map.insert(key_entry.fingerprint_sha256.clone(), key_entry);
    }

    // Get system agent identities (transient key - in agent but not .ssh or vault)
    if let Ok(system_identities) = list_system_agent_identities().await {
        for identity in system_identities {
            let fingerprint_sha256 = compute_sha256_fingerprint(&identity.pubkey);
            if let Some(key_entry) = keys_map.get_mut(&fingerprint_sha256) {
                key_entry.agent.insert(SshKeyAgent::SystemAgent);
            } else {
                let mut key_entry: SshKeyEntry = identity.into();
                key_entry.has_saved_password = PasswordEntry::ssh(&fingerprint_sha256)
                    .exists()
                    .unwrap_or(false);
                key_entry.agent.insert(SshKeyAgent::SystemAgent);
                keys_map.insert(fingerprint_sha256, key_entry);
            }
        }
    }

    // Get axo agent identities (transient key - in agent but not .ssh or vault)
    if let Ok(our_identities) = list_axo_agent_identities().await {
        for identity in our_identities {
            let fingerprint_sha256 = compute_sha256_fingerprint(&identity.pubkey);
            if let Some(key_entry) = keys_map.get_mut(&fingerprint_sha256) {
                key_entry.agent.insert(SshKeyAgent::AxoPassAgent);
            } else {
                let mut key_entry: SshKeyEntry = identity.into();
                key_entry.has_saved_password = PasswordEntry::ssh(&fingerprint_sha256)
                    .exists()
                    .unwrap_or(false);
                key_entry.agent.insert(SshKeyAgent::AxoPassAgent);
                keys_map.insert(fingerprint_sha256, key_entry);
            }
        }
    }

    let mut keys: Vec<SshKeyEntry> = keys_map.into_values().collect();
    keys.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(ListSshKeysResponse { keys })
}
