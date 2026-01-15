use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::secrets::keychain::managed_key::ManagedSshKey;
use crate::ssh::ssh_keys::{SshKeyType, SystemSshKey};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub struct SshKeyInfo {
    pub name: String,
    pub path: Option<String>,
    pub public_key: Option<String>,
    pub key_type: SshKeyType,
    pub fingerprint_sha256: String,
    pub fingerprint_md5: String,
    pub has_saved_password: bool,
    pub is_managed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub struct ListSshKeysResponse {
    pub keys: Vec<SshKeyInfo>,
}

#[tauri::command]
pub async fn list_ssh_keys() -> Result<ListSshKeysResponse, String> {
    let mut keys = Vec::new();

    let system_ssh_keys = SystemSshKey::load_from_user_ssh_dir()
        .inspect_err(|e| log::error!("Failed to find system SSH keys: {e}"))
        .unwrap_or_default();
    for system_key in system_ssh_keys {
        let path_str = system_key.path.to_string_lossy().to_string();
        let has_saved_password = system_key.has_saved_password();
        keys.push(SshKeyInfo {
            name: system_key.name,
            path: Some(path_str),
            public_key: system_key
                .public_key_path
                .as_ref()
                .map(|p| format!("{}", p.display())),
            key_type: system_key.key_type,
            fingerprint_sha256: system_key.fingerprint_sha256,
            fingerprint_md5: system_key.fingerprint_md5,
            has_saved_password,
            is_managed: false,
        });
    }

    let managed_ssh_keys = ManagedSshKey::list()
        .inspect_err(|e| log::debug!("Failed to list managed SSH keys: {e}"))
        .unwrap_or_default();
    for managed_key in managed_ssh_keys {
        keys.push(SshKeyInfo {
            name: managed_key.name(),
            path: None,
            key_type: SshKeyType::Ecdsa, // Managed keys are always ECDSA
            public_key: managed_key
                .pubkey_path()
                .ok()
                .filter(|p| p.exists())
                .map(|p| format!("{}", p.display())),
            fingerprint_sha256: managed_key.fingerprint_sha256().to_string(),
            fingerprint_md5: managed_key.fingerprint_md5().to_string(),
            has_saved_password: false,
            is_managed: true,
        });
    }

    keys.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(ListSshKeysResponse { keys })
}
