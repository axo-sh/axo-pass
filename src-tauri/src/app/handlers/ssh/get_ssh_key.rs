use serde::{Deserialize, Serialize};
use ssh_key::PublicKey;
use typeshare::typeshare;

use crate::secrets::keychain::managed_key::ManagedSshKey;
use crate::ssh::ssh_keys::SystemSshKey;

#[derive(Debug, Clone, Deserialize)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub struct GetSshKeyRequest {
    pub fingerprint_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub struct GetSshKeyResponse {
    pub path: Option<String>,
    pub public_key: String,
}

#[tauri::command]
pub async fn get_ssh_key(request: GetSshKeyRequest) -> Result<GetSshKeyResponse, String> {
    let fingerprint = &request.fingerprint_sha256;

    // Try managed SSH keys first
    let managed_keys =
        ManagedSshKey::list().map_err(|e| format!("Failed to list managed SSH keys: {e}"))?;

    for managed_key in managed_keys {
        if managed_key.fingerprint_sha256() == *fingerprint {
            let public_key_openssh =
                PublicKey::new(managed_key.public_key().clone(), managed_key.label())
                    .to_openssh()
                    .map_err(|e| format!("Failed to format public key: {e}"))?;

            return Ok(GetSshKeyResponse {
                public_key: public_key_openssh,
                path: Some("managed".to_string()),
            });
        }
    }

    // Try system SSH keys (from ~/.ssh)
    let system_keys = SystemSshKey::load_from_user_ssh_dir()
        .map_err(|e| format!("Failed to load system SSH keys: {e}"))?;

    for system_key in system_keys {
        if system_key.fingerprint_sha256 == *fingerprint {
            return Ok(GetSshKeyResponse {
                path: Some(system_key.path.to_string_lossy().to_string()),
                public_key: system_key
                    .public_key
                    .to_openssh()
                    .map_err(|e| format!("Failed to format public key: {e}"))?,
            });
        }
    }

    Err(format!("SSH key not found"))
}
