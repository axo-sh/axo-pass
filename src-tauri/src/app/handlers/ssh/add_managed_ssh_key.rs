use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::secrets::keychain::managed_key::ManagedSshKey;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub struct AddManagedSshKeyRequest {
    alias: Option<String>,
}

#[tauri::command]
pub async fn add_managed_ssh_key(_request: AddManagedSshKeyRequest) -> Result<(), String> {
    // todo: support managed ssh key aliases
    ManagedSshKey::create().await.map_err(|e| e.to_string())
}
