use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::secrets::keychain::managed_key::ManagedSshKey;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub struct DeleteManagedSshKeyRequest {
    label: String,
}

#[tauri::command]
pub async fn delete_managed_ssh_key(request: DeleteManagedSshKeyRequest) -> Result<(), String> {
    let ssh_key = ManagedSshKey::find(&request.label)
        .map_err(|e| format!("Failed to find SSH key: {e}"))?
        .ok_or_else(|| format!("SSH key {} not found", request.label))?;

    ssh_key
        .delete()
        .map_err(|e| format!("Failed to delete SSH key: {e}"))
}
