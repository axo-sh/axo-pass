use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::app::handlers::app_errors::{AppError, ErrorContext};
use crate::secrets::keychain::managed_key::ManagedSshKey;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub struct DeleteManagedSshKeyRequest {
    label: String,
}

#[tauri::command]
pub async fn delete_managed_ssh_key(request: DeleteManagedSshKeyRequest) -> Result<(), AppError> {
    ManagedSshKey::find(&request.label)?
        .ok_or_else(|| AppError::not_found(&format!("SSH key {} not found", request.label)))?
        .delete()
        .error_context(format!("Failed to delete SSH key {}", request.label))
}
