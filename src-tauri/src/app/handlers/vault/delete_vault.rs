use std::sync::Mutex;

use serde::Deserialize;
use typeshare::typeshare;

use crate::app::AppState;
use crate::app::handlers::app_errors::{AppError, ErrorContext};

#[derive(Deserialize)]
#[typeshare]
pub struct DeleteVaultRequest {
    pub vault_key: String,
}

#[tauri::command]
pub fn delete_vault(
    request: DeleteVaultRequest,
    state: tauri::State<'_, Mutex<AppState>>,
) -> Result<(), AppError> {
    state
        .lock()?
        .vaults
        .delete_vault(&request.vault_key)
        .error_context(format!("Failed to delete vault {}", request.vault_key))
}
