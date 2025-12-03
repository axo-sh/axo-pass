use std::sync::Mutex;

use serde::Deserialize;
use typeshare::typeshare;

use crate::app::AppState;

#[derive(Deserialize)]
#[typeshare]
pub struct DeleteVaultRequest {
    pub vault_key: String,
}

#[tauri::command]
pub fn delete_vault(
    request: DeleteVaultRequest,
    state: tauri::State<'_, Mutex<AppState>>,
) -> Result<(), String> {
    let mut guard = state
        .lock()
        .map_err(|e| format!("Failed to lock app state: {e}"))?;

    guard
        .vaults
        .delete_vault(&request.vault_key)
        .map_err(|e| format!("Failed to delete vault: {e}"))
}
