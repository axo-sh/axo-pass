use std::sync::Mutex;

use serde::Deserialize;
use typeshare::typeshare;

use crate::app::AppState;
use crate::app::handlers::vault::get_vault::VaultResponse;

#[derive(Deserialize)]
#[typeshare]
pub struct NewVaultRequest {
    vault_name: Option<String>,
    vault_key: String,
}

#[tauri::command]
pub async fn add_vault(
    request: NewVaultRequest,
    state: tauri::State<'_, Mutex<AppState>>,
) -> Result<VaultResponse, String> {
    log::debug!("command: add_vault");
    let mut state = state
        .lock()
        .map_err(|e| format!("Failed to lock app state: {e}"))?;

    let vw = state
        .vaults
        .add_vault(request.vault_name, &request.vault_key)
        .map_err(|e| format!("Failed to create new vault: {e}"))?;

    Ok(VaultResponse { vault: vw.into() })
}
