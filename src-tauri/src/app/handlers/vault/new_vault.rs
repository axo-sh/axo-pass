use std::sync::Mutex;

use serde::Deserialize;
use typeshare::typeshare;

use crate::app::AppState;
use crate::app::handlers::vault::get_vault::VaultResponse;
use crate::secrets::vault_wrapper::normalize_key;

#[derive(Deserialize)]
#[typeshare]
pub struct NewVaultRequest {
    vault_name: Option<String>,
    vault_key: Option<String>,
}

#[tauri::command]
pub async fn new_vault(
    request: NewVaultRequest,
    state: tauri::State<'_, Mutex<AppState>>,
) -> Result<VaultResponse, String> {
    log::debug!("command: new_vault");
    let mut state = state
        .lock()
        .map_err(|e| format!("Failed to lock app state: {e}"))?;

    let Some(vault_key) = request
        .vault_key
        .or_else(|| request.vault_name.clone().map(|name| normalize_key(&name)))
    else {
        return Err("Vault key is required".to_string());
    };

    let vw = state
        .vaults
        .new_vault(request.vault_name, vault_key)
        .map_err(|e| format!("Failed to create new vault: {e}"))?;

    Ok(VaultResponse { vault: vw.into() })
}
