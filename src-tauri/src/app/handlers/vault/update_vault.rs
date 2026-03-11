use std::sync::Mutex;

use serde::Deserialize;
use typeshare::typeshare;

use crate::app::app_state::AppState;

#[derive(Deserialize, Debug)]
#[typeshare]
pub struct UpdateVaultRequest {
    pub vault_key: String,
    pub new_vault_key: Option<String>,
    pub new_name: Option<String>,
}

#[tauri::command]
pub async fn update_vault(
    state: tauri::State<'_, Mutex<AppState>>,
    request: UpdateVaultRequest,
) -> Result<(), String> {
    // note: updating the vault doesn't require the vault to be unlocked
    // (at least not to update the vault key or name), so we don't use
    // with_unlocked_vault here
    let mut state = state.lock().unwrap();
    let vw = state.vaults.get_vault_mut(&request.vault_key)?;

    if request.new_name.as_deref() != vw.vault_name()
        && let Some(new_name) = request.new_name
    {
        vw.set_vault_name(new_name)?;
        vw.save()?;
    }

    if request.new_vault_key.as_deref() != Some(request.vault_key.as_str())
        && let Some(new_vault_key) = request.new_vault_key
    {
        // note: update saves the vault
        state
            .vaults
            .update_vault_key(&request.vault_key, &new_vault_key)
            .map_err(|e| format!("Failed to update vault key in manager: {}", e))?;
    }

    Ok(())
}
