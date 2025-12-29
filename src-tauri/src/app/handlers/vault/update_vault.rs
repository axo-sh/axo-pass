use std::sync::Mutex;

use serde::Deserialize;
use typeshare::typeshare;

use crate::app::app_state::AppState;
use crate::app::handlers::vault::with_unlocked_vault;

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
    let new_vault_key = request.new_vault_key.filter(|k| k != &request.vault_key);

    with_unlocked_vault(&state, &request.vault_key, |vw| {
        if let Some(new_vault_key) = new_vault_key.clone() {
            vw.set_vault_key(new_vault_key)?;
        }
        if request.new_name != vw.vault.name
            && let Some(new_name) = request.new_name
        {
            vw.set_vault_name(new_name);
        }
        Ok(vw.save()?)
    })?;

    if let Some(new_vault_key) = new_vault_key {
        let mut state = state.lock().unwrap();
        state
            .vaults
            .update_vault_key(&request.vault_key, &new_vault_key)
            .map_err(|e| format!("Failed to update vault key in manager: {}", e))?;
    }
    Ok(())
}
