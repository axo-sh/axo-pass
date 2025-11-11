use std::sync::Mutex;

use serde::Deserialize;
use typeshare::typeshare;

use crate::app::AppState;
use crate::secrets::vault_wrapper::VaultWrapper;

#[derive(Deserialize)]
#[typeshare]
pub struct AddItemRequest {
    pub vault_key: String,
    pub item_title: String,
    pub item_key: String,
}

#[tauri::command]
pub async fn add_item(
    request: AddItemRequest,
    state: tauri::State<'_, Mutex<AppState>>,
) -> Result<(), String> {
    let mut state = state
        .lock()
        .map_err(|e| format!("Failed to lock state: {e}"))?;

    let vw: &mut VaultWrapper = state
        .vaults
        .get_vault_mut(&request.vault_key)
        .map_err(|e| format!("Failed to get vault: {e}"))?;

    vw.add_item(request.item_title, request.item_key);
    vw.save()
        .map_err(|e| format!("Failed to save vault: {e}"))?;

    Ok(())
}
