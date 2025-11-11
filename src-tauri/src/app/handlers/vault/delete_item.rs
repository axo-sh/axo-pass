use std::sync::Mutex;

use serde::Deserialize;
use typeshare::typeshare;

use crate::app::AppState;
use crate::app::handlers::vault::with_unlocked_vault;

#[derive(Deserialize)]
#[typeshare]
pub struct DeleteItemRequest {
    pub vault_key: String,
    pub item_key: String,
}

#[tauri::command]
pub fn delete_item(
    request: DeleteItemRequest,
    state: tauri::State<'_, Mutex<AppState>>,
) -> Result<(), String> {
    with_unlocked_vault(&state, &request.vault_key, |vw| {
        vw.delete_item(&request.item_key)
            .map_err(|e| format!("Failed to delete credential: {e}"))
    })
}
