use std::sync::Mutex;

use serde::Deserialize;
use typeshare::typeshare;

use crate::app::AppState;
use crate::app::handlers::app_errors::{AppError, ErrorContext};
use crate::app::handlers::vault::with_unlocked_vault;

#[derive(Deserialize)]
#[typeshare]
pub struct AddOrUpdateItemRequest {
    pub vault_key: String,
    pub item_title: String,
    pub item_key: String,
}

#[tauri::command]
pub async fn add_or_update_item(
    request: AddOrUpdateItemRequest,
    state: tauri::State<'_, Mutex<AppState>>,
) -> Result<(), AppError> {
    with_unlocked_vault(&state, &request.vault_key, |vw| {
        vw.add_item(&request.item_key, &request.item_title)
            .error_context("Failed to add/update item.")?;
        Ok(())
    })
}
