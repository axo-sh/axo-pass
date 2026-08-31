use std::sync::Mutex;

use serde::Deserialize;
use typeshare::typeshare;

use crate::app::AppState;
use crate::app::handlers::app_errors::{AppError, ErrorContext};

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
) -> Result<(), AppError> {
    let mut guard = state.lock()?;
    guard
        .vaults
        .with_unlocked_vault(&request.vault_key, |vw| vw.delete_item(&request.item_key))
        .error_context("Failed to delete item.")
}
