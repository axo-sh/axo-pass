use std::sync::Mutex;

use serde::Deserialize;
use typeshare::typeshare;

use crate::app::AppState;
use crate::app::handlers::app_errors::{AppError, ErrorContext};

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
    let mut guard = state.lock()?;
    guard
        .vaults
        .with_unlocked_vault(&request.vault_key, |vw| {
            vw.add_item(&request.item_key, &request.item_title)
                .map(|_| ())
        })
        .error_context("Failed to add/update item.")
}
