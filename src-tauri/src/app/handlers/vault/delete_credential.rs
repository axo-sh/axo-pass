use std::sync::Mutex;

use serde::Deserialize;
use typeshare::typeshare;

use crate::app::AppState;
use crate::app::handlers::app_errors::{AppError, ErrorContext};
use crate::app::handlers::vault::with_unlocked_vault;

#[derive(Deserialize)]
#[typeshare]
pub struct DeleteCredentialRequest {
    pub vault_key: String,
    pub item_key: String,
    pub credential_key: String,
}

#[tauri::command]
pub fn delete_credential(
    request: DeleteCredentialRequest,
    state: tauri::State<'_, Mutex<AppState>>,
) -> Result<(), AppError> {
    with_unlocked_vault(&state, &request.vault_key, |vw| {
        vw.delete_item_credential(&request.item_key, &request.credential_key)
            .error_context("Failed to delete credential.")
    })
}
