use std::sync::Mutex;

use serde::Deserialize;
use typeshare::typeshare;

use crate::app::AppState;
use crate::app::handlers::app_errors::{AppError, ErrorContext};
use crate::app::handlers::vault::with_unlocked_vault;

#[derive(Deserialize)]
#[typeshare]
pub struct AddOrUpdateCredentialRequest {
    pub vault_key: String,
    pub item_key: String,
    pub credential_key: String,
    pub title: String,
    pub value: String,
}

#[tauri::command]
pub async fn add_or_update_credential(
    request: AddOrUpdateCredentialRequest,
    state: tauri::State<'_, Mutex<AppState>>,
) -> Result<(), AppError> {
    let AddOrUpdateCredentialRequest {
        vault_key,
        item_key,
        credential_key,
        title,
        value,
    } = request;

    with_unlocked_vault(&state, &vault_key, |vw| {
        vw.add_secret(&item_key, &credential_key, &title, value.into())
            .error_context("Failed to add/update credential.")
    })
}
