use std::sync::Mutex;

use serde::Deserialize;
use typeshare::typeshare;

use crate::app::AppState;
use crate::app::vault::with_unlocked_vault;

#[derive(Deserialize)]
#[typeshare]
pub struct AddCredentialRequest {
    pub vault_key: String,
    pub item_key: String,
    pub credential_title: String,
    pub credential_key: String,
    pub credential_value: String,
}

#[tauri::command]
pub async fn add_credential(
    request: AddCredentialRequest,
    state: tauri::State<'_, Mutex<AppState>>,
) -> Result<(), String> {
    let AddCredentialRequest {
        vault_key,
        item_key,
        credential_title,
        credential_key,
        credential_value,
    } = request;

    with_unlocked_vault(&state, &vault_key, |vw| {
        vw.add_secret(
            "", // item_title is not used when item already exists
            &item_key,
            &credential_title,
            &credential_key,
            credential_value.into(),
        )
        .map_err(|e| format!("Failed to add credential to vault: {e}"))
    })
}
