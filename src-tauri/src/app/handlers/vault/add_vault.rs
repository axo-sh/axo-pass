use std::sync::Mutex;

use serde::Deserialize;
use typeshare::typeshare;

use crate::app::AppState;
use crate::app::handlers::app_errors::{AppError, ErrorContext};
use crate::app::handlers::vault::get_vault::VaultResponse;

#[derive(Deserialize)]
#[typeshare]
pub struct NewVaultRequest {
    vault_name: Option<String>,
    vault_key: String,
}

#[tauri::command]
pub async fn add_vault(
    request: NewVaultRequest,
    state: tauri::State<'_, Mutex<AppState>>,
) -> Result<VaultResponse, AppError> {
    log::debug!("command: add_vault");
    let mut state = state.lock()?;
    let vw = state
        .vaults
        .add_vault(request.vault_name, &request.vault_key)
        .error_context("Failed to create new vault.")?;
    let schema = vw
        .to_schema()
        .error_context("Failed to build vault schema.")?;
    Ok(VaultResponse { vault: schema })
}
