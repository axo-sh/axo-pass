use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::app::AppState;
use crate::app::handlers::app_errors::{AppError, ErrorContext};
use crate::app::handlers::vault::schemas::VaultSchema;
use crate::app::handlers::vault::with_unlocked_vault;
use crate::secrets::vaults::DEFAULT_VAULT;

#[derive(Deserialize)]
#[typeshare]
pub struct GetVaultRequest {
    vault_key: Option<String>,
}

#[derive(Serialize)]
#[typeshare]
pub struct VaultResponse {
    pub vault: VaultSchema,
}

#[tauri::command]
pub async fn get_vault(
    request: GetVaultRequest,
    state: tauri::State<'_, Mutex<AppState>>,
) -> Result<VaultResponse, AppError> {
    log::debug!("command: get_vault");
    let vault_key = request
        .vault_key
        .unwrap_or_else(|| DEFAULT_VAULT.to_string());
    let schema = with_unlocked_vault(&state, &vault_key, |vw| {
        vw.to_schema()
            .error_context("Failed to build vault schema.")
    })?;
    Ok(VaultResponse { vault: schema })
}

#[derive(Serialize)]
#[typeshare]
pub struct VaultInfo {
    pub name: Option<String>,
    pub key: String,
}

#[derive(Serialize)]
#[typeshare]
pub struct ListVaultsResponse {
    pub vaults: Vec<VaultInfo>,
}

#[tauri::command]
pub async fn list_vaults(
    state: tauri::State<'_, Mutex<AppState>>,
) -> Result<ListVaultsResponse, AppError> {
    log::debug!("command: list_vaults");
    let mut state = state.lock()?;

    let vault_keys: Vec<String> = state.vaults.iter_vault_keys().collect();
    let mut vaults: Vec<VaultInfo> = vault_keys
        .iter()
        .map(|k| VaultInfo {
            name: state
                .vaults
                .get_vault(k.as_str())
                .ok()
                .and_then(|vw| vw.vault_name().map(|s| s.to_string())),
            key: k.to_string(),
        })
        .collect();

    vaults.sort_by_cached_key(|v| v.name.clone().unwrap_or_else(|| v.key.clone()));
    Ok(ListVaultsResponse { vaults })
}
