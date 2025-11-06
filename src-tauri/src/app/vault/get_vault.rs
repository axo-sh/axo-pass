use std::sync::Mutex;

use serde::Serialize;
use tauri::{AppHandle, Manager};
use typeshare::typeshare;

use crate::app::AppState;
use crate::app::vault::schemas::VaultSchema;
use crate::secrets::vault_wrapper::{DEFAULT_VAULT, VaultWrapper, get_vault_encryption_key};

#[derive(Serialize)]
#[typeshare]
pub struct VaultResponse {
    pub vault: VaultSchema,
}

#[tauri::command]
pub async fn init_vault(app: AppHandle) -> Result<VaultResponse, String> {
    log::debug!("command: init_vault with test values");
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to get app data directory: {e}"))?;
    let user_encryption_key = get_vault_encryption_key()
        .map_err(|e| format!("Failed to get vault encryption key: {e}"))?;

    let mut vw = VaultWrapper::new_vault(&app_data_dir, DEFAULT_VAULT, user_encryption_key)
        .map_err(|e| format!("Failed to create new vault: {e}",))?;

    log::debug!("Vault created, saving new vault to disk...");
    vw.add_secret(
        "test item",
        Some("test_item"),
        "cred item",
        "cred_item",
        "super-secret-value".into(),
    )
    .map_err(|e| format!("Failed to add test secret to vault: {e}"))?;
    vw.save()
        .map_err(|e| format!("Failed to save vault: {e}"))?;
    Ok(VaultResponse {
        vault: (&vw).into(),
    })
}

#[tauri::command]
pub async fn get_vault(state: tauri::State<'_, Mutex<AppState>>) -> Result<VaultResponse, String> {
    log::debug!("command: get_vault");
    let mut state = state
        .lock()
        .map_err(|e| format!("Failed to lock app state: {e}"))?;
    let vw: &VaultWrapper = state
        .get_vault(DEFAULT_VAULT)
        .map_err(|e| format!("Failed to get vault: {e}"))?;
    Ok(VaultResponse { vault: vw.into() })
}
