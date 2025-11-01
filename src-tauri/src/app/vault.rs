use std::collections::BTreeMap;

use serde::Serialize;
use tauri::{AppHandle, Manager};

use crate::secrets::vault::{Vault, init_vault as do_init_vault, read_vault};

// safe view for vaults
#[derive(Serialize, Debug, Clone)]
pub struct VaultView {
    title: Option<String>,
    data: BTreeMap<String, VaultItemView>,
}

impl From<Vault> for VaultView {
    fn from(vault: Vault) -> Self {
        VaultView {
            title: vault.title,
            data: vault
                .data
                .iter()
                .map(|(key, item)| {
                    (
                        key.clone(),
                        VaultItemView {
                            id: item.id,
                            title: item.title.clone(),
                            credentials: item
                                .credentials
                                .iter()
                                .map(|(cred_key, cred)| {
                                    (
                                        cred_key.clone(),
                                        VaultItemCredentialView {
                                            title: cred.title.clone(),
                                        },
                                    )
                                })
                                .collect(),
                        },
                    )
                })
                .collect(),
        }
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct VaultItemView {
    id: uuid::Uuid,
    title: String,
    credentials: BTreeMap<String, VaultItemCredentialView>,
}

#[derive(Serialize, Debug, Clone)]
pub struct VaultItemCredentialView {
    title: Option<String>,
}

#[tauri::command(rename_all = "snake_case")]
pub async fn init_vault(app: AppHandle) -> Result<VaultView, String> {
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to get app data directory: {e}"))?;
    let vault =
        do_init_vault(&app_data_dir).map_err(|e| format!("Failed to initialize vault: {e}"))?;
    Ok(vault.into())
}

#[tauri::command(rename_all = "snake_case")]
pub async fn get_vault(app: AppHandle) -> Result<VaultView, String> {
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to get app data directory: {e}"))?;
    log::debug!("Reading vault from app data dir: {:?}", app_data_dir);
    let vault = read_vault(&app_data_dir, None).map_err(|e| {
        log::error!("Error reading vault: {:?}", e);
        format!("Failed to read vault: {e}")
    })?;
    Ok(vault.into())
}
