use std::collections::BTreeMap;
use std::sync::Mutex;

use serde::Serialize;
use tauri::{AppHandle, Manager};

use crate::app::AppState;
use crate::secrets::vault::{DEFAULT_VAULT, Vault, VaultItem, init_vault as do_init_vault};

// safe view for vaults
#[derive(Serialize, Debug, Clone)]
pub struct VaultView {
    key: String,
    title: Option<String>,
    data: BTreeMap<String, VaultItemView>,
}

impl From<&Vault> for VaultView {
    fn from(vault: &Vault) -> Self {
        VaultView {
            key: vault.key.clone(),
            title: vault.title.clone(),
            data: vault
                .data
                .iter()
                .map(|(key, item)| (key.clone(), item.into()))
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

impl From<&VaultItem> for VaultItemView {
    fn from(item: &VaultItem) -> Self {
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
                            id: cred.id,
                            title: cred.title.clone(),
                        },
                    )
                })
                .collect(),
        }
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct VaultItemCredentialView {
    id: uuid::Uuid,
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
    Ok((&vault).into())
}

#[tauri::command(rename_all = "snake_case")]
pub async fn get_vault(state: tauri::State<'_, Mutex<AppState>>) -> Result<VaultView, String> {
    let mut state = state
        .lock()
        .map_err(|e| format!("Failed to lock app state: {e}"))?;
    let vault: &Vault = state
        .get_vault_mut(DEFAULT_VAULT)
        .map_err(|e| format!("Failed to get vault: {e}"))?;
    Ok(vault.into())
}

#[derive(Serialize)]
pub struct DecryptedCredential {
    pub title: Option<String>,
    pub secret: String,
    pub url: String,
}

#[tauri::command(rename_all = "snake_case")]
pub async fn get_decrypted_vault_item_credential(
    vault_key: String,
    item_key: String,
    credential_key: String,
    state: tauri::State<'_, Mutex<AppState>>,
) -> Result<Option<DecryptedCredential>, String> {
    let cred_path = format!("{vault_key}/{item_key}/{credential_key}");
    let mut state = state
        .lock()
        .map_err(|e| format!("Failed to lock app state: {e}"))?;
    let vault: &mut Vault = state
        .get_vault_mut(&vault_key)
        .map_err(|e| format!("Failed to get vault: {e}"))?;
    let item = vault
        .data
        .get(&item_key)
        .ok_or_else(|| format!("Item {vault_key}/{item_key} not found."))?;

    let credential = item
        .credentials
        .get(&credential_key)
        .ok_or_else(|| format!("Credential {cred_path} not found"))?;
    let title = credential.title.clone();

    vault
        .unlock()
        .map_err(|e| format!("Failed to unlock vault: {e}"))?;
    let secret = vault
        .get_secret(&item_key, &credential_key)
        .map_err(|e| format!("Failed to get secret for {cred_path}: {e}"))?;
    Ok(secret.map(|secret| DecryptedCredential {
        title,
        secret,
        url: format!("axo://{cred_path}"),
    }))
}
