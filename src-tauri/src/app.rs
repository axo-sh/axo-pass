use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Serialize;
use tauri::{AppHandle, Manager};

use crate::APP_MODE;
use crate::pinentry_handler::{PinentryState, UserPinentryResponse};
use crate::secrets::keychain::generic_password::{PasswordEntry, PasswordEntryType};
use crate::secrets::vault::{Vault, init_vault as do_init_vault, read_vault};

// App mode enum
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "lowercase")]
pub enum AppMode {
    App(AppState),
    Pinentry,
}

impl AppMode {
    pub fn is_pinentry(&self) -> bool {
        matches!(self, AppMode::Pinentry)
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct AppState {
    pub pinentry_program_path: Option<PathBuf>,
}

#[tauri::command]
pub async fn get_mode() -> Result<AppMode, String> {
    APP_MODE
        .get()
        .cloned()
        .ok_or_else(|| "App mode not set".to_string())
}

#[tauri::command]
pub async fn list_passwords() -> Result<Vec<PasswordEntry>, String> {
    // no keychain in debug mode because it's not codesigned
    #[cfg(debug_assertions)]
    let passwords = vec![
        PasswordEntry {
            password_type: PasswordEntryType::GPGKey,
            key_id: "test-key-1".to_string(),
        },
        PasswordEntry {
            password_type: PasswordEntryType::GPGKey,
            key_id: "test-key-2".to_string(),
        },
        PasswordEntry {
            password_type: PasswordEntryType::GPGKey,
            key_id: "test-key-3".to_string(),
        },
    ];

    #[cfg(not(debug_assertions))]
    let passwords = PasswordEntry::list().map_err(|e| format!("Failed to list passwords: {e}"))?;

    Ok(passwords)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn send_pinentry_response(
    response: UserPinentryResponse,
    state: tauri::State<'_, PinentryState>,
) -> Result<(), String> {
    let sender = state.response_sender.lock().unwrap().take();
    if let Some(sender) = sender {
        sender
            .send(response)
            .map_err(|_| "Failed to send response".to_string())?;
    }
    Ok(())
}

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
