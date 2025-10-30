use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Serialize;
use tauri::{AppHandle, Manager};

use crate::APP_MODE;
use crate::password_request::{PasswordResponse, RequestEvent};
use crate::pinentry_handler::{GetPinRequest, PinentryState};
use crate::secrets::keychain::generic_password::PasswordEntry;
use crate::secrets::vault::{Vault, init_vault as do_init_vault, read_vault};
use crate::ssh_askpass_handler::{AskPassState, AskPasswordRequest};

// App mode enum
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum AppMode {
    App,
    CLI,
    Pinentry,
    SshAskpass,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum AppModeAndState {
    App {
        pinentry_program_path: Option<PathBuf>,
    },
    Pinentry(Option<RequestEvent<GetPinRequest>>),
    SshAskpass(Option<RequestEvent<AskPasswordRequest>>),
}

#[tauri::command]
pub async fn get_mode(app_handle: AppHandle) -> Result<AppModeAndState, String> {
    let Some(mode) = APP_MODE.get() else {
        return Err("Unknown mode".to_string());
    };

    match mode {
        AppMode::App => {
            let pinentry_program_path = app_handle
                .path()
                .resource_dir()
                .map(|p| p.join("frittata-pinentry"))
                .inspect_err(|e| log::debug!("Failed to get app data directory: {e}"))
                .ok();
            Ok(AppModeAndState::App {
                pinentry_program_path,
            })
        },
        AppMode::Pinentry => {
            let state = app_handle.state::<PinentryState>();
            let pending_event = state.get_pending_event();
            Ok(AppModeAndState::Pinentry(pending_event))
        },
        AppMode::SshAskpass => {
            let state = app_handle.state::<AskPassState>();
            let pending_event = state.get_pending_event();
            Ok(AppModeAndState::SshAskpass(pending_event))
        },
        _ => {
            return Err("Unsupported mode".to_string());
        },
    }
}

#[cfg(debug_assertions)]
#[tauri::command]
pub async fn list_passwords() -> Result<Vec<PasswordEntry>, String> {
    use crate::secrets::keychain::generic_password::PasswordEntryType;
    // no keychain in debug mode because it's not codesigned
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
    Ok(passwords)
}

#[cfg(not(debug_assertions))]
#[tauri::command]
pub async fn list_passwords() -> Result<Vec<PasswordEntry>, String> {
    let passwords = PasswordEntry::list().map_err(|e| format!("Failed to list passwords: {e}"))?;
    Ok(passwords)
}

#[tauri::command(rename_all = "snake_case")]
pub async fn send_pinentry_response(
    response: PasswordResponse,
    state: tauri::State<'_, PinentryState>,
) -> Result<(), String> {
    if let Some(sender) = state.take_response_sender() {
        sender
            .send(response)
            .map_err(|_| "Failed to send response".to_string())?;
    }
    Ok(())
}

#[tauri::command(rename_all = "snake_case")]
pub async fn send_askpass_response(
    response: PasswordResponse,
    state: tauri::State<'_, AskPassState>,
) -> Result<(), String> {
    if let Some(sender) = state.take_response_sender() {
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
