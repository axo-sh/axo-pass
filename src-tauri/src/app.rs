use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::AppHandle;
use tokio::sync::oneshot;

use crate::APP_MODE;
use crate::keychain::PasswordEntry;
use crate::pinentry_handler::{PinentryRequest, UserPinentryResponse};

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
            key_id: "test-key-1".to_string(),
        },
        PasswordEntry {
            key_id: "test-key-2".to_string(),
        },
        PasswordEntry {
            key_id: "test-key-3".to_string(),
        },
    ];

    #[cfg(not(debug_assertions))]
    let passwords = crate::keychain::get_all_password_entries()
        .map_err(|e| format!("Failed to list passwords: {e}"))?
        .into_iter()
        .collect();
    Ok(passwords)
}

// Shared state for pinentry requests
#[derive(Default, Clone)]
pub struct PinentryState {
    pub pending_request: Arc<Mutex<Option<PinentryRequest>>>,
    pub response_sender: Arc<Mutex<Option<oneshot::Sender<UserPinentryResponse>>>>,
    pub app_handle: Arc<Mutex<Option<AppHandle>>>,
}

impl PinentryState {
    pub fn set_app_handle(&self, handle: AppHandle) {
        *self.app_handle.lock().unwrap() = Some(handle);
    }
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
