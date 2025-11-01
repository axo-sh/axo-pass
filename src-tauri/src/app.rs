pub mod passwords;
pub mod user_authorization;
pub mod vault;

use std::path::PathBuf;

use serde::Serialize;
use tauri::{AppHandle, Manager};

use crate::APP_MODE;
use crate::password_request::RequestEvent;
use crate::pinentry_handler::{GetPinRequest, PinentryState};
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
        _ => Err("Unsupported mode".to_string()),
    }
}
