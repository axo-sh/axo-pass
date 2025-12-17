use std::path::PathBuf;

use serde::Serialize;
use tauri::{AppHandle, Manager};
use tauri_utils::platform::current_exe;

use crate::app::password_request::RequestEvent;
use crate::app::protocols::pinentry::{GpgGetPinRequest, PinentryState};
use crate::app::protocols::ssh_askpass::{AskPassState, SshAskPassRequest};

// App mode enum
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum AppMode {
    App,
    Pinentry,
    SshAskpass,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum AppModeAndState {
    App { helper_bin_path: Option<PathBuf> },
    GpgPinentry(Option<RequestEvent<GpgGetPinRequest>>),
    SshAskpass(Option<RequestEvent<SshAskPassRequest>>),
}

#[tauri::command]
pub async fn get_mode(
    app_handle: AppHandle,
    app_mode: tauri::State<'_, AppMode>,
) -> Result<AppModeAndState, String> {
    match &*app_mode {
        AppMode::App => {
            let helper_bin_path = current_exe()
                .inspect_err(|e| log::debug!("Failed to get app directory: {e}"))
                .ok()
                .and_then(|p| p.parent().map(|parent| parent.to_path_buf()));

            Ok(AppModeAndState::App { helper_bin_path })
        },
        AppMode::Pinentry => {
            let state = app_handle.state::<PinentryState>();
            let pending_event = state.get_pending_event();
            Ok(AppModeAndState::GpgPinentry(pending_event))
        },
        AppMode::SshAskpass => {
            let state = app_handle.state::<AskPassState>();
            let pending_event = state.get_pending_event();
            Ok(AppModeAndState::SshAskpass(pending_event))
        },
    }
}
