use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::Manager;
use tauri_plugin_updater::UpdaterExt;
use time::OffsetDateTime;

use crate::app::app_state::AppState;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged, rename_all = "snake_case")]
pub enum UpdateCheckResult {
    UpdateAvailable { version: String },
    UpToDate,
    Error { error: String },
}

#[derive(Serialize, Deserialize, Clone)]
pub struct UpdateCheckRecord {
    #[serde(with = "time::serde::rfc3339")]
    pub checked_at: OffsetDateTime,
    pub result: UpdateCheckResult,
}

pub async fn check_for_updates(app_handle: tauri::AppHandle) {
    let state = app_handle.state::<Mutex<AppState>>();
    let config = &state.lock().unwrap().config.clone();
    if config.update_check_disabled.unwrap_or(false) {
        log::debug!("Skipping update check: Update checks are disabled.");
        return;
    }

    if let Some(ref updates) = config.updates
        && updates.checked_at.date() == OffsetDateTime::now_utc().date()
    {
        log::debug!("Skipping update check: Already checked today.");
        if let UpdateCheckResult::UpdateAvailable { version } = &updates.result {
            log::info!("Update available (cached): {version}");
        }
        return;
    }

    log::debug!("Checking for updates...");
    match app_handle.updater() {
        Ok(updater) => match updater.check().await {
            Ok(Some(update)) => {
                let version = update.version.clone();
                log::info!("Update available: {version}");
                let mut state = state.lock().unwrap();
                state
                    .config
                    .record_update_check(UpdateCheckResult::UpdateAvailable { version });
                if let Err(e) = state.config.save() {
                    log::warn!("Failed to save config after update check: {e}");
                }
            },
            Ok(None) => {
                log::debug!("No updates available");
                let mut state = state.lock().unwrap();
                state
                    .config
                    .record_update_check(UpdateCheckResult::UpToDate);
                if let Err(e) = state.config.save() {
                    log::warn!("Failed to save config after update check: {e}");
                }
            },
            Err(e) => {
                log::warn!("Failed to check for updates: {e}");
                let mut state = state.lock().unwrap();
                state.config.record_update_check(UpdateCheckResult::Error {
                    error: e.to_string(),
                });
                if let Err(e) = state.config.save() {
                    log::warn!("Failed to save config after update check: {e}");
                }
            },
        },
        Err(e) => {
            let mut state = state.lock().unwrap();
            log::warn!("Failed to get updater: {e}");
            state.config.record_update_check(UpdateCheckResult::Error {
                error: e.to_string(),
            });
            if let Err(e) = state.config.save() {
                log::warn!("Failed to save config after update check: {e}");
            }
        },
    }
}
