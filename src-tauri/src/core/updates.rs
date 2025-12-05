use serde::{Deserialize, Serialize};
use tauri_plugin_updater::UpdaterExt;
use time::OffsetDateTime;

use crate::core::config::APP_CONFIG;

#[derive(Serialize, Deserialize, Clone)]
pub struct UpdateCheckRecord {
    #[serde(with = "time::serde::rfc3339")]
    pub checked_at: OffsetDateTime,
    pub result: UpdateCheckResult,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged, rename_all = "snake_case")]
pub enum UpdateCheckResult {
    UpdateAvailable { version: String },
    UpToDate,
    Error { error: String },
}

pub async fn check_for_updates(app_handle: tauri::AppHandle) {
    // Check updates in a block to release the lock early
    if let Ok(config) = APP_CONFIG.lock() {
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
    } else {
        log::warn!("Failed to acquire config lock for update check.");
        return;
    }

    log::debug!("Checking for updates...");
    match app_handle.updater() {
        Ok(updater) => match updater.check().await {
            Ok(Some(update)) => {
                let version = update.version.clone();
                log::info!("Update available: {version}");
                let mut config = APP_CONFIG.lock().unwrap();
                config.record_update_check(UpdateCheckResult::UpdateAvailable { version });
                if let Err(e) = config.save() {
                    log::warn!("Failed to save config after update check: {e}");
                }
            },
            Ok(None) => {
                log::debug!("No updates available");
                let mut config = APP_CONFIG.lock().unwrap();
                config.record_update_check(UpdateCheckResult::UpToDate);
                if let Err(e) = config.save() {
                    log::warn!("Failed to save config after update check: {e}");
                }
            },
            Err(e) => {
                log::warn!("Failed to check for updates: {e}");
                let mut config = APP_CONFIG.lock().unwrap();
                config.record_update_check(UpdateCheckResult::Error {
                    error: e.to_string(),
                });
                if let Err(e) = config.save() {
                    log::warn!("Failed to save config after update check: {e}");
                }
            },
        },
        Err(e) => {
            log::warn!("Failed to get updater: {e}");
            let mut config = APP_CONFIG.lock().unwrap();
            config.record_update_check(UpdateCheckResult::Error {
                error: e.to_string(),
            });
            if let Err(e) = config.save() {
                log::warn!("Failed to save config after update check: {e}");
            }
        },
    }
}
