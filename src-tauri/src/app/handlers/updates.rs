use serde::Serialize;
use tauri_plugin_updater::UpdaterExt;
use time::format_description::well_known;
use time::{Duration, OffsetDateTime};
use typeshare::typeshare;

use axo_pass_core::core::config::APP_CONFIG;
use axo_pass_core::core::updates::{UpdateCheckRecord, UpdateCheckResult};

#[derive(Serialize, Debug)]
#[serde(tag = "status", content = "data", rename_all = "snake_case")]
#[typeshare]
pub enum UpdateStatusResponse {
    UpdateAvailable {
        version: String,
        checked_at_rfc3339: String,
    },
    UpToDate {
        version: String,
        checked_at_rfc3339: String,
    },
    Error {
        error: String,
        checked_at_rfc3339: String,
    },
    NotChecked,
}

impl From<Option<&UpdateCheckRecord>> for UpdateStatusResponse {
    fn from(record: Option<&UpdateCheckRecord>) -> Self {
        match record {
            Some(record) => {
                let checked_at_rfc3339 = record
                    .checked_at
                    .format(&well_known::Rfc3339)
                    .unwrap_or_default();
                match &record.result {
                    UpdateCheckResult::UpdateAvailable { version } => {
                        UpdateStatusResponse::UpdateAvailable {
                            version: version.clone(),
                            checked_at_rfc3339,
                        }
                    },
                    UpdateCheckResult::UpToDate {} => UpdateStatusResponse::UpToDate {
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        checked_at_rfc3339,
                    },
                    UpdateCheckResult::Error { error } => UpdateStatusResponse::Error {
                        error: error.clone(),
                        checked_at_rfc3339,
                    },
                }
            },
            None => UpdateStatusResponse::NotChecked,
        }
    }
}

#[tauri::command]
pub async fn check_updates(app_handle: tauri::AppHandle) -> Result<UpdateStatusResponse, String> {
    check_for_updates(app_handle, true).await;
    get_update_status().await
}

#[tauri::command]
pub async fn get_update_status() -> Result<UpdateStatusResponse, String> {
    let config = APP_CONFIG
        .lock()
        .map_err(|e| format!("Failed to acquire config lock: {e}"))?;
    Ok(UpdateStatusResponse::from(config.updates.as_ref()))
}

#[derive(Serialize, Debug)]
#[typeshare]
pub struct UpdateCheckDisabledStatusResponse {
    pub disabled: bool,
}

#[tauri::command]
pub async fn get_update_check_disabled() -> Result<UpdateCheckDisabledStatusResponse, String> {
    let config = APP_CONFIG
        .lock()
        .map_err(|e| format!("Failed to acquire config lock: {e}"))?;
    Ok(UpdateCheckDisabledStatusResponse {
        disabled: config.update_check_disabled.unwrap_or(false),
    })
}

#[tauri::command]
pub async fn set_update_check_disabled(disabled: bool) -> Result<(), String> {
    log::debug!("command: set_update_check_disabled={disabled}");
    let mut config = APP_CONFIG
        .lock()
        .map_err(|e| format!("Failed to acquire config lock: {e}"))?;
    config.update_check_disabled = Some(disabled);
    config
        .save()
        .map_err(|e| format!("Failed to save config: {e}"))?;
    Ok(())
}

pub async fn check_for_updates(app_handle: tauri::AppHandle, force: bool) {
    // Check updates in a block to release the lock early
    let now = OffsetDateTime::now_utc();
    if force {
        if let Ok(config) = APP_CONFIG.lock()
            && let Some(ref updates) = config.updates
            && now - updates.checked_at < Duration::minutes(5)
        {
            log::debug!("Skipping update check: too soon after last check.");
            return;
        }
    } else if let Ok(config) = APP_CONFIG.lock() {
        if config.update_check_disabled.unwrap_or(false) {
            log::debug!("Skipping update check: Update checks are disabled.");
        }
        if let Some(ref updates) = config.updates
            && updates.checked_at.date() == now.date()
        {
            log::debug!("Skipping update check: Already checked today.");
            if let UpdateCheckResult::UpdateAvailable { version } = &updates.result {
                println!("Update available (cached): {version}");
            }
        }
        return;
    } else {
        log::warn!("Failed to acquire config lock for update check.");
        return;
    }

    log::debug!("Checking for updates...");
    match app_handle.updater() {
        Ok(updater) => match updater.check().await {
            Ok(Some(update)) => {
                let version = update.version.clone();
                println!("Update available: {version}");
                let mut config = APP_CONFIG.lock().unwrap();
                config.record_update_check(UpdateCheckResult::UpdateAvailable { version });
                if let Err(e) = config.save() {
                    eprintln!("Failed to save config after update check: {e}");
                }
            },
            Ok(None) => {
                eprintln!("No updates available");
                let mut config = APP_CONFIG.lock().unwrap();
                config.record_update_check(UpdateCheckResult::UpToDate {});
                if let Err(e) = config.save() {
                    eprintln!("Failed to save config after update check: {e}");
                }
            },
            Err(e) => {
                eprintln!("Failed to check for updates: {e}");
                let mut config = APP_CONFIG.lock().unwrap();
                config.record_update_check(UpdateCheckResult::Error {
                    error: e.to_string(),
                });
                if let Err(e) = config.save() {
                    eprintln!("Failed to save config after update check: {e}");
                }
            },
        },
        Err(e) => {
            eprintln!("Failed to get updater: {e}");
            let mut config = APP_CONFIG.lock().unwrap();
            config.record_update_check(UpdateCheckResult::Error {
                error: e.to_string(),
            });
            if let Err(e) = config.save() {
                eprintln!("Failed to save config after update check: {e}");
            }
        },
    }
}
