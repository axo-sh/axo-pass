use serde::Serialize;
use time::format_description::well_known;
use typeshare::typeshare;

use crate::core::config::APP_CONFIG;
use crate::core::updates::{UpdateCheckRecord, UpdateCheckResult, check_for_updates};

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
                    UpdateCheckResult::UpToDate => UpdateStatusResponse::UpToDate {
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
