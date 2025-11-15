use serde::Serialize;
use tauri_utils::platform::current_exe;
use typeshare::typeshare;

#[derive(Serialize, Debug)]
#[typeshare]
pub struct AppSettingsResponse {
    helper_bin_path: Option<String>,
}

#[tauri::command]
pub async fn get_app_settings() -> Result<AppSettingsResponse, String> {
    let helper_bin_path = current_exe()
        .inspect_err(|e| log::debug!("Failed to get app directory: {e}"))
        .ok()
        .and_then(|p| {
            p.parent()
                .and_then(|p| p.parent())
                .map(|parent| parent.to_string_lossy().to_string())
        });

    Ok(AppSettingsResponse { helper_bin_path })
}
