use serde::Serialize;
use typeshare::typeshare;

use crate::cli::shell_integration;

#[derive(Serialize, Debug)]
#[typeshare]
pub struct ShellIntegrationStatus {
    pub configured: bool,
    pub zshrc_path: String,
}

#[tauri::command]
pub async fn get_shell_integration_status() -> ShellIntegrationStatus {
    let (configured, path) = shell_integration::check_status();
    ShellIntegrationStatus {
        configured,
        zshrc_path: path.to_string_lossy().to_string(),
    }
}

#[tauri::command]
pub async fn configure_shell_integration() -> Result<ShellIntegrationStatus, String> {
    let path = shell_integration::write_integration()?;
    Ok(ShellIntegrationStatus {
        configured: true,
        zshrc_path: path.to_string_lossy().to_string(),
    })
}
