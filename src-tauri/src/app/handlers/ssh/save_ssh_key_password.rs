use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::app::handlers::app_errors::{AppError, ErrorContext};
use crate::secrets::keychain::generic_password::PasswordEntry;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub struct SaveSshKeyPasswordRequest {
    pub fingerprint: String,
    pub password: String,
}

#[tauri::command]
pub async fn save_ssh_key_password(request: SaveSshKeyPasswordRequest) -> Result<(), AppError> {
    let entry = PasswordEntry::ssh(&request.fingerprint);

    // Check if password already exists
    if entry.exists()? {
        return Err(AppError::internal("Password already exists for this key"));
    }

    let password = SecretString::from(request.password);
    entry
        .save_password(password)
        .error_context("Failed to save password")?;

    log::info!(
        "Saved password for SSH key with fingerprint: {}",
        request.fingerprint
    );
    Ok(())
}
