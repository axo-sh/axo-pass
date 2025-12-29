use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::secrets::keychain::generic_password::PasswordEntry;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub struct SaveSshKeyPasswordRequest {
    pub fingerprint: String,
    pub password: String,
}

#[tauri::command]
pub async fn save_ssh_key_password(request: SaveSshKeyPasswordRequest) -> Result<(), String> {
    let entry = PasswordEntry::ssh(&request.fingerprint);

    // Check if password already exists
    if entry
        .exists()
        .map_err(|e| format!("Failed to check existing password: {e}"))?
    {
        return Err("Password already exists for this key".to_string());
    }

    let password = SecretString::from(request.password);
    entry
        .save_password(password)
        .map_err(|e| format!("Failed to save password: {e}"))?;

    log::info!(
        "Saved password for SSH key with fingerprint: {}",
        request.fingerprint
    );
    Ok(())
}
