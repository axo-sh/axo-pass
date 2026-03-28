use serde::Serialize;
use typeshare::typeshare;

use crate::app::handlers::app_errors::AppError;
use crate::app::handlers::ssh::schema::ssh_key_entry::SshKeyEntry;
use crate::secrets::keychain::managed_key::ManagedSshKey;

#[derive(Debug, Clone, Serialize)]
#[typeshare]
pub struct AddManagedSshKeyResponse {
    pub key: SshKeyEntry,
}

#[tauri::command]
pub async fn add_managed_ssh_key() -> Result<AddManagedSshKeyResponse, AppError> {
    // todo: support managed ssh key aliases
    let managed_key = ManagedSshKey::create().await?;
    Ok(AddManagedSshKeyResponse {
        key: managed_key.into(),
    })
}
