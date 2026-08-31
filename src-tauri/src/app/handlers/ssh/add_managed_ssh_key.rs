use serde::Serialize;
use typeshare::typeshare;

use crate::app::handlers::app_errors::AppError;
use crate::app::handlers::ssh::schema::ssh_key_entry::SshKeyEntry;
use axo_pass_core::secrets::keychain::managed_key::ManagedSshKey;

#[derive(Debug, Clone, Serialize)]
#[typeshare]
pub struct AddManagedSshKeyResponse {
    pub key: SshKeyEntry,
}

#[tauri::command]
pub async fn add_managed_ssh_key() -> Result<AddManagedSshKeyResponse, AppError> {
    // todo: support managed ssh key aliases
    let managed_key = ManagedSshKey::create().await?;
    let overview: axo_pass_core::ssh::key_overview::SshKeyOverview = managed_key.into();
    Ok(AddManagedSshKeyResponse {
        key: overview.into(),
    })
}
