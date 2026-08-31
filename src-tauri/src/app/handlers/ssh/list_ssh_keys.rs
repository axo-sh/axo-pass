use serde::Serialize;
use typeshare::typeshare;

use crate::app::handlers::app_errors::{AppError, ErrorContext};
use crate::app::handlers::ssh::schema::ssh_key_entry::SshKeyEntry;
use axo_pass_core::ssh::key_overview::list_all_ssh_keys;

#[derive(Debug, Clone, Serialize)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub struct ListSshKeysResponse {
    pub keys: Vec<SshKeyEntry>,
}

#[tauri::command]
pub async fn list_ssh_keys() -> Result<ListSshKeysResponse, AppError> {
    let overviews = list_all_ssh_keys()
        .await
        .error_context("Failed to list SSH keys")?;
    Ok(ListSshKeysResponse {
        keys: overviews.into_iter().map(SshKeyEntry::from).collect(),
    })
}
