use std::collections::BTreeMap;
use std::sync::Mutex;

use secrecy::SecretString;
use serde::Deserialize;
use typeshare::typeshare;

use crate::app::AppState;
use crate::secrets::vaults::VaultWrapper;

#[derive(Deserialize)]
#[typeshare]
pub struct CredentialUpdate {
    pub title: Option<String>,
    pub value: Option<String>,
}

#[derive(Deserialize)]
#[typeshare]

pub struct UpdateItemRequest {
    pub vault_key: String,
    pub item_key: String,
    pub item_title: String,
    #[typeshare(serialized_as = "HashMap<String, CredentialUpdate>")]
    pub credentials: BTreeMap<String, CredentialUpdate>,
}

#[tauri::command]
pub async fn update_item(
    request: UpdateItemRequest,
    state: tauri::State<'_, Mutex<AppState>>,
) -> Result<(), String> {
    let UpdateItemRequest {
        vault_key,
        item_key,
        item_title,
        credentials,
    } = request;

    let mut state = state
        .lock()
        .map_err(|e| format!("Failed to lock app state: {e}"))?;
    let vw: &mut VaultWrapper = state
        .vaults
        .get_vault_mut(&vault_key)
        .map_err(|e| format!("Failed to get vault: {e}"))?;

    let credentials_with_secrets: BTreeMap<String, (Option<String>, Option<SecretString>)> =
        credentials
            .into_iter()
            .map(|(key, cred)| {
                let secret_value = cred.value.map(|v| v.into());
                (key, (cred.title, secret_value))
            })
            .collect();

    vw.update_item(&item_key, item_title, credentials_with_secrets)
        .map_err(|e| format!("Failed to update item in vault: {e}"))?;
    vw.save()
        .map_err(|e| format!("Failed to save vault: {e}"))?;
    Ok(())
}
