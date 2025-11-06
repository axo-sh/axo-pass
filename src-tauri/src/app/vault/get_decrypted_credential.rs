use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::app::AppState;
use crate::app::vault::with_unlocked_vault;

#[typeshare]
#[derive(Deserialize, Debug)]
pub struct DecryptedCredentialRequest {
    pub vault_key: String,
    pub item_key: String,
    pub credential_key: String,
}

#[derive(Serialize)]
#[typeshare]
pub struct DecryptedCredential {
    pub title: Option<String>,
    pub secret: String,
    pub url: String,
}

#[tauri::command]
pub async fn get_decrypted_credential(
    request: DecryptedCredentialRequest,
    state: tauri::State<'_, Mutex<AppState>>,
) -> Result<Option<DecryptedCredential>, String> {
    let (secret, title) = with_unlocked_vault(&state, &request.vault_key, |vw| {
        let credential = vw
            .get_item_credential(&request.item_key, &request.credential_key)
            .map_err(|e| format!("Failed to get credential: {e}"))?
            .ok_or("Could not find credential.".to_string())?;
        let secret = vw
            .get_secret(&request.item_key, &request.credential_key)
            .map_err(|e| format!("Failed to decrypt secret: {e}"))?;
        Ok((secret, credential.title.clone()))
    })?;

    Ok(secret.map(|secret| DecryptedCredential {
        title,
        secret,
        url: format!(
            "axo://{}/{}/{}",
            request.vault_key, request.item_key, request.credential_key
        ),
    }))
}
