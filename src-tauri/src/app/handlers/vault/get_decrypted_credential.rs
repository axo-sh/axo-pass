use std::sync::Mutex;

use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::app::AppState;
use crate::app::handlers::app_errors::{AppError, ErrorContext};
use crate::app::handlers::vault::with_unlocked_vault;

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
    pub title: String,
    pub secret: String,
    pub url: String,
}

#[tauri::command]
pub async fn get_decrypted_credential(
    request: DecryptedCredentialRequest,
    state: tauri::State<'_, Mutex<AppState>>,
) -> Result<Option<DecryptedCredential>, AppError> {
    let (secret, title) = with_unlocked_vault(&state, &request.vault_key, |vw| {
        let credential = vw
            .get_secret_overview(&request.item_key, &request.credential_key)?
            .ok_or(AppError::internal("Could not find credential."))?;
        let secret = vw
            .get_secret(&request.item_key, &request.credential_key)
            .error_context("Failed to decrypt secret.")?;
        Ok((secret, credential.title.clone()))
    })?;

    Ok(secret.map(|secret| DecryptedCredential {
        title,
        secret: secret.expose_secret().to_string(),
        url: format!(
            "axo://{}/{}/{}",
            request.vault_key, request.item_key, request.credential_key
        ),
    }))
}
