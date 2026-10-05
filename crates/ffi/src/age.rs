use axo_pass_core::age::key_overview::{AgeKeyOverview, list_age_keys};
use axo_pass_core::age::recipients::{delete_recipient as delete_age_recipient, generate_age_key};

use crate::*;

#[derive(uniffi::Record, Clone)]
pub struct AgeKeyEntry {
    /// The user-facing name, and the keychain entry's key.
    pub name: String,
    /// The `age1...` public recipient, derived from the secret.
    pub recipient: String,
}

impl From<AgeKeyOverview> for AgeKeyEntry {
    fn from(o: AgeKeyOverview) -> Self {
        AgeKeyEntry {
            name: o.name,
            recipient: o.recipient,
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl AxoPass {
    /// List the age identities held in the keychain. Derives each recipient
    /// from its secret, so this reads every entry on the shared auth context.
    pub async fn list_age_keys(&self) -> Result<Vec<AgeKeyEntry>, FfiError> {
        tokio::task::spawn_blocking(list_age_keys)
            .await
            .map_err(|e| FfiError::Internal(e.to_string()))?
            .map_err(FfiError::from)
            .map(|keys| keys.into_iter().map(AgeKeyEntry::from).collect())
    }

    /// Generate a new x25519 age identity, save it under `name`, and record an
    /// `age.key_create` audit event.
    pub async fn generate_age_key(&self, name: String) -> Result<AgeKeyEntry, FfiError> {
        tokio::task::spawn_blocking(move || generate_age_key(&name, None))
            .await
            .map_err(|e| FfiError::Internal(e.to_string()))?
            .map_err(FfiError::from)
            .map(AgeKeyEntry::from)
    }

    /// Delete an age identity from the keychain, recording an `age.key_delete`
    /// audit event.
    pub async fn delete_age_key(&self, name: String) -> Result<(), FfiError> {
        tokio::task::spawn_blocking(move || delete_age_recipient(&name, None))
            .await
            .map_err(|e| FfiError::Internal(e.to_string()))?
            .map_err(FfiError::from)
    }
}
