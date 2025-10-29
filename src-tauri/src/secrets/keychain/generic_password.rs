mod query;

use std::collections::HashMap;
use std::sync::Arc;

use apple_native_keyring_store::protected::{Cred, Store};
use keyring_core::api::CredentialStoreApi;
use secrecy::SecretString;
use serde::Serialize;

use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::generic_password::query::GenericPasswordQuery;
use crate::secrets::keychain::keychain_query::KeyChainQuery;

static SERVICE_NAME: &str = "com.breakfastlabs.frittata";
static REQUIRE_USER_PRESENCE: &str = "RequireUserPresence"; // see also: WhenUnlockedThisDeviceOnly

#[derive(Clone, Serialize)]
pub struct PasswordEntry {
    pub key_id: String,
}

fn get_store() -> Result<Arc<Store>, keyring_core::Error> {
    Store::new().inspect_err(|e| {
        log::debug!("Failed to create store: {e}");
    })
}

pub fn get_all_password_entries() -> Result<Vec<PasswordEntry>, keyring_core::Error> {
    let store = get_store()?;
    let options = HashMap::from([("show-authentication-ui", "true")]);
    let entries: Vec<_> = store
        .search(&options)?
        .into_iter()
        .filter_map(|item| {
            item.as_any()
                .downcast_ref::<Cred>()
                .and_then(|cred| cred.account.strip_prefix("gpg-key-"))
                .map(|key_id| PasswordEntry {
                    key_id: key_id.to_string(),
                })
        })
        .collect();

    log::debug!("Found {} password entries", entries.len());
    Ok(entries)
}

pub fn has_password(key_id: &str) -> Result<bool, KeychainError> {
    log::debug!("Checking if password exists for key_id: {key_id}");
    let account = format!("gpg-key-{key_id}");
    let res = GenericPasswordQuery::build()
        .with_account(&account)
        .without_authentication()
        .one();

    match res {
        Ok(Some(_)) => Ok(true),
        Ok(None) => Ok(false),
        Err(KeychainError::ItemNotAccessible) => Ok(true),
        Err(e) => {
            log::error!("Error checking password existence: {e}");
            Err(anyhow::anyhow!(e).into())
        },
    }
}

pub fn save_password(key_id: &str, password: &str) -> Result<(), keyring_core::Error> {
    log::debug!("Attempting to save password for key_id: {key_id}");
    let account = format!("gpg-key-{}", key_id);

    let mut modifiers = HashMap::new();
    modifiers.insert("access-policy", REQUIRE_USER_PRESENCE);

    let entry = get_store()?.build(SERVICE_NAME, &account, Some(&modifiers))?;

    log::debug!("Setting password for account: {account}");
    entry.set_password(password).inspect_err(|e| {
        log::error!("Failed to set password: {e}");
    })?;
    log::debug!("Password saved successfully to keychain!");
    Ok(())
}

pub fn get_password(key_id: &str) -> Result<Option<SecretString>, KeychainError> {
    log::debug!("Attempting to retrieve password for key_id: {key_id}");
    let account = format!("gpg-key-{key_id}");

    GenericPasswordQuery::build()
        .with_account(&account)
        .one()
        .map(|opt| opt.map(|entry| entry.password))
}
