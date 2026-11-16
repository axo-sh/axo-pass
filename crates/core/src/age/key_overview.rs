//! A unified view of the age identities held in the keychain.
//!
//! Each identity is stored as a `PasswordEntry` of type `AgeKey`, keyed by the
//! user-facing name. The public recipient is derived from the secret on read,
//! so listing identities reads each entry on an auth context.

use std::str::FromStr;

use secrecy::ExposeSecret;

use crate::age::errors::AgeError;
use crate::core::auth::AuthContext;
use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::generic_password::{PasswordEntry, PasswordEntryType};

/// One age identity: its name and its `age1...` recipient. Only identities
/// whose secret is in the keychain are listed, so there is no public-only case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgeKeyOverview {
    pub name: String,
    pub recipient: String,
}

/// List every age identity in the keychain, newest name order.
///
/// Reads each entry's secret to derive its recipient on the shared auth
/// context, the same as reading a vault item. This never prompts. It fails if
/// the app is locked.
pub fn list_age_keys() -> Result<Vec<AgeKeyOverview>, AgeError> {
    list_age_keys_on(AuthContext::SharedThreadLocal)
        .map_err(|e| AgeError::FailedToRetrieveRecipient("age key list".to_owned(), e))
}

/// [`list_age_keys`] on a specific [`AuthContext`]. The app broker passes
/// [`AuthContext::Foreign`] if the app is locked, so the app that owns the
/// context draws the prompt. The listing authenticates the context, so the
/// reads of each secret that follow add no prompt.
pub fn list_age_keys_on(context: AuthContext) -> Result<Vec<AgeKeyOverview>, KeychainError> {
    let entries = PasswordEntry::list_on(context.clone())?;

    let mut keys: Vec<AgeKeyOverview> = Vec::new();
    for entry in entries {
        if !matches!(entry.password_type, PasswordEntryType::AgeKey) {
            continue;
        }
        let name = entry.key_id.clone();
        match entry.get_password_on(context.clone(), None) {
            Ok(Some(pwd)) => match age::x25519::Identity::from_str(pwd.expose_secret()) {
                Ok(identity) => keys.push(AgeKeyOverview {
                    name,
                    recipient: identity.to_public().to_string(),
                }),
                Err(e) => log::warn!("age key {name}: cannot parse identity: {e}"),
            },
            Ok(None) => log::warn!("age key {name}: no secret in keychain"),
            Err(e) => log::warn!("age key {name}: {e}"),
        }
    }

    keys.sort_by_key(|a| a.name.to_lowercase());
    Ok(keys)
}
