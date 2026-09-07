//! A unified view of the age identities held in the keychain.
//!
//! Each identity is stored as a `PasswordEntry` of type `AgeKey`, keyed by the
//! user-facing name. The public recipient is derived from the secret on read,
//! so listing identities reads each entry on the shared auth context.

use std::str::FromStr;

use secrecy::ExposeSecret;

use crate::age::errors::AgeError;
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
/// Reads each entry's secret to derive its recipient. After the app is unlocked
/// this reuses the shared auth context, the same as reading a vault item.
pub fn list_age_keys() -> Result<Vec<AgeKeyOverview>, AgeError> {
    let entries = PasswordEntry::list()
        .map_err(|e| AgeError::FailedToRetrieveRecipient("age key list".to_owned(), e))?;

    let mut keys: Vec<AgeKeyOverview> = Vec::new();
    for entry in entries {
        if !matches!(entry.password_type, PasswordEntryType::AgeKey) {
            continue;
        }
        let name = entry.key_id.clone();
        match entry.get_password() {
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
