//! `ap keychain`'s side of the broker: listing the saved generic passwords and
//! deleting a managed Secure Enclave key.

use serde::{Deserialize, Serialize};

use super::{BrokerError, WireRequest, WireResponse, send_request};
use crate::audit;
use crate::secrets::keychain::generic_password::{PasswordEntry, PasswordEntryType};
use crate::secrets::keychain::managed_key::ManagedSshKey;

/// One saved generic password as it crosses the socket. Mirrors the fields of
/// [`PasswordEntry`]; the secret is never included.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerPasswordEntry {
    pub password_type: PasswordEntryType,
    pub key_id: String,
}

impl From<PasswordEntry> for BrokerPasswordEntry {
    fn from(entry: PasswordEntry) -> Self {
        BrokerPasswordEntry {
            password_type: entry.password_type,
            key_id: entry.key_id,
        }
    }
}

// Client (the CLI).

/// List every saved generic password. Blocking, and starts the app if it is not
/// running.
pub fn request_keychain_passwords(
    caller: Option<&str>,
) -> Result<Vec<BrokerPasswordEntry>, BrokerError> {
    let request = WireRequest::ListKeychainPasswords {
        caller: caller.map(String::from),
    };
    match send_request(&request)? {
        WireResponse::KeychainPasswords { entries } => Ok(entries),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to keychain password listing".to_string(),
        )),
    }
}

/// Delete a managed Secure Enclave key by its label. Blocking, and starts the
/// app if it is not running.
pub fn request_delete_managed_key(label: &str, caller: Option<&str>) -> Result<(), BrokerError> {
    let request = WireRequest::DeleteManagedKey {
        label: label.to_string(),
        caller: caller.map(String::from),
    };
    match send_request(&request)? {
        WireResponse::Acknowledged => Ok(()),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to managed key deletion".to_string(),
        )),
    }
}

// Server (the app).

pub(super) async fn list_passwords() -> WireResponse {
    tokio::task::spawn_blocking(PasswordEntry::list)
        .await
        .map_or_else(
            |e| Err(e.to_string()),
            |result| result.map_err(|e| e.to_string()),
        )
        .map_or_else(
            |message| WireResponse::Failed { message },
            |entries| WireResponse::KeychainPasswords {
                entries: entries.into_iter().map(BrokerPasswordEntry::from).collect(),
            },
        )
}

pub(super) async fn delete_managed_key(label: String, actor: audit::Actor) -> WireResponse {
    let result = tokio::task::spawn_blocking(move || delete_managed_key_locally(&label))
        .await
        .unwrap_or_else(|e| Err(format!("Managed key deletion task failed: {e}")));

    audit::record_managed_key_delete(Some(actor), &result);

    match result {
        Ok(_) => WireResponse::Acknowledged,
        Err(message) => WireResponse::Failed { message },
    }
}

/// Find the managed key by label, then delete it, capturing its label and
/// `SHA256:` fingerprint for the audit event.
fn delete_managed_key_locally(label: &str) -> Result<(String, String), String> {
    let key = ManagedSshKey::find(label)
        .map_err(|e| format!("Failed to find managed key: {e}"))?
        .ok_or_else(|| format!("No managed key named {label}"))?;
    key.delete_capturing()
        .map_err(|e| format!("Failed to delete managed key: {e}"))
}
