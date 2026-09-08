//! `ap age`'s side of the broker: listing age keys, creating and deleting them,
//! and unlocking an identity's secret for encrypt or decrypt.
//!
//! `ap` holds no keychain entitlements, so it cannot reach the data-protection
//! keychain at all: `SecItemAdd` fails with `errSecMissingEntitlement` and a
//! read returns an empty access group. Every keychain operation behind `ap age`
//! therefore runs in the app. The age encryption itself stays in `ap`, which
//! hands back the resolved identity, the same split as `ap ssh-askpass`.
//!
//! Listing, keygen and delete raise no prompt. Reading an identity's secret is
//! gated on a biometric prompt drawn on a context the app owns, the same as
//! [`super::gpg::get_passphrase`].

use anyhow::anyhow;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as b64;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use super::{
    BrokerError, PassphraseAuthorizer, PassphraseKind, PassphrasePrompt, PromptOutcome,
    WireRequest, WireResponse, send_request,
};
use crate::age::key_overview::list_age_keys;
use crate::age::recipients::{delete_recipient, generate_age_key};
use crate::audit;
use crate::core::auth::AuthContext;
use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::generic_password::PasswordEntry;

/// One age key as it crosses the socket: the public half only, never the
/// secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerAgeKey {
    pub name: String,
    pub recipient: String,
}

// Client (the CLI).

/// List every saved age key. Blocking, and starts the app if it is not running.
pub fn request_age_keys(caller: Option<&str>) -> Result<Vec<BrokerAgeKey>, BrokerError> {
    let request = WireRequest::ListAgeKeys {
        caller: caller.map(String::from),
    };
    match send_request(&request)? {
        WireResponse::AgeKeys { keys } => Ok(keys),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to age key listing".to_string(),
        )),
    }
}

/// Unlock one age key's secret identity, behind a biometric prompt. Blocking:
/// it waits for the user.
pub fn request_age_identity(
    key_id: &str,
    caller: Option<&str>,
) -> Result<SecretString, BrokerError> {
    let request = WireRequest::GetAgeIdentity {
        key_id: key_id.to_string(),
        caller: caller.map(String::from),
    };
    match send_request(&request)? {
        WireResponse::AgeIdentity { identity } => {
            let bytes = b64
                .decode(identity)
                .map_err(|e| BrokerError::Failed(format!("Malformed identity: {e}")))?;
            String::from_utf8(bytes)
                .map(SecretString::from)
                .map_err(|e| BrokerError::Failed(format!("Malformed identity: {e}")))
        },
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to age identity request".to_string(),
        )),
    }
}

/// Create a new age key. Blocking, and starts the app if it is not running.
pub fn request_create_age_key(
    key_id: &str,
    caller: Option<&str>,
) -> Result<BrokerAgeKey, BrokerError> {
    let request = WireRequest::CreateAgeKey {
        key_id: key_id.to_string(),
        caller: caller.map(String::from),
    };
    match send_request(&request)? {
        WireResponse::AgeKey { name, recipient } => Ok(BrokerAgeKey { name, recipient }),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to age key creation".to_string(),
        )),
    }
}

/// Delete an age key. Blocking, and starts the app if it is not running.
pub fn request_delete_age_key(key_id: &str, caller: Option<&str>) -> Result<(), BrokerError> {
    let request = WireRequest::DeleteAgeKey {
        key_id: key_id.to_string(),
        caller: caller.map(String::from),
    };
    match send_request(&request)? {
        WireResponse::Acknowledged => Ok(()),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to age key deletion".to_string(),
        )),
    }
}

// Server (the app).

pub(super) async fn list_keys() -> WireResponse {
    tokio::task::spawn_blocking(list_age_keys)
        .await
        .unwrap_or_else(|e| Err(crate::age::errors::AgeError::Broker(e.to_string())))
        .map_or_else(
            |e| WireResponse::Failed {
                message: e.to_string(),
            },
            |keys| WireResponse::AgeKeys {
                keys: keys
                    .into_iter()
                    .map(|k| BrokerAgeKey {
                        name: k.name,
                        recipient: k.recipient,
                    })
                    .collect(),
            },
        )
}

pub(super) async fn create_key(key_id: String, actor: audit::Actor) -> WireResponse {
    tokio::task::spawn_blocking(move || generate_age_key(&key_id, Some(actor)))
        .await
        .unwrap_or_else(|e| Err(crate::age::errors::AgeError::Broker(e.to_string())))
        .map_or_else(
            |e| WireResponse::Failed {
                message: e.to_string(),
            },
            |key| WireResponse::AgeKey {
                name: key.name,
                recipient: key.recipient,
            },
        )
}

pub(super) async fn delete_key(key_id: String, actor: audit::Actor) -> WireResponse {
    tokio::task::spawn_blocking(move || delete_recipient(&key_id, Some(actor)))
        .await
        .unwrap_or_else(|e| Err(crate::age::errors::AgeError::Broker(e.to_string())))
        .map_or_else(
            |e| WireResponse::Failed {
                message: e.to_string(),
            },
            |()| WireResponse::Acknowledged,
        )
}

/// Unlock one age key's secret on a context the app owns.
pub(super) async fn get_identity(
    authorizer: &dyn PassphraseAuthorizer,
    key_id: String,
    caller: Option<String>,
    peer: audit::Actor,
) -> WireResponse {
    let entry = PasswordEntry::age(&key_id);

    if !has_entry(&entry).await {
        // An age identity cannot be typed, so a missing one is a hard error.
        // The CLI maps this back to `AgeError::RecipientNotFound`.
        return WireResponse::Failed {
            message: format!("No age key named {key_id}"),
        };
    }

    let prompt = PassphrasePrompt {
        kind: PassphraseKind::Age,
        key_id: Some(key_id),
        description: None,
        prompt: None,
        error_message: None,
        caller,
        caller_chain: peer.chain_detail.clone(),
    };

    let context = match authorizer.begin(prompt.clone(), peer).await {
        Ok(context) => context,
        Err(message) => {
            log::debug!("App broker age authorization declined: {message}");
            authorizer
                .end(prompt, PromptOutcome::Failed(message.clone()))
                .await;
            return WireResponse::Failed { message };
        },
    };

    let read_caller = prompt.caller.clone();
    let result = tokio::task::spawn_blocking(move || {
        entry.get_password_on(AuthContext::Foreign(context), read_caller.as_deref())
    })
    .await
    .unwrap_or_else(|e| {
        Err(KeychainError::Generic(anyhow!(
            "Age identity task failed: {e}"
        )))
    });

    let (response, outcome) = match result {
        Ok(Some(identity)) => (
            WireResponse::AgeIdentity {
                identity: b64.encode(identity.expose_secret().as_bytes()),
            },
            PromptOutcome::Succeeded,
        ),
        Ok(None) => {
            let message = format!(
                "No age key named {}",
                prompt.key_id.as_deref().unwrap_or("")
            );
            (
                WireResponse::Failed {
                    message: message.clone(),
                },
                PromptOutcome::Failed(message),
            )
        },
        Err(KeychainError::UserCancelled) => (WireResponse::Cancelled, PromptOutcome::Cancelled),
        Err(e) => {
            let message = e.to_string();
            (
                WireResponse::Failed {
                    message: message.clone(),
                },
                PromptOutcome::Failed(message),
            )
        },
    };
    authorizer.end(prompt, outcome).await;
    response
}

/// Whether the keychain holds an entry for this key. Raises no prompt: the
/// existence check runs with interaction disallowed.
async fn has_entry(entry: &PasswordEntry) -> bool {
    let entry = entry.clone();
    tokio::task::spawn_blocking(move || {
        entry
            .exists()
            .inspect_err(|e| log::debug!("Could not check for an age key: {e}"))
            .unwrap_or(false)
    })
    .await
    .unwrap_or(false)
}
