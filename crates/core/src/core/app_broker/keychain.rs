//! `ap keychain`'s side of the broker: listing the saved generic passwords and
//! deleting a managed Secure Enclave key.
//!
//! A listing reads on the shared context if the app is unlocked, and raises no
//! prompt. If the app is locked, the app draws a prompt on a context it owns
//! ([`read_or_prompt`]).

use std::sync::Arc;

use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use super::client::send_request;
use super::in_flight::InFlightRequest;
use super::wire::{WireRequest, WireResponse};
use super::{BrokerError, PassphraseAuthorizer, PassphraseKind, PassphrasePrompt, PromptOutcome};
use crate::audit;
use crate::core::auth::AuthContext;
use crate::secrets::keychain::errors::KeychainError;
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
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
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

/// Supplies the saved passwords the broker reports.
///
/// The one implementation that ships is [`SystemKeychain`]. It exists as a
/// trait so tests can route the request without reading the developer's own
/// login keychain, which raises an authorization prompt and stalls the suite.
/// Called on a blocking thread.
pub trait KeychainLister: Send + Sync + 'static {
    /// List the saved passwords, authenticating on `context`.
    fn list_passwords(
        &self,
        context: AuthContext,
    ) -> Result<Vec<BrokerPasswordEntry>, KeychainError>;
}

/// Reads the real login keychain.
pub struct SystemKeychain;

impl KeychainLister for SystemKeychain {
    fn list_passwords(
        &self,
        context: AuthContext,
    ) -> Result<Vec<BrokerPasswordEntry>, KeychainError> {
        PasswordEntry::list_on(context)
            .map(|entries| entries.into_iter().map(BrokerPasswordEntry::from).collect())
    }
}

pub(super) async fn list_passwords(
    lister: Arc<dyn KeychainLister>,
    authorizer: &dyn PassphraseAuthorizer,
    caller: Option<String>,
    peer: audit::Actor,
    in_flight: &InFlightRequest,
) -> WireResponse {
    let prompt = PassphrasePrompt {
        kind: PassphraseKind::KeychainList,
        key_id: None,
        description: None,
        prompt: None,
        error_message: None,
        caller,
        caller_chain: peer.chain_detail.clone(),
    };
    let read = move |context: AuthContext| lister.list_passwords(context);
    match read_or_prompt(authorizer, prompt, peer, in_flight, read).await {
        Ok(entries) => WireResponse::KeychainPasswords { entries },
        Err(response) => response,
    }
}

/// Run `read` on the shared context, which the app adopted at unlock. If the
/// app is locked, ask the app for a context through `authorizer`, which puts
/// `prompt` up, and run `read` again on that context. An error is returned as
/// the response to send.
pub(super) async fn read_or_prompt<T, F>(
    authorizer: &dyn PassphraseAuthorizer,
    prompt: PassphrasePrompt,
    peer: audit::Actor,
    in_flight: &InFlightRequest,
    read: F,
) -> Result<T, WireResponse>
where
    T: Send + 'static,
    F: Fn(AuthContext) -> Result<T, KeychainError> + Clone + Send + 'static,
{
    let shared_read = read.clone();
    match run_blocking(move || shared_read(AuthContext::SharedThreadLocal)).await {
        Ok(value) => return Ok(value),
        Err(KeychainError::AuthenticationExpired) => {
            log::debug!("App is locked, prompting for {:?}", prompt.kind);
        },
        Err(e) => {
            return Err(WireResponse::Failed {
                message: e.to_string(),
            });
        },
    }

    let context = match authorizer.begin(prompt.clone(), peer).await {
        Ok(context) => context,
        Err(message) => {
            log::debug!(
                "App broker {:?} authorization declined: {message}",
                prompt.kind
            );
            authorizer
                .end(prompt, PromptOutcome::Failed(message.clone()))
                .await;
            return Err(WireResponse::Failed { message });
        },
    };
    in_flight.attach(&context);

    let result = run_blocking(move || read(AuthContext::Foreign(context))).await;
    let (result, outcome) = match result {
        Ok(value) => (Ok(value), PromptOutcome::Succeeded),
        // A foreign context expires only if the app invalidated it, which is
        // how its Cancel button ends the prompt.
        Err(KeychainError::UserCancelled | KeychainError::AuthenticationExpired) => {
            (Err(WireResponse::Cancelled), PromptOutcome::Cancelled)
        },
        Err(e) => {
            let message = e.to_string();
            (
                Err(WireResponse::Failed {
                    message: message.clone(),
                }),
                PromptOutcome::Failed(message),
            )
        },
    };
    authorizer.end(prompt, outcome).await;
    result
}

/// Run a keychain read on a blocking thread.
async fn run_blocking<T: Send + 'static>(
    read: impl FnOnce() -> Result<T, KeychainError> + Send + 'static,
) -> Result<T, KeychainError> {
    tokio::task::spawn_blocking(read)
        .await
        .unwrap_or_else(|e| Err(KeychainError::Generic(anyhow!("Keychain task failed: {e}"))))
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
