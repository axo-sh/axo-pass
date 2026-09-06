//! The SSH agent's side of the broker: signing with managed Secure Enclave
//! keys, and listing the identities they advertise. Also `ap ssh-askpass`'s
//! side: SSH key passphrases, either unlocked from the keychain behind a
//! biometric prompt or typed by the user.

use anyhow::anyhow;
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as b64;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use ssh_key::{Algorithm, Signature};

use super::{
    BrokerError, PassphraseAuthorizer, PassphrasePrompt, PromptOutcome, WireRequest, WireResponse,
    send_request,
};
use crate::core::auth::{AuthContext, ForeignContext, sign_with_managed_key_on};
use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::generic_password::PasswordEntry;
use crate::secrets::keychain::managed_key::ManagedSshKey;

/// What the app needs to describe the prompt.
#[derive(Debug, Clone)]
pub struct SignPrompt {
    pub key_label: String,

    /// Canonical `SHA256:...` fingerprint of the key, resolved by the agent.
    /// Used as the subject of the grant events the app records, so they match
    /// the `ssh.sign` events the agent records.
    pub fingerprint: Option<String>,

    /// The key's OpenSSH comment, when it has one.
    pub comment: Option<String>,

    /// Who asked, as the agent resolved it. See [`WireRequest::Sign`] for why
    /// this can be shown to the user.
    pub caller: Option<String>,
}

/// Supplies an `LAContext` to sign on, and learns how the attempt ended so it
/// can take its prompt down.
#[async_trait]
pub trait SignAuthorizer: Send + Sync + 'static {
    /// Prepare a context for `prompt` and put the prompt on screen. The broker
    /// evaluates the returned context, which is what makes the attached
    /// `LAAuthenticationView` draw.
    async fn begin(&self, prompt: SignPrompt) -> Result<ForeignContext, String>;

    /// The attempt finished. Always called once `begin` has been called, so the
    /// app can take the prompt down and settle the authorization it handed out.
    async fn end(&self, prompt: SignPrompt, outcome: PromptOutcome);
}

/// A managed key as the agent sees it: enough to advertise the identity and to
/// ask for a signature later, with no keychain access of its own.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedIdentity {
    pub key_label: String,
    /// One OpenSSH public key line: algorithm, base64 key, comment.
    pub public_key: String,
}

/// List the managed keys the app can sign with. Blocking, and starts the app if
/// it is not already running.
pub fn list_identities() -> Result<Vec<ManagedIdentity>, BrokerError> {
    match send_request(&WireRequest::ListIdentities)? {
        WireResponse::Identities { keys } => Ok(keys),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to identity listing".to_string(),
        )),
    }
}

/// Ask the app to authorize and produce a signature. Blocking: it waits for the
/// user to answer a prompt, so call it from a thread that can block.
pub fn request_signature(
    key_label: &str,
    fingerprint: Option<&str>,
    comment: Option<&str>,
    data: &[u8],
    caller: Option<&str>,
) -> Result<Signature, BrokerError> {
    let request = WireRequest::Sign {
        key_label: key_label.to_string(),
        fingerprint: fingerprint.map(String::from),
        comment: comment.map(String::from),
        caller: caller.map(String::from),
        data: b64.encode(data),
    };
    match send_request(&request)? {
        WireResponse::Signed {
            algorithm,
            signature,
        } => {
            let algorithm = Algorithm::new(&algorithm)
                .map_err(|e| BrokerError::Failed(format!("Unknown algorithm: {e}")))?;
            let body = b64
                .decode(signature)
                .map_err(|e| BrokerError::Failed(format!("Malformed signature: {e}")))?;
            Signature::new(algorithm, body)
                .map_err(|e| BrokerError::Failed(format!("Invalid signature: {e}")))
        },
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to signing request".to_string(),
        )),
    }
}

/// Read the managed keys out of the keychain. Listing needs no authentication,
/// so this raises no prompt and works with the vault still locked.
pub(super) fn list_identities_locally() -> Result<Vec<ManagedIdentity>, String> {
    let keys = ManagedSshKey::list().map_err(|e| format!("Failed to list managed keys: {e}"))?;
    let mut identities = Vec::with_capacity(keys.len());
    for key in keys {
        let comment = format!("axo-secure-enclave:{}", &key.name()[0..6]);
        let public_key = ssh_key::PublicKey::new(key.public_key().clone(), comment)
            .to_openssh()
            .map_err(|e| format!("Failed to encode public key: {e}"))?;
        identities.push(ManagedIdentity {
            key_label: key.label(),
            public_key,
        });
    }
    Ok(identities)
}

pub(super) async fn authorize_and_sign(
    authorizer: &dyn SignAuthorizer,
    prompt: SignPrompt,
    data: Vec<u8>,
) -> WireResponse {
    let context = match authorizer.begin(prompt.clone()).await {
        Ok(context) => context,
        Err(message) => {
            log::debug!("App broker authorization declined: {message}");
            // `begin` may already have put a prompt on screen, so end the
            // attempt rather than leaving it there.
            authorizer
                .end(prompt, PromptOutcome::Failed(message.clone()))
                .await;
            return WireResponse::Failed { message };
        },
    };

    let key_label = prompt.key_label.clone();
    let caller = prompt.caller.clone();
    let result = tokio::task::spawn_blocking(move || {
        sign_with_managed_key_on(
            AuthContext::Foreign(context),
            &key_label,
            &data,
            caller.as_deref(),
        )
    })
    .await
    .unwrap_or_else(|e| {
        Err(KeychainError::SigningFailed(format!(
            "Signing task failed: {e}"
        )))
    });

    let (response, outcome) = match result {
        Ok(signature) => (
            WireResponse::Signed {
                algorithm: signature.algorithm().to_string(),
                signature: b64.encode(signature.as_bytes()),
            },
            PromptOutcome::Succeeded,
        ),
        // A dismissed prompt is the user's answer, so report a cancellation
        // rather than a failure.
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

/// Ask the app for an SSH key passphrase, on `ap ssh-askpass`'s behalf.
/// Blocking, for the same reason as [`request_signature`]: it waits for the
/// user.
pub fn request_ssh_passphrase(prompt: &PassphrasePrompt) -> Result<SecretString, BrokerError> {
    let request = WireRequest::GetSshPassphrase {
        key_id: prompt.key_id.clone(),
        prompt: prompt.prompt.clone().unwrap_or_default(),
        caller: prompt.caller.clone(),
    };
    match send_request(&request)? {
        WireResponse::Passphrase { passphrase } => {
            let bytes = b64
                .decode(passphrase)
                .map_err(|e| BrokerError::Failed(format!("Malformed passphrase: {e}")))?;
            String::from_utf8(bytes)
                .map(SecretString::from)
                .map_err(|e| BrokerError::Failed(format!("Malformed passphrase: {e}")))
        },
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to passphrase request".to_string(),
        )),
    }
}

/// Answer an SSH passphrase request: unlock the saved passphrase behind a
/// biometric prompt, or ask the user to type one. Mirrors
/// [`super::gpg::get_passphrase`], keyed to the SSH keychain namespace instead
/// of GPG's.
pub(super) async fn get_passphrase(
    authorizer: &dyn PassphraseAuthorizer,
    prompt: PassphrasePrompt,
) -> WireResponse {
    let entry = prompt.key_id.as_deref().map(PasswordEntry::ssh);

    if let Some(entry) = entry.clone()
        && has_saved_passphrase(&entry).await
    {
        match unlock_saved_passphrase(authorizer, &prompt, entry).await {
            SavedPassphrase::Unlocked(passphrase) => return passphrase_response(&passphrase),
            // Dismissing the biometric prompt answers the request: the user
            // was asked and said no. Falling through to a text field instead
            // would make cancelling take two attempts.
            SavedPassphrase::Cancelled => return WireResponse::Cancelled,
            // A read that failed is not an answer, so let them type it.
            SavedPassphrase::Failed => {},
        }
    }

    match authorizer.collect(prompt).await {
        Ok(Some(collected)) => {
            let response = passphrase_response(&collected.value);
            if collected.save_to_keychain
                && let Some(entry) = entry
            {
                save_passphrase(entry, collected.value).await;
            }
            response
        },
        Ok(None) => WireResponse::Cancelled,
        Err(message) => {
            log::debug!("App broker could not collect an SSH passphrase: {message}");
            WireResponse::Failed { message }
        },
    }
}

/// How reading a saved passphrase ended.
enum SavedPassphrase {
    Unlocked(SecretString),
    Cancelled,
    Failed,
}

/// Whether the keychain holds a passphrase for this key. Raises no prompt: the
/// existence check runs with interaction disallowed.
async fn has_saved_passphrase(entry: &PasswordEntry) -> bool {
    let entry = entry.clone();
    tokio::task::spawn_blocking(move || {
        entry
            .exists()
            .inspect_err(|e| log::debug!("Could not check for a saved passphrase: {e}"))
            .unwrap_or(false)
    })
    .await
    .unwrap_or(false)
}

/// Read the saved passphrase on a context the app owns, so the biometric
/// prompt is drawn in our own panel.
async fn unlock_saved_passphrase(
    authorizer: &dyn PassphraseAuthorizer,
    prompt: &PassphrasePrompt,
    entry: PasswordEntry,
) -> SavedPassphrase {
    let context = match authorizer.begin(prompt.clone()).await {
        Ok(context) => context,
        Err(message) => {
            log::debug!("App broker passphrase authorization declined: {message}");
            authorizer
                .end(prompt.clone(), PromptOutcome::Failed(message))
                .await;
            return SavedPassphrase::Failed;
        },
    };

    let caller = prompt.caller.clone();
    let result = tokio::task::spawn_blocking(move || {
        entry.get_password_on(AuthContext::Foreign(context), caller.as_deref())
    })
    .await
    .unwrap_or_else(|e| {
        Err(KeychainError::Generic(anyhow!(
            "Passphrase task failed: {e}"
        )))
    });

    let (outcome, saved) = match result {
        Ok(Some(passphrase)) => (
            PromptOutcome::Succeeded,
            SavedPassphrase::Unlocked(passphrase),
        ),
        Ok(None) => {
            let message = "No saved passphrase for this key".to_string();
            (PromptOutcome::Failed(message), SavedPassphrase::Failed)
        },
        Err(KeychainError::UserCancelled) => (PromptOutcome::Cancelled, SavedPassphrase::Cancelled),
        Err(e) => {
            log::debug!("Could not read the saved passphrase: {e}");
            (
                PromptOutcome::Failed(e.to_string()),
                SavedPassphrase::Failed,
            )
        },
    };
    authorizer.end(prompt.clone(), outcome).await;
    saved
}

/// Store a passphrase the user asked us to remember. A failure here is logged
/// and no more: the caller still gets the passphrase it asked for.
async fn save_passphrase(entry: PasswordEntry, passphrase: SecretString) {
    let result = tokio::task::spawn_blocking(move || {
        entry.set_password(passphrase).map_err(|e| e.to_string())
    })
    .await
    .unwrap_or_else(|e| Err(format!("Saving task failed: {e}")));
    if let Err(e) = result {
        log::error!("Failed to save the SSH passphrase to the keychain: {e}");
    }
}

fn passphrase_response(passphrase: &SecretString) -> WireResponse {
    WireResponse::Passphrase {
        passphrase: b64.encode(passphrase.expose_secret().as_bytes()),
    }
}
