//! The SSH agent's side of the broker: signing with managed Secure Enclave
//! keys, and listing the identities they advertise.

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as b64;
use serde::{Deserialize, Serialize};
use ssh_key::{Algorithm, Signature};

use super::{BrokerError, PromptOutcome, WireRequest, WireResponse, send_request};
use crate::core::auth::{AuthContext, ForeignContext, sign_with_managed_key_on};
use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::managed_key::ManagedSshKey;

/// What the app needs to describe the prompt.
#[derive(Debug, Clone)]
pub struct SignPrompt {
    pub key_label: String,

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
    data: &[u8],
    caller: Option<&str>,
) -> Result<Signature, BrokerError> {
    let request = WireRequest::Sign {
        key_label: key_label.to_string(),
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
