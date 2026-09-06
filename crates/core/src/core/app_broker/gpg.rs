//! `ap pinentry`'s side of the broker: GPG passphrases, either unlocked from
//! the keychain behind a biometric prompt or typed by the user, plus gpg's
//! plain `CONFIRM` and `MESSAGE` prompts.

use anyhow::anyhow;
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as b64;
use secrecy::{ExposeSecret, SecretString};

use super::{BrokerError, PromptOutcome, WireRequest, WireResponse, send_request};
use crate::audit;
use crate::core::auth::{AuthContext, ForeignContext};
use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::generic_password::PasswordEntry;

/// Which agent this passphrase prompt is on behalf of. The two share a
/// prompt UI, but need different wording: gpg's key grips and assuan
/// commands mean nothing to an SSH prompt, and vice versa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassphraseKind {
    Gpg,
    Ssh,
}

/// What the app needs to describe a passphrase prompt, from either gpg-agent
/// (via `ap pinentry`) or `SSH_ASKPASS` (via `ap ssh-askpass`).
///
/// For GPG, the strings come from gpg-agent through the assuan `SETDESC`,
/// `SETPROMPT` and `SETERROR` commands, so they are gpg's own wording rather
/// than ours; for SSH they are lifted from ssh/ssh-add's own prompt text.
#[derive(Debug, Clone)]
pub struct PassphrasePrompt {
    pub kind: PassphraseKind,

    /// The keychain entry this prompt names: a GPG key grip from
    /// `SETKEYINFO`, or an SSH key's fingerprint. Absent when nothing
    /// identifies a key, in which case nothing can be saved or read back and
    /// the user types the passphrase.
    pub key_id: Option<String>,

    pub description: Option<String>,
    pub prompt: Option<String>,

    /// gpg's report of the previous attempt, set when the passphrase was
    /// rejected. Its presence means any saved passphrase is wrong. Always
    /// `None` for SSH.
    pub error_message: Option<String>,

    /// Who asked, as `ap pinentry` / `ap ssh-askpass` resolved it. Carries the
    /// same delegated trust as [`WireRequest::Sign`]'s caller.
    pub caller: Option<String>,
}

/// A passphrase the user typed, and what they asked us to do with it.
#[derive(Debug)]
pub struct CollectedPassphrase {
    pub value: SecretString,
    pub save_to_keychain: bool,
}

/// Draws the prompts `ap pinentry` asks for on gpg-agent's behalf.
#[async_trait]
pub trait PassphraseAuthorizer: Send + Sync + 'static {
    /// Prepare a context to read the saved passphrase on, and put the biometric
    /// prompt on screen. As with [`super::SignAuthorizer::begin`], the broker's
    /// evaluation on the returned context is what draws the attached
    /// `LAAuthenticationView`, and `peer` is the process the broker verified.
    async fn begin(
        &self,
        prompt: PassphrasePrompt,
        peer: audit::Actor,
    ) -> Result<ForeignContext, String>;

    /// Ask the user to type the passphrase, for a key with nothing saved or one
    /// whose saved passphrase gpg has just rejected. `None` means they
    /// dismissed the prompt.
    async fn collect(
        &self,
        prompt: PassphrasePrompt,
    ) -> Result<Option<CollectedPassphrase>, String>;

    /// The attempt finished. Called once for every [`Self::begin`].
    async fn end(&self, prompt: PassphrasePrompt, outcome: PromptOutcome);

    /// Answer gpg's `CONFIRM`.
    async fn confirm(&self, description: Option<String>) -> bool;

    /// Show gpg's `MESSAGE` and wait for the user to dismiss it.
    async fn message(&self, description: Option<String>);
}

/// Ask the app for a GPG passphrase. Blocking, for the same reason as
/// `ssh::request_signature`: it waits for the user.
pub fn request_passphrase(prompt: &PassphrasePrompt) -> Result<SecretString, BrokerError> {
    let request = WireRequest::GetPassphrase {
        key_id: prompt.key_id.clone(),
        description: prompt.description.clone(),
        prompt: prompt.prompt.clone(),
        error_message: prompt.error_message.clone(),
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

/// Put gpg's `CONFIRM` question to the user.
pub fn request_confirm(description: Option<&str>) -> Result<bool, BrokerError> {
    let request = WireRequest::Confirm {
        description: description.map(String::from),
    };
    match send_request(&request)? {
        WireResponse::Confirmed { ok } => Ok(ok),
        WireResponse::Cancelled => Ok(false),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to confirmation request".to_string(),
        )),
    }
}

/// Show gpg's `MESSAGE` and wait for the user to dismiss it.
pub fn request_message(description: Option<&str>) -> Result<(), BrokerError> {
    let request = WireRequest::Message {
        description: description.map(String::from),
    };
    match send_request(&request)? {
        WireResponse::Acknowledged => Ok(()),
        WireResponse::Cancelled => Ok(()),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to message request".to_string(),
        )),
    }
}

/// Answer a passphrase request: unlock the saved passphrase behind a biometric
/// prompt, or ask the user to type one.
pub(super) async fn get_passphrase(
    authorizer: &dyn PassphraseAuthorizer,
    prompt: PassphrasePrompt,
    peer: audit::Actor,
) -> WireResponse {
    let entry = prompt.key_id.as_deref().map(PasswordEntry::gpg);

    // An error message means gpg rejected the passphrase it was last given, so
    // the saved one is wrong and unlocking it would only waste a prompt.
    if prompt.error_message.is_none()
        && let Some(entry) = entry.clone()
        && has_saved_passphrase(&entry).await
    {
        match unlock_saved_passphrase(authorizer, &prompt, peer, entry).await {
            SavedPassphrase::Unlocked(passphrase) => return passphrase_response(&passphrase),
            // Dismissing the biometric prompt answers the request: the user was
            // asked and said no. Falling through to a text field instead would
            // make cancelling take two attempts.
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
            log::debug!("App broker could not collect a passphrase: {message}");
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

/// Read the saved passphrase on a context the app owns, so the biometric prompt
/// is drawn in our own panel.
async fn unlock_saved_passphrase(
    authorizer: &dyn PassphraseAuthorizer,
    prompt: &PassphrasePrompt,
    peer: audit::Actor,
    entry: PasswordEntry,
) -> SavedPassphrase {
    let context = match authorizer.begin(prompt.clone(), peer).await {
        Ok(context) => context,
        Err(message) => {
            log::debug!("App broker passphrase authorization declined: {message}");
            // `begin` may already have put a prompt on screen, so end the
            // attempt rather than leaving it there.
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
        // The entry went away between the check and the read.
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
/// and no more: gpg still gets the passphrase it asked for.
async fn save_passphrase(entry: PasswordEntry, passphrase: SecretString) {
    let key_id = entry.key_id.clone();
    let result = tokio::task::spawn_blocking(move || {
        entry.set_password(passphrase).map_err(|e| e.to_string())
    })
    .await
    .unwrap_or_else(|e| Err(format!("Saving task failed: {e}")));

    let (outcome, message) = match &result {
        Ok(()) => (audit::Outcome::Succeeded, None),
        Err(e) => (audit::Outcome::Failed, Some(e.clone())),
    };
    let mut event = audit::AuditEvent::new(
        audit::process_source(),
        audit::Action::GpgPassphraseSaved,
        outcome,
    )
    .subject(audit::Subject::new(audit::SubjectKind::GpgKey, key_id));
    if let Some(message) = message {
        event = event.message(message);
    }
    audit::record(event);

    if let Err(e) = result {
        log::error!("Failed to save the passphrase to the keychain: {e}");
    }
}

fn passphrase_response(passphrase: &SecretString) -> WireResponse {
    WireResponse::Passphrase {
        passphrase: b64.encode(passphrase.expose_secret().as_bytes()),
    }
}
