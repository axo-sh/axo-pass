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
    BrokerError, Hangup, PassphraseAuthorizer, PassphrasePrompt, PromptOutcome, WireRequest,
    WireResponse, send_request,
};
use crate::audit;
use crate::core::auth::{
    AuthContext, AuthMethod, ForeignContext, run_on_auth_thread, sign_with_managed_key_on,
    sign_with_managed_key_preapproved,
};
use crate::core::provenance::ProcessNode;
use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::generic_password::PasswordEntry;
use crate::secrets::keychain::managed_key::{KeyPolicy, ManagedSshKey};
use crate::ssh::app_grants::{self, GrantApp};

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

    /// The full requesting process chain, resolved the same way as `caller`.
    /// Shown when the user expands the prompt.
    pub caller_chain: Vec<ProcessNode>,

    /// True for a managed Secure Enclave key, false for a key the agent holds
    /// directly (a confirm-on-use gate from `ssh-add -c`). The app words its
    /// prompt differently for each.
    pub managed: bool,

    /// The managed key's policy, read from the keychain by the broker. `None`
    /// for a key the agent holds directly, or when the key could not be read.
    pub policy: Option<KeyPolicy>,

    /// The app the user may grant lasting access to this key from the prompt.
    /// Set only for a [`KeyPolicy::Default`] key requested through a fully
    /// verified chain that contains a signed app.
    pub grant_candidate: Option<GrantApp>,
}

/// Supplies an `LAContext` to sign on, and learns how the attempt ended so it
/// can take its prompt down.
#[async_trait]
pub trait SignAuthorizer: Send + Sync + 'static {
    /// Prepare a context for `prompt` and put the prompt on screen. The broker
    /// evaluates the returned context, which is what makes the attached
    /// `LAAuthenticationView` draw.
    ///
    /// `peer` is the process the broker verified at accept time. The app
    /// attributes the grant it hands out to it, so the audit log names the
    /// process that asked and not only the caller it claimed.
    async fn begin(&self, prompt: SignPrompt, peer: audit::Actor)
    -> Result<ForeignContext, String>;

    /// The attempt finished. Always called once `begin` has been called, so the
    /// app can take the prompt down and settle the authorization it handed out.
    async fn end(&self, prompt: SignPrompt, outcome: PromptOutcome);

    /// The broker signed without a prompt because `app` holds a grant for the
    /// key. Neither `begin` nor `end` is called for such a request.
    async fn notify_preapproved(&self, prompt: SignPrompt, app: GrantApp);
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
    flags: u32,
    caller: Option<&str>,
    caller_chain: &[ProcessNode],
) -> Result<Signature, BrokerError> {
    let request = WireRequest::Sign {
        key_label: key_label.to_string(),
        fingerprint: fingerprint.map(String::from),
        comment: comment.map(String::from),
        caller: caller.map(String::from),
        caller_chain: caller_chain.to_vec(),
        data: b64.encode(data),
        flags,
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

/// Ask the app to gate a signature for a key the agent holds itself: one added
/// with `ssh-add -c`, or an auto-loaded key. The app draws the prompt and
/// evaluates the biometric check; the agent does the signing once this returns
/// `Ok`. Blocking, for the same reason as [`request_signature`].
///
/// `Err(BrokerError::Cancelled)` means the user declined. Any other error means
/// the app could not be reached or the prompt failed.
///
/// With `allow_grants`, an app grant for the key answers without a prompt.
pub fn request_authorize_key_use(
    fingerprint: Option<&str>,
    comment: Option<&str>,
    caller: Option<&str>,
    caller_chain: &[ProcessNode],
    allow_grants: bool,
) -> Result<(), BrokerError> {
    let request = WireRequest::AuthorizeKeyUse {
        fingerprint: fingerprint.map(String::from),
        comment: comment.map(String::from),
        caller: caller.map(String::from),
        caller_chain: caller_chain.to_vec(),
        allow_grants,
    };
    match send_request(&request)? {
        WireResponse::Confirmed { ok: true } => Ok(()),
        WireResponse::Confirmed { ok: false } | WireResponse::Cancelled => {
            Err(BrokerError::Cancelled)
        },
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to a key-use authorization request".to_string(),
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

/// A managed key's policy and canonical `SHA256:...` fingerprint, read from the
/// keychain without prompting.
pub(super) struct ResolvedKey {
    pub policy: KeyPolicy,
    pub fingerprint: String,
}

/// Read a managed key without prompting. `None` when the key is not found or
/// the keychain read fails.
pub(super) async fn resolve_key(key_label: String) -> Option<ResolvedKey> {
    tokio::task::spawn_blocking(move || match ManagedSshKey::find(&key_label) {
        Ok(key) => key.map(|k| ResolvedKey {
            policy: k.policy(),
            fingerprint: format!("SHA256:{}", k.fingerprint_sha256()),
        }),
        Err(e) => {
            log::debug!("Could not read {key_label}: {e}");
            None
        },
    })
    .await
    .ok()
    .flatten()
}

/// The grant that covers this request, if any. The fingerprint is the one the
/// broker read from the keychain, not the one the agent sent.
async fn find_grant(
    key: &ResolvedKey,
    caller_chain: &[ProcessNode],
) -> Option<app_grants::AppGrant> {
    if key.policy != KeyPolicy::Default {
        return None;
    }
    let grants = tokio::task::spawn_blocking(app_grants::load)
        .await
        .ok()?
        .inspect_err(|e| log::warn!("Could not read SSH app grants: {e}"))
        .ok()?;
    app_grants::find_match(
        &grants,
        &key.fingerprint,
        key.policy,
        caller_chain,
        time::OffsetDateTime::now_utc(),
    )
    .cloned()
}

/// Sign without a prompt for an app that holds a grant. `None` when the
/// signature could not be made, so the caller falls back to prompting.
async fn sign_preapproved(
    authorizer: &dyn SignAuthorizer,
    prompt: &SignPrompt,
    peer: &audit::Actor,
    grant: app_grants::AppGrant,
    data: &[u8],
) -> Option<WireResponse> {
    let key_label = prompt.key_label.clone();
    let data = data.to_vec();
    let result =
        tokio::task::spawn_blocking(move || sign_with_managed_key_preapproved(&key_label, &data))
            .await;
    let signature = match result {
        Ok(Ok(signature)) => signature,
        Ok(Err(e)) => {
            log::warn!(
                "Signing for granted app {} failed: {e}",
                grant.app.bundle_id
            );
            return None;
        },
        Err(e) => {
            log::warn!("Signing task for granted app failed: {e}");
            return None;
        },
    };

    record_grant_use(authorizer, prompt, peer, grant).await;
    Some(WireResponse::Signed {
        algorithm: signature.algorithm().to_string(),
        signature: b64.encode(signature.as_bytes()),
    })
}

/// Record that an app grant authorized a signature, and tell the app so it can
/// report the use.
async fn record_grant_use(
    authorizer: &dyn SignAuthorizer,
    prompt: &SignPrompt,
    peer: &audit::Actor,
    grant: app_grants::AppGrant,
) {
    let mut subject = audit::Subject::new(audit::SubjectKind::SshKey, grant.fingerprint.clone())
        .fingerprint(grant.fingerprint.clone());
    if let Some(comment) = prompt.comment.as_deref().filter(|c| !c.is_empty()) {
        subject = subject.label(comment);
    }
    audit::record(
        audit::AuditEvent::new(
            audit::process_source(),
            audit::Action::AuthGrantReused,
            audit::Outcome::Succeeded,
        )
        .subject(subject)
        .actor(peer.clone())
        .detail("scope", "ssh.sign")
        .detail("grant", format!("app:{}", grant.app.bundle_id)),
    );

    authorizer
        .notify_preapproved(prompt.clone(), grant.app)
        .await;
}

/// Held from the grant check until the app's prompt has ended, so a request
/// that arrives while another is being approved waits and then finds the grant
/// the user gave. The app also keeps one active request at a time.
static SIGN_REQUESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Serve a managed-key signature: without a prompt when an app grant covers
/// the request, through the app's prompt otherwise.
pub(super) async fn sign_managed(
    authorizer: &dyn SignAuthorizer,
    mut prompt: SignPrompt,
    peer: audit::Actor,
    data: Vec<u8>,
    hangup: &Hangup,
) -> WireResponse {
    let _serial = SIGN_REQUESTS.lock().await;
    let key = resolve_key(prompt.key_label.clone()).await;
    prompt.policy = key.as_ref().map(|k| k.policy);

    if let Some(key) = &key {
        if let Some(grant) = find_grant(key, &prompt.caller_chain).await
            && let Some(response) = sign_preapproved(authorizer, &prompt, &peer, grant, &data).await
        {
            return response;
        }
        if key.policy == KeyPolicy::Default {
            prompt.grant_candidate = app_grants::candidate_app(&prompt.caller_chain);
        }
    }
    log::debug!(
        "Signing with {}: policy {:?}, grant candidate {:?}, chain {:?}",
        prompt.key_label,
        prompt.policy,
        prompt.grant_candidate,
        prompt
            .caller_chain
            .iter()
            .map(|n| (
                n.command.as_str(),
                n.bundle_id.as_deref(),
                n.team_id.as_deref(),
                n.verified,
                n.code_id.is_some(),
            ))
            .collect::<Vec<_>>(),
    );

    authorize_and_sign(authorizer, prompt, peer, data, hangup).await
}

async fn authorize_and_sign(
    authorizer: &dyn SignAuthorizer,
    prompt: SignPrompt,
    peer: audit::Actor,
    data: Vec<u8>,
    hangup: &Hangup,
) -> WireResponse {
    let context = match authorizer.begin(prompt.clone(), peer).await {
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
    hangup.watch(&context);

    let key_label = prompt.key_label.clone();
    let caller = prompt.caller.clone();
    // A key whose policy could not be read is treated as the stricter kind. The
    // Secure Enclave enforces the real access control either way.
    let policy = prompt.policy.unwrap_or(KeyPolicy::AlwaysRequireAuth);
    let result = tokio::task::spawn_blocking(move || {
        sign_with_managed_key_on(
            AuthContext::Foreign(context),
            &key_label,
            policy,
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

/// Draw the confirm-on-use prompt and evaluate the biometric check on a
/// context the app owns. The agent signs once this returns `Confirmed`.
///
/// With `allow_grants`, a matching app grant confirms without a prompt, and
/// otherwise the prompt may offer one. The fingerprint is the agent's: the
/// agent holds the key and does the signing, so it is trusted to name it.
pub(super) async fn authorize_key_use(
    authorizer: &dyn SignAuthorizer,
    mut prompt: SignPrompt,
    peer: audit::Actor,
    allow_grants: bool,
    hangup: &Hangup,
) -> WireResponse {
    let _serial = SIGN_REQUESTS.lock().await;
    if allow_grants && let Some(fingerprint) = prompt.fingerprint.clone() {
        let key = ResolvedKey {
            policy: KeyPolicy::Default,
            fingerprint,
        };
        if let Some(grant) = find_grant(&key, &prompt.caller_chain).await {
            record_grant_use(authorizer, &prompt, &peer, grant).await;
            return WireResponse::Confirmed { ok: true };
        }
        prompt.grant_candidate = app_grants::candidate_app(&prompt.caller_chain);
    }

    let context = match authorizer.begin(prompt.clone(), peer).await {
        Ok(context) => context,
        Err(message) => {
            log::debug!("App broker key-use authorization declined: {message}");
            authorizer
                .end(prompt, PromptOutcome::Failed(message.clone()))
                .await;
            return WireResponse::Failed { message };
        },
    };
    hangup.watch(&context);

    let reason = match prompt.caller.as_deref() {
        Some(caller) => format!("approve use of an SSH key for {caller}"),
        None => "approve use of an SSH key".to_string(),
    };
    let result = tokio::task::spawn_blocking(move || {
        run_on_auth_thread(
            AuthContext::Foreign(context),
            AuthMethod::Policy { reason },
            |_| (),
        )
    })
    .await
    .unwrap_or_else(|e| {
        Err(KeychainError::Generic(anyhow!(
            "Authorization task failed: {e}"
        )))
    });

    let (response, outcome) = match result {
        Ok(()) => (
            WireResponse::Confirmed { ok: true },
            PromptOutcome::Succeeded,
        ),
        // A dismissed prompt, whether through the biometric sheet or our own
        // Cancel button, which invalidates the context.
        Err(KeychainError::UserCancelled | KeychainError::AuthenticationExpired) => {
            (WireResponse::Cancelled, PromptOutcome::Cancelled)
        },
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
        caller_chain: prompt.caller_chain.clone(),
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
    peer: audit::Actor,
) -> WireResponse {
    let entry = prompt.key_id.as_deref().map(PasswordEntry::ssh);

    if let Some(entry) = entry.clone()
        && has_saved_passphrase(&entry).await
    {
        match unlock_saved_passphrase(authorizer, &prompt, peer, entry).await {
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
    peer: audit::Actor,
    entry: PasswordEntry,
) -> SavedPassphrase {
    let context = match authorizer.begin(prompt.clone(), peer).await {
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
