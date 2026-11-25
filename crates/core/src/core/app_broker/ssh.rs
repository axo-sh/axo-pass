//! The SSH agent's side of the broker: signing with managed Secure Enclave
//! keys and vault SSH keys, and listing the identities they advertise. Also
//! `ap ssh-askpass`'s side: SSH key passphrases, either unlocked from the
//! keychain behind a biometric prompt or typed by the user.

pub mod vault_keys;

use std::collections::HashSet;
use std::os::fd::BorrowedFd;
use std::path::{Path, PathBuf};

use anyhow::anyhow;
use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use ssh_key::{Algorithm, HashAlg, PrivateKey, Signature};
use zeroize::Zeroizing;

use self::vault_keys::VaultKeyEntry;
use super::client::send_request_for;
use super::in_flight::InFlightRequest;
use super::vault::{
    ClientIdentity, LoadSshKeyPayload, SignSshKeyPayload, VaultAccessPrompt, VaultAction,
    VaultAuthorizer, VaultPayload, authorize_and_serve, serve_granted_sign,
};
use super::wire::{WireRequest, WireResponse, b64_decode_raw, b64_encode};
use super::{BrokerError, PassphraseAuthorizer, PassphrasePrompt, PromptOutcome};
use crate::audit;
use crate::core::auth::{
    AuthContext, AuthMethod, ForeignContext, run_on_auth_thread, sign_with_managed_key_on,
    sign_with_managed_key_preapproved,
};
use crate::core::dirs::app_data_dir;
use crate::core::provenance::ProcessNode;
use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::generic_password::PasswordEntry;
use crate::secrets::keychain::managed_key::{KeyPolicy, ManagedSshKey};
use crate::secrets::vaults::VaultCatalog;
use crate::secrets::vaults::ssh_keys::default_true;
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

    /// Who asked, as the agent resolved it. See
    /// [`WireRequest::SignWithSecureEnclaveKey`] for why this can be shown
    /// to the user.
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

    /// The purpose of the signature, parsed by the agent from the request.
    /// `None` when the agent cannot determine the purpose.
    pub purpose: Option<SignPurpose>,
}

/// The purpose of a signature, parsed by the agent from the data to be signed.
/// Show in the prompt only. The requesting process chooses the data, so this
/// value is not authenticated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SignPurpose {
    /// An SSH login. `host` is the server's name from a session binding or
    /// `known_hosts`, or the short fingerprint of its host key when no name
    /// was found. `None` when the request carries no host key.
    Login {
        user: Option<String>,
        host: Option<String>,
    },

    /// An `ssh-keygen -Y sign` signature in `namespace`, e.g. `git`.
    Sshsig { namespace: String },
}

impl SignPurpose {
    /// The namespace of an SSHSIG signed-data blob: the `SSHSIG` magic
    /// followed by the namespace as an SSH string. `None` for any other data.
    pub fn sshsig(data: &[u8]) -> Option<Self> {
        let rest = data.strip_prefix(b"SSHSIG")?;
        let len = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize;
        let namespace = rest.get(4..4 + len)?;
        let namespace = std::str::from_utf8(namespace).ok()?;
        Some(Self::Sshsig {
            namespace: namespace.to_string(),
        })
    }
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

/// Where a managed key is held.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KeySource {
    /// A Secure Enclave key in the keychain, signed with by its label.
    #[default]
    SecureEnclave,

    /// An SSH key credential in a vault, signed with by its fingerprint.
    Vault {
        vault_key: String,
        item_key: String,
        credential_key: String,
    },
}

/// A managed key as the agent sees it: enough to advertise the identity and to
/// ask for a signature later, with no keychain access of its own.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedIdentity {
    /// The keychain label of a Secure Enclave key. The location of a vault key
    /// as `vault/item/credential`.
    pub key_label: String,
    /// One OpenSSH public key line: algorithm, base64 key, comment.
    pub public_key: String,
    #[serde(default)]
    pub source: KeySource,
    /// The agent advertises the key to SSH clients. A key that is not
    /// advertised is still listed here, so the agent can sign with it.
    #[serde(default = "default_true")]
    pub auto_load: bool,
}

impl From<VaultKeyEntry> for ManagedIdentity {
    fn from(entry: VaultKeyEntry) -> Self {
        Self {
            key_label: format!(
                "{}/{}/{}",
                entry.vault_key, entry.item_key, entry.credential_key
            ),
            public_key: entry.public_key,
            source: KeySource::Vault {
                vault_key: entry.vault_key,
                item_key: entry.item_key,
                credential_key: entry.credential_key,
            },
            auto_load: entry.auto_load,
        }
    }
}

/// Listing cache of the vault SSH keys, written by the app at unlock and after
/// an edit of a key. See [`vault_keys`].
pub fn vault_keys_path() -> PathBuf {
    // typically: ~/Library/Application Support/Axo Pass/ssh-vault-keys.json
    app_data_dir().join("ssh-vault-keys.json")
}

/// List the managed keys the app can sign with. Blocking, and starts the app if
/// it is not already running.
///
/// `requester` is the client this is for, when there is one, such as the `ssh`
/// process connected to the agent. The request is dropped if it disconnects
/// first. The same holds for the other requests in this module.
pub fn list_identities(
    requester: Option<BorrowedFd<'_>>,
) -> Result<Vec<ManagedIdentity>, BrokerError> {
    match send_request_for(&WireRequest::ListIdentities, requester)? {
        WireResponse::Identities { keys } => Ok(keys),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to identity listing".to_string(),
        )),
    }
}

/// Ask the app to authorize and produce a signature. Blocking: it waits for the
/// user to answer a prompt, so call it from a thread that can block.
#[allow(clippy::too_many_arguments)]
pub fn request_signature(
    key_label: &str,
    fingerprint: Option<&str>,
    comment: Option<&str>,
    data: &[u8],
    flags: u32,
    caller: Option<&str>,
    caller_chain: &[ProcessNode],
    purpose: Option<&SignPurpose>,
    requester: Option<BorrowedFd<'_>>,
) -> Result<Signature, BrokerError> {
    let request = WireRequest::SignWithSecureEnclaveKey {
        key_label: key_label.to_string(),
        fingerprint: fingerprint.map(String::from),
        comment: comment.map(String::from),
        caller: caller.map(String::from),
        caller_chain: caller_chain.to_vec(),
        purpose: purpose.cloned(),
        data: b64_encode(data),
        flags,
    };
    signature_from(send_request_for(&request, requester)?)
}

/// Ask the app to authorize and produce a signature with a vault SSH key,
/// named by its fingerprint. Blocking, for the same reason as
/// [`request_signature`]. `flags` select the hash of an RSA key.
#[allow(clippy::too_many_arguments)]
pub fn request_vault_signature(
    fingerprint: &str,
    comment: Option<&str>,
    data: &[u8],
    flags: u32,
    caller: Option<&str>,
    caller_chain: &[ProcessNode],
    purpose: Option<&SignPurpose>,
    requester: Option<BorrowedFd<'_>>,
) -> Result<Signature, BrokerError> {
    let request = WireRequest::SignWithVaultKey {
        fingerprint: fingerprint.to_string(),
        comment: comment.map(String::from),
        caller: caller.map(String::from),
        caller_chain: caller_chain.to_vec(),
        purpose: purpose.cloned(),
        data: b64_encode(data),
        flags,
    };
    signature_from(send_request_for(&request, requester)?)
}

/// The signature in the response to a signing request.
fn signature_from(response: WireResponse) -> Result<Signature, BrokerError> {
    match response {
        WireResponse::Signed {
            algorithm,
            signature,
        } => {
            let algorithm = Algorithm::new(&algorithm)
                .map_err(|e| BrokerError::Failed(format!("Unknown algorithm: {e}")))?;
            let body = b64_decode_raw(signature)
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
    purpose: Option<&SignPurpose>,
    allow_grants: bool,
    requester: Option<BorrowedFd<'_>>,
) -> Result<(), BrokerError> {
    let request = WireRequest::AuthorizeKeyUse {
        fingerprint: fingerprint.map(String::from),
        comment: comment.map(String::from),
        caller: caller.map(String::from),
        caller_chain: caller_chain.to_vec(),
        purpose: purpose.cloned(),
        allow_grants,
    };
    match send_request_for(&request, requester)? {
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

/// Read the managed keys out of the keychain, then the vault keys out of the
/// listing cache. Listing needs no authentication, so this raises no prompt and
/// works with the vault still locked. A missing or unreadable cache lists no
/// vault keys.
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
            source: KeySource::SecureEnclave,
            auto_load: true,
        });
    }
    identities.extend(vault_identities(&vault_keys_path()));
    Ok(identities)
}

/// The vault keys in the listing cache that may sign, one for each
/// fingerprint.
fn vault_identities(cache_path: &Path) -> Vec<ManagedIdentity> {
    let mut seen = HashSet::new();
    vault_keys::load(cache_path)
        .into_iter()
        .filter(|entry| entry.ssh_use)
        .filter(|entry| seen.insert(entry.fingerprint.clone()))
        .map(ManagedIdentity::from)
        .collect()
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
        signature: b64_encode(signature.as_bytes()),
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

/// Serve a managed-key signature: without a prompt when an app grant covers
/// the request, through the app's prompt otherwise.
pub(super) async fn sign_managed(
    authorizer: &dyn SignAuthorizer,
    mut prompt: SignPrompt,
    peer: audit::Actor,
    data: Vec<u8>,
    in_flight: &InFlightRequest,
) -> WireResponse {
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

    authorize_and_sign(authorizer, prompt, peer, data, in_flight).await
}

async fn authorize_and_sign(
    authorizer: &dyn SignAuthorizer,
    prompt: SignPrompt,
    peer: audit::Actor,
    data: Vec<u8>,
    in_flight: &InFlightRequest,
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
    in_flight.attach(&context);

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
                signature: b64_encode(signature.as_bytes()),
            },
            PromptOutcome::Succeeded,
        ),
        // A dismissed prompt is the user's answer, so report a cancellation
        // rather than a failure. This includes our own Cancel button, which
        // invalidates the context.
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
    in_flight: &InFlightRequest,
) -> WireResponse {
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
    in_flight.attach(&context);

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

/// What a vault key signature request carries.
pub(super) struct VaultSignRequest {
    /// Canonical `SHA256:...` fingerprint of the key.
    pub fingerprint: String,
    pub comment: Option<String>,
    pub caller: Option<String>,
    pub caller_chain: Vec<ProcessNode>,
    pub purpose: Option<SignPurpose>,
    pub data: Vec<u8>,
    /// The agent sign request's flags. They select the hash of an RSA key.
    pub flags: u32,
}

/// Serve a vault key signature. The broker finds the key in the listing cache
/// and prompts through the vault authorizer. It unlocks only the vault the
/// cache entry names, checks that the credential holds a key with the
/// requested fingerprint, and signs.
pub(super) async fn sign_vault(
    authorizer: &dyn VaultAuthorizer,
    vaults: &VaultCatalog,
    request: VaultSignRequest,
    peer: audit::Actor,
    in_flight: &InFlightRequest,
) -> WireResponse {
    sign_vault_with(
        &vault_keys_path(),
        authorizer,
        vaults,
        request,
        peer,
        in_flight,
    )
    .await
}

async fn sign_vault_with(
    cache_path: &Path,
    authorizer: &dyn VaultAuthorizer,
    vaults: &VaultCatalog,
    request: VaultSignRequest,
    peer: audit::Actor,
    in_flight: &InFlightRequest,
) -> WireResponse {
    let path = cache_path.to_path_buf();
    let Some(entry) = find_vault_entry(&path, &request.fingerprint, false).await else {
        return WireResponse::Failed {
            message: "No vault SSH key with SSH use allowed has this fingerprint".to_string(),
        };
    };

    let comment = Some(entry.comment)
        .filter(|comment| !comment.is_empty())
        .or(request.comment);
    let mut prompt = VaultAccessPrompt {
        vault_key: entry.vault_key,
        caller: request.caller,
        caller_chain: request.caller_chain,
        client: ClientIdentity::Process,
        action: VaultAction::SignSshKey {
            item_key: entry.item_key,
            credential_key: entry.credential_key,
            fingerprint: request.fingerprint,
            comment,
            purpose: request.purpose,
            grant_candidate: None,
        },
    };
    log::debug!("App broker request: {prompt:?}");
    let payload = SignSshKeyPayload {
        data: request.data,
        flags: request.flags,
        cache_path: cache_path.to_path_buf(),
    };
    if let Some(response) = serve_granted_sign(authorizer, vaults, &prompt, &payload, &peer).await {
        return response;
    }
    if let VaultAction::SignSshKey {
        grant_candidate, ..
    } = &mut prompt.action
    {
        *grant_candidate = app_grants::candidate_app(&prompt.caller_chain);
    }
    authorize_and_serve(
        authorizer,
        vaults,
        prompt,
        peer,
        Some(VaultPayload::SignSshKey(payload)),
        in_flight,
    )
    .await
}

/// The entry in the listing cache `path` for the key with `fingerprint`, if SSH
/// use is allowed for it. With `require_auto_load`, auto-load must be allowed
/// as well.
async fn find_vault_entry(
    path: &Path,
    fingerprint: &str,
    require_auto_load: bool,
) -> Option<VaultKeyEntry> {
    let path = path.to_path_buf();
    let entries = tokio::task::spawn_blocking(move || vault_keys::load(&path))
        .await
        .unwrap_or_default();
    entries.into_iter().find(|entry| {
        entry.fingerprint == fingerprint && entry.ssh_use && (entry.auto_load || !require_auto_load)
    })
}

/// What a vault key load request carries.
pub(super) struct VaultLoadRequest {
    /// Canonical `SHA256:...` fingerprint of the key.
    pub fingerprint: String,
    pub comment: Option<String>,
    pub caller: Option<String>,
    pub caller_chain: Vec<ProcessNode>,
    /// What the signature that caused the load is for.
    pub purpose: Option<SignPurpose>,
}

/// Serve a vault key load. The broker finds the key in the listing cache and
/// prompts through the vault authorizer. It unlocks only the vault the cache
/// entry names, checks that the credential holds a key with the requested
/// fingerprint and allows SSH use and auto-load, and returns the key.
pub(super) async fn load_vault(
    authorizer: &dyn VaultAuthorizer,
    vaults: &VaultCatalog,
    request: VaultLoadRequest,
    peer: audit::Actor,
    in_flight: &InFlightRequest,
) -> WireResponse {
    load_vault_with(
        &vault_keys_path(),
        authorizer,
        vaults,
        request,
        peer,
        in_flight,
    )
    .await
}

async fn load_vault_with(
    cache_path: &Path,
    authorizer: &dyn VaultAuthorizer,
    vaults: &VaultCatalog,
    request: VaultLoadRequest,
    peer: audit::Actor,
    in_flight: &InFlightRequest,
) -> WireResponse {
    let Some(entry) = find_vault_entry(cache_path, &request.fingerprint, true).await else {
        return WireResponse::Failed {
            message: "No vault SSH key with SSH use and auto-load allowed has this fingerprint"
                .to_string(),
        };
    };

    let comment = Some(entry.comment)
        .filter(|comment| !comment.is_empty())
        .or(request.comment);
    let mut prompt = VaultAccessPrompt {
        vault_key: entry.vault_key,
        caller: request.caller,
        caller_chain: request.caller_chain,
        client: ClientIdentity::Process,
        action: VaultAction::LoadSshKey {
            item_key: entry.item_key,
            credential_key: entry.credential_key,
            fingerprint: request.fingerprint,
            comment,
            purpose: request.purpose,
            grant_candidate: None,
        },
    };
    if let VaultAction::LoadSshKey {
        grant_candidate, ..
    } = &mut prompt.action
    {
        *grant_candidate = app_grants::candidate_app(&prompt.caller_chain);
    }
    log::debug!("App broker request: {prompt:?}");
    let payload = LoadSshKeyPayload {
        cache_path: cache_path.to_path_buf(),
    };
    authorize_and_serve(
        authorizer,
        vaults,
        prompt,
        peer,
        Some(VaultPayload::LoadSshKey(payload)),
        in_flight,
    )
    .await
}

/// Ask the app for the private key of a vault SSH key, named by its
/// fingerprint, for the agent to hold. Blocking, for the same reason as
/// [`request_signature`]. The key is checked against `fingerprint` and is never
/// logged. Every buffer that held it is zeroized.
pub fn request_vault_key(
    fingerprint: &str,
    comment: Option<&str>,
    caller: Option<&str>,
    caller_chain: &[ProcessNode],
    purpose: Option<&SignPurpose>,
    requester: Option<BorrowedFd<'_>>,
) -> Result<PrivateKey, BrokerError> {
    let request = WireRequest::LoadVaultKey {
        fingerprint: fingerprint.to_string(),
        comment: comment.map(String::from),
        caller: caller.map(String::from),
        caller_chain: caller_chain.to_vec(),
        purpose: purpose.cloned(),
    };
    match send_request_for(&request, requester)? {
        WireResponse::VaultKey { private_key } => {
            let text = Zeroizing::new(
                b64_decode_raw(private_key.as_bytes())
                    .map_err(|e| BrokerError::Failed(format!("Malformed key: {e}")))?,
            );
            let key = PrivateKey::from_openssh(&*text)
                .map_err(|e| BrokerError::Failed(format!("Invalid key: {e}")))?;
            if key.is_encrypted() {
                return Err(BrokerError::Failed("The key is encrypted".to_string()));
            }
            let actual = key.fingerprint(HashAlg::Sha256).to_string();
            if actual != fingerprint {
                return Err(BrokerError::Failed(format!(
                    "The app returned the key {actual} instead of {fingerprint}"
                )));
            }
            Ok(key)
        },
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to key load request".to_string(),
        )),
    }
}

/// Ask the app for an SSH key passphrase, on behalf of `ap ssh-askpass` or the
/// agent loading an auto-load key. Blocking, for the same reason as
/// [`request_signature`]: it waits for the user.
pub fn request_ssh_passphrase(
    prompt: &PassphrasePrompt,
    requester: Option<BorrowedFd<'_>>,
) -> Result<SecretString, BrokerError> {
    let request = WireRequest::GetSshPassphrase {
        key_id: prompt.key_id.clone(),
        prompt: prompt.prompt.clone().unwrap_or_default(),
        description: prompt.description.clone(),
        caller: prompt.caller.clone(),
        caller_chain: prompt.caller_chain.clone(),
    };
    match send_request_for(&request, requester)? {
        WireResponse::Passphrase { passphrase } => {
            let bytes = b64_decode_raw(passphrase)
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
    in_flight: &InFlightRequest,
) -> WireResponse {
    let entry = prompt.key_id.as_deref().map(PasswordEntry::ssh);

    loop {
        // True if a saved passphrase exists but could not be read, so the text
        // field offers a way back to it.
        let mut can_use_saved = false;
        if let Some(entry) = entry.clone()
            && has_saved_passphrase(&entry).await
        {
            let mut interruptions = 0;
            loop {
                let saved = unlock_saved_passphrase(
                    authorizer,
                    &prompt,
                    peer.clone(),
                    entry.clone(),
                    in_flight,
                )
                .await;
                match saved {
                    SavedPassphrase::Unlocked(passphrase) => {
                        return passphrase_response(&passphrase);
                    },
                    // The user chose to type the passphrase instead.
                    _ if authorizer.take_typed_request().await => {
                        can_use_saved = true;
                        break;
                    },
                    // Dismissing the biometric prompt answers the request: the
                    // user was asked and said no. Falling through to a text
                    // field instead would make cancelling take two attempts.
                    SavedPassphrase::Cancelled => return WireResponse::Cancelled,
                    // The system cancels the prompt right after wake, while the
                    // screen is still locking or unlocking. Retry on a fresh
                    // context before asking for a typed passphrase.
                    SavedPassphrase::Interrupted if interruptions < INTERRUPTED_RETRIES => {
                        interruptions += 1;
                        let delay = tokio::time::sleep(INTERRUPTED_RETRY_DELAY);
                        if in_flight.unless_abandoned(delay).await.is_none() {
                            return WireResponse::Cancelled;
                        }
                    },
                    // A read that failed is not an answer, so let them type it.
                    SavedPassphrase::Interrupted | SavedPassphrase::Failed => {
                        can_use_saved = true;
                        break;
                    },
                }
            }
        }

        let collecting = authorizer.collect(prompt.clone(), can_use_saved);
        let Some(collected) = in_flight.unless_abandoned(collecting).await else {
            return WireResponse::Cancelled;
        };
        match collected {
            Ok(Some(collected)) if collected.use_saved => continue,
            Ok(Some(collected)) => {
                let response = passphrase_response(&collected.value);
                if collected.save_to_keychain
                    && let Some(entry) = entry
                {
                    save_passphrase(entry, collected.value).await;
                }
                return response;
            },
            Ok(None) => return WireResponse::Cancelled,
            Err(message) => {
                log::debug!("App broker could not collect an SSH passphrase: {message}");
                return WireResponse::Failed { message };
            },
        }
    }
}

/// Attempts to read a saved passphrase again after the system cancels the
/// biometric prompt.
const INTERRUPTED_RETRIES: u32 = 5;
const INTERRUPTED_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(1);

/// How reading a saved passphrase ended.
enum SavedPassphrase {
    Unlocked(SecretString),
    Cancelled,
    /// The system cancelled the biometric prompt.
    Interrupted,
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
    in_flight: &InFlightRequest,
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
    in_flight.attach(&context);

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
            let saved = match e {
                KeychainError::SystemCancelled => SavedPassphrase::Interrupted,
                _ => SavedPassphrase::Failed,
            };
            (PromptOutcome::Failed(e.to_string()), saved)
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
        passphrase: b64_encode(passphrase.expose_secret().as_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD_NO_PAD as b64;
    use ssh_key::{HashAlg, PrivateKey};

    use super::vault_keys::VaultKeyEntry;
    use super::*;
    use crate::core::app_broker::tests::support::empty_vaults;
    use crate::core::app_broker::vault::VaultAuthorization;
    use crate::secrets::vaults::ssh_keys::SshKeyRecord;

    /// Declines every prompt and keeps what it was asked.
    #[derive(Default)]
    struct DecliningAuthorizer {
        prompts: Mutex<Vec<VaultAccessPrompt>>,
    }

    #[async_trait]
    impl VaultAuthorizer for DecliningAuthorizer {
        async fn begin(
            &self,
            prompt: VaultAccessPrompt,
            _peer: audit::Actor,
        ) -> Result<VaultAuthorization, String> {
            self.prompts.lock().unwrap().push(prompt);
            Err("declined".to_string())
        }

        async fn abandon(&self) {}

        async fn end(&self, _prompt: VaultAccessPrompt, _outcome: PromptOutcome) {}
    }

    fn ed25519_key() -> PrivateKey {
        let data = include_str!("../../../../cli/src/cli/commands/ssh_agent/fixtures/b64_ed25519");
        PrivateKey::from_bytes(&b64.decode(data.trim()).unwrap()).unwrap()
    }

    fn cache_entry(vault_key: &str, credential_key: &str) -> VaultKeyEntry {
        let record = SshKeyRecord::new(&ed25519_key(), "laptop").unwrap();
        VaultKeyEntry::from_record(&record, vault_key, "github", credential_key).unwrap()
    }

    fn sign_request(fingerprint: &str) -> VaultSignRequest {
        VaultSignRequest {
            fingerprint: fingerprint.to_string(),
            comment: None,
            caller: Some("git (ssh)".to_string()),
            caller_chain: Vec::new(),
            purpose: None,
            data: b"data".to_vec(),
            flags: 0,
        }
    }

    #[test]
    fn vault_identities_from_cache_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ssh-vault-keys.json");
        let entry = cache_entry("personal", "key");
        vault_keys::store(&path, std::slice::from_ref(&entry)).unwrap();

        let identities = vault_identities(&path);

        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].public_key, entry.public_key);
        assert_eq!(identities[0].key_label, "personal/github/key");
        assert_eq!(
            identities[0].source,
            KeySource::Vault {
                vault_key: "personal".to_string(),
                item_key: "github".to_string(),
                credential_key: "key".to_string(),
            }
        );
    }

    #[test]
    fn vault_identities_list_one_key_for_each_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ssh-vault-keys.json");
        let entries = [cache_entry("personal", "a"), cache_entry("work", "b")];
        vault_keys::store(&path, &entries).unwrap();

        assert_eq!(vault_identities(&path).len(), 1);
    }

    #[test]
    fn vault_identities_omit_keys_with_ssh_use_off() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ssh-vault-keys.json");
        let mut record = SshKeyRecord::new(&ed25519_key(), "laptop").unwrap();
        record.set_access(true, false);
        let entry = VaultKeyEntry::from_record(&record, "personal", "github", "key").unwrap();
        vault_keys::store(&path, &[entry]).unwrap();

        assert!(vault_identities(&path).is_empty());
    }

    #[test]
    fn vault_identities_keep_unadvertised_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ssh-vault-keys.json");
        let mut record = SshKeyRecord::new(&ed25519_key(), "laptop").unwrap();
        record.set_access(false, true);
        let entry = VaultKeyEntry::from_record(&record, "personal", "github", "key").unwrap();
        vault_keys::store(&path, &[entry]).unwrap();

        let identities = vault_identities(&path);

        assert_eq!(identities.len(), 1);
        assert!(!identities[0].auto_load);
    }

    #[test]
    fn vault_identities_empty_for_missing_or_corrupt_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ssh-vault-keys.json");
        assert!(vault_identities(&path).is_empty());

        std::fs::write(&path, "not json").unwrap();
        assert!(vault_identities(&path).is_empty());
    }

    #[test]
    fn identity_without_source_is_secure_enclave() {
        let json = r#"{"key_label":"k","public_key":"ssh-ed25519 AAAA"}"#;

        let identity: ManagedIdentity = serde_json::from_str(json).unwrap();

        assert_eq!(identity.source, KeySource::SecureEnclave);
    }

    #[test]
    fn vault_source_roundtrips_as_tagged_object() {
        let source = KeySource::Vault {
            vault_key: "v".to_string(),
            item_key: "i".to_string(),
            credential_key: "c".to_string(),
        };

        let json = serde_json::to_string(&source).unwrap();

        assert_eq!(
            json,
            r#"{"kind":"vault","vault_key":"v","item_key":"i","credential_key":"c"}"#
        );
        assert_eq!(serde_json::from_str::<KeySource>(&json).unwrap(), source);
    }

    #[tokio::test]
    async fn vault_signature_refused_without_cache_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ssh-vault-keys.json");
        let authorizer = DecliningAuthorizer::default();

        let response = sign_vault_with(
            &path,
            &authorizer,
            &empty_vaults(),
            sign_request("SHA256:unknown"),
            audit::Actor::default(),
            &InFlightRequest::default(),
        )
        .await;

        assert!(matches!(response, WireResponse::Failed { .. }));
        assert!(authorizer.prompts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn vault_signature_prompts_for_vault_of_cache_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ssh-vault-keys.json");
        let entry = cache_entry("work", "key");
        vault_keys::store(&path, std::slice::from_ref(&entry)).unwrap();
        let authorizer = DecliningAuthorizer::default();

        let response = sign_vault_with(
            &path,
            &authorizer,
            &empty_vaults(),
            sign_request(&entry.fingerprint),
            audit::Actor::default(),
            &InFlightRequest::default(),
        )
        .await;

        assert!(matches!(response, WireResponse::Failed { .. }));
        let prompts = authorizer.prompts.lock().unwrap();
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].vault_key, "work");
        assert_eq!(prompts[0].caller.as_deref(), Some("git (ssh)"));
        let VaultAction::SignSshKey {
            item_key,
            credential_key,
            fingerprint,
            comment,
            ..
        } = &prompts[0].action
        else {
            panic!("expected an SSH signing prompt");
        };
        assert_eq!(item_key, "github");
        assert_eq!(credential_key, "key");
        assert_eq!(*fingerprint, entry.fingerprint);
        assert_eq!(comment.as_deref(), Some("laptop"));
        assert_eq!(
            *fingerprint,
            ed25519_key()
                .public_key()
                .fingerprint(HashAlg::Sha256)
                .to_string()
        );
    }

    fn app_node(verified: bool) -> ProcessNode {
        ProcessNode {
            command: "Fork".to_string(),
            executable: None,
            pid: 1,
            bundle_id: Some("com.DanPristupov.Fork".to_string()),
            team_id: Some("Q6M7LEEA66".to_string()),
            code_id: Some("cdhash:Fork".to_string()),
            verified,
        }
    }

    /// Grant candidate on the prompt of a vault signature from `chain`.
    async fn prompted_grant_candidate(chain: Vec<ProcessNode>) -> Option<GrantApp> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ssh-vault-keys.json");
        let entry = cache_entry("work", "key");
        vault_keys::store(&path, std::slice::from_ref(&entry)).unwrap();
        let authorizer = DecliningAuthorizer::default();
        let mut request = sign_request(&entry.fingerprint);
        request.caller_chain = chain;

        sign_vault_with(
            &path,
            &authorizer,
            &empty_vaults(),
            request,
            audit::Actor::default(),
            &InFlightRequest::default(),
        )
        .await;

        let prompts = authorizer.prompts.lock().unwrap();
        let VaultAction::SignSshKey {
            grant_candidate, ..
        } = &prompts[0].action
        else {
            panic!("expected an SSH signing prompt");
        };
        grant_candidate.clone()
    }

    #[tokio::test]
    async fn vault_signature_prompt_offers_grant_to_verified_app() {
        let candidate = prompted_grant_candidate(vec![app_node(true)]).await;

        let candidate = candidate.expect("a verified app is offered a grant");
        assert_eq!(candidate.bundle_id, "com.DanPristupov.Fork");
        assert_eq!(candidate.team_id, "Q6M7LEEA66");
    }

    #[tokio::test]
    async fn vault_signature_prompt_offers_no_grant_to_unverified_app() {
        assert_eq!(prompted_grant_candidate(vec![app_node(false)]).await, None);
    }

    #[tokio::test]
    async fn vault_signature_prompt_offers_no_grant_without_chain() {
        assert_eq!(prompted_grant_candidate(Vec::new()).await, None);
    }

    fn load_request(fingerprint: &str) -> VaultLoadRequest {
        VaultLoadRequest {
            fingerprint: fingerprint.to_string(),
            comment: None,
            caller: Some("git (ssh)".to_string()),
            caller_chain: Vec::new(),
            purpose: None,
        }
    }

    /// Cache entry for the test key with the given access settings.
    fn access_entry(auto_load: bool, ssh_use: bool) -> VaultKeyEntry {
        let mut record = SshKeyRecord::new(&ed25519_key(), "laptop").unwrap();
        record.set_access(auto_load, ssh_use);
        VaultKeyEntry::from_record(&record, "work", "github", "key").unwrap()
    }

    /// Answer to a load request for `entries`, and the prompts it raised.
    async fn load_with_cache(
        entries: &[VaultKeyEntry],
        request: VaultLoadRequest,
    ) -> (WireResponse, Vec<VaultAccessPrompt>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ssh-vault-keys.json");
        vault_keys::store(&path, entries).unwrap();
        let authorizer = DecliningAuthorizer::default();

        let response = load_vault_with(
            &path,
            &authorizer,
            &empty_vaults(),
            request,
            audit::Actor::default(),
            &InFlightRequest::default(),
        )
        .await;

        let prompts = authorizer.prompts.lock().unwrap().clone();
        (response, prompts)
    }

    #[tokio::test]
    async fn vault_load_refused_without_cache_entry() {
        let (response, prompts) = load_with_cache(&[], load_request("SHA256:unknown")).await;

        assert!(matches!(response, WireResponse::Failed { .. }));
        assert!(prompts.is_empty());
    }

    #[tokio::test]
    async fn vault_load_refused_with_ssh_use_off() {
        let entry = access_entry(true, false);

        let (response, prompts) = load_with_cache(
            std::slice::from_ref(&entry),
            load_request(&entry.fingerprint),
        )
        .await;

        assert!(matches!(response, WireResponse::Failed { .. }));
        assert!(prompts.is_empty());
    }

    #[tokio::test]
    async fn vault_load_refused_with_auto_load_off() {
        let entry = access_entry(false, true);

        let (response, prompts) = load_with_cache(
            std::slice::from_ref(&entry),
            load_request(&entry.fingerprint),
        )
        .await;

        assert!(matches!(response, WireResponse::Failed { .. }));
        assert!(prompts.is_empty());
    }

    #[tokio::test]
    async fn vault_load_prompts_for_vault_of_cache_entry() {
        let entry = access_entry(true, true);

        let (response, prompts) = load_with_cache(
            std::slice::from_ref(&entry),
            load_request(&entry.fingerprint),
        )
        .await;

        assert!(matches!(response, WireResponse::Failed { .. }));
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].vault_key, "work");
        assert_eq!(prompts[0].caller.as_deref(), Some("git (ssh)"));
        let VaultAction::LoadSshKey {
            item_key,
            credential_key,
            fingerprint,
            comment,
            ..
        } = &prompts[0].action
        else {
            panic!("expected an SSH key load prompt");
        };
        assert_eq!(item_key, "github");
        assert_eq!(credential_key, "key");
        assert_eq!(*fingerprint, entry.fingerprint);
        assert_eq!(comment.as_deref(), Some("laptop"));
    }

    #[tokio::test]
    async fn vault_load_prompt_offers_grant_to_verified_app() {
        let entry = access_entry(true, true);
        let mut request = load_request(&entry.fingerprint);
        request.caller_chain = vec![app_node(true)];

        let (_, prompts) = load_with_cache(std::slice::from_ref(&entry), request).await;

        let VaultAction::LoadSshKey {
            grant_candidate, ..
        } = &prompts[0].action
        else {
            panic!("expected an SSH key load prompt");
        };
        let candidate = grant_candidate.as_ref().expect("a verified app is offered");
        assert_eq!(candidate.bundle_id, "com.DanPristupov.Fork");
    }

    /// A key with auto-load off stays with the app, which signs with it on
    /// every request.
    #[tokio::test]
    async fn vault_signature_prompts_with_auto_load_off() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ssh-vault-keys.json");
        let entry = access_entry(false, true);
        vault_keys::store(&path, std::slice::from_ref(&entry)).unwrap();
        let authorizer = DecliningAuthorizer::default();

        sign_vault_with(
            &path,
            &authorizer,
            &empty_vaults(),
            sign_request(&entry.fingerprint),
            audit::Actor::default(),
            &InFlightRequest::default(),
        )
        .await;

        let prompts = authorizer.prompts.lock().unwrap();
        assert_eq!(prompts.len(), 1);
        assert!(matches!(prompts[0].action, VaultAction::SignSshKey { .. }));
    }

    #[test]
    fn sshsig_namespace() {
        let mut data = b"SSHSIG".to_vec();
        data.extend_from_slice(&3u32.to_be_bytes());
        data.extend_from_slice(b"git");
        data.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            SignPurpose::sshsig(&data),
            Some(SignPurpose::Sshsig {
                namespace: "git".to_string()
            })
        );
    }

    #[test]
    fn sshsig_rejects_other_data() {
        assert_eq!(SignPurpose::sshsig(b""), None);
        assert_eq!(SignPurpose::sshsig(b"SSHSIG"), None);
        assert_eq!(SignPurpose::sshsig(b"SSHSIG\0\0\0\x09git"), None);
        assert_eq!(SignPurpose::sshsig(b"\0\0\0\x20session"), None);
    }
}
