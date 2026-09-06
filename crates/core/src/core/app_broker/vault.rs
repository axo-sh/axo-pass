//! `ap item list` and `ap read`'s side of the broker: reading a vault's item
//! overview, or one secret value, through the app.
//!
//! `ap` holds no keychain entitlements, so it cannot read or create the vault
//! encryption key itself. It hands the request to the app, which unlocks the
//! vault on a context it owns and returns the result. A read prompts every
//! time; a listing may reuse a recent approval.
//!
//! The app verifies the peer before it serves either request, so it holds the
//! full provenance for the process that asked. It is therefore the process that
//! records the `secret.read` and `vault.items_listed` events, the same way the
//! SSH agent records `ssh.sign`.

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use super::{BrokerError, PromptOutcome, WireRequest, WireResponse, send_request};
use crate::audit::{self, Action, Actor, AuditEvent, Outcome, Subject, SubjectKind};
use crate::core::auth::{AuthContext, ForeignContext};
use crate::core::dirs::vaults_dir;
use crate::secrets::vaults::VaultWrapper;

/// One `axo://` reference to resolve, as it crosses the socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultRef {
    pub vault_key: String,
    pub item_key: String,
    pub credential_key: String,
}

/// Which command asked for a batch resolve, so the app records the matching
/// audit action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolvePurpose {
    /// `ap exec`.
    Exec,
    /// `ap inject`.
    Inject,
}

/// What the app is being asked to do with the vault. Grants are keyed on the
/// action as well as the vault, so authorizing a listing does not also
/// authorize a read of the same vault.
#[derive(Debug, Clone)]
pub enum VaultAction {
    /// `ap item list`: return the item overview, never a secret.
    ListItems,

    /// `ap read`: return one credential's secret value.
    ReadSecret {
        item_key: String,
        credential_key: String,
    },

    /// `ap exec` / `ap inject`: resolve many `axo://` references at once,
    /// possibly across several vaults, behind one prompt.
    ResolveSecrets {
        purpose: ResolvePurpose,
        refs: Vec<VaultRef>,
    },
}

/// What the app needs to describe the prompt for a vault access.
#[derive(Debug, Clone)]
pub struct VaultAccessPrompt {
    /// The vault a single-vault access names. For
    /// [`VaultAction::ResolveSecrets`], the distinct vault keys joined with
    /// `, `, since one resolve can span several vaults.
    pub vault_key: String,

    /// Who asked, as `ap` resolved it. Carries the same delegated trust as
    /// [`WireRequest::Sign`]'s caller.
    pub caller: Option<String>,

    pub action: VaultAction,
}

/// One vault item as it crosses the socket: the overview only, never a secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerVaultItem {
    pub key: String,
    pub title: String,
    pub credentials: Vec<BrokerCredential>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerCredential {
    pub key: String,
    pub title: String,
}

/// Supplies an `LAContext` to unlock the vault on, and learns how the attempt
/// ended so it can take its prompt down.
#[async_trait]
pub trait VaultAuthorizer: Send + Sync + 'static {
    /// Prepare a context for `prompt` and put the prompt on screen. The broker
    /// unlocks on the returned context, which is what makes the attached
    /// `LAAuthenticationView` draw. `peer` is the process the broker verified.
    async fn begin(&self, prompt: VaultAccessPrompt, peer: Actor)
    -> Result<ForeignContext, String>;

    /// The attempt finished. Always called once `begin` has been called, so the
    /// app can take the prompt down and settle the authorization it handed out.
    async fn end(&self, prompt: VaultAccessPrompt, outcome: PromptOutcome);
}

/// Ask the app to unlock a vault and return its item overview. Blocking: it may
/// wait for the user to answer a prompt, so call it from a thread that can
/// block. Starts the app if it is not already running.
pub fn request_vault_items(
    vault_key: &str,
    caller: Option<&str>,
) -> Result<Vec<BrokerVaultItem>, BrokerError> {
    let request = WireRequest::ListVaultItems {
        vault_key: vault_key.to_string(),
        caller: caller.map(String::from),
    };
    match send_request(&request)? {
        WireResponse::VaultItems { items } => Ok(items),
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to vault listing".to_string(),
        )),
    }
}

/// Ask the app to unlock a vault and return one credential's secret. `None`
/// means the credential does not exist. Blocking, same as
/// [`request_vault_items`].
pub fn request_vault_secret(
    vault_key: &str,
    item_key: &str,
    credential_key: &str,
    caller: Option<&str>,
) -> Result<Option<SecretString>, BrokerError> {
    let request = WireRequest::ReadVaultSecret {
        vault_key: vault_key.to_string(),
        item_key: item_key.to_string(),
        credential_key: credential_key.to_string(),
        caller: caller.map(String::from),
    };
    match send_request(&request)? {
        WireResponse::VaultSecret { value } => Ok(value.map(SecretString::from)),
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to vault secret read".to_string(),
        )),
    }
}

/// Ask the app to resolve many `axo://` references at once, behind one prompt.
/// The returned vector is positionally matched to `refs`; `None` means that
/// reference does not resolve. Blocking, same as [`request_vault_items`].
pub fn request_resolve_secrets(
    refs: &[VaultRef],
    purpose: ResolvePurpose,
    caller: Option<&str>,
) -> Result<Vec<Option<SecretString>>, BrokerError> {
    let request = WireRequest::ResolveSecrets {
        refs: refs.to_vec(),
        purpose,
        caller: caller.map(String::from),
    };
    match send_request(&request)? {
        WireResponse::ResolvedSecrets { values } => Ok(values
            .into_iter()
            .map(|v| v.map(SecretString::from))
            .collect()),
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to secret resolution".to_string(),
        )),
    }
}

pub(super) async fn authorize_and_serve(
    authorizer: &dyn VaultAuthorizer,
    prompt: VaultAccessPrompt,
    actor: Actor,
) -> WireResponse {
    let context = match authorizer.begin(prompt.clone(), actor.clone()).await {
        Ok(context) => context,
        Err(message) => {
            log::debug!("App broker vault authorization declined: {message}");
            record_access(&prompt, &actor, Outcome::Denied, None, Some(&message));
            authorizer
                .end(prompt, PromptOutcome::Failed(message.clone()))
                .await;
            return WireResponse::Failed { message };
        },
    };

    let job = prompt.clone();
    let result = tokio::task::spawn_blocking(move || serve_on_context(job, context))
        .await
        .unwrap_or_else(|e| Err(format!("Vault task failed: {e}")));

    let (response, outcome) = match result {
        Ok(response) => {
            record_access(&prompt, &actor, Outcome::Succeeded, Some(&response), None);
            (response, PromptOutcome::Succeeded)
        },
        Err(message) => {
            record_access(&prompt, &actor, Outcome::Failed, None, Some(&message));
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

/// Record one vault access. Values never appear: a read is named by its
/// `vault/item/credential` path, and a listing by its item count.
fn record_access(
    prompt: &VaultAccessPrompt,
    actor: &Actor,
    outcome: Outcome,
    response: Option<&WireResponse>,
    message: Option<&str>,
) {
    let vault_key = &prompt.vault_key;
    let (action, subject) = match &prompt.action {
        VaultAction::ListItems => (
            Action::VaultItemsListed,
            Subject::new(SubjectKind::Vault, vault_key.clone()),
        ),
        VaultAction::ReadSecret {
            item_key,
            credential_key,
        } => (
            Action::SecretRead,
            Subject::new(
                SubjectKind::Credential,
                format!("{vault_key}/{item_key}/{credential_key}"),
            ),
        ),
        VaultAction::ResolveSecrets { purpose, .. } => {
            let action = match purpose {
                ResolvePurpose::Exec => Action::SecretExec,
                ResolvePurpose::Inject => Action::SecretInject,
            };
            (action, Subject::new(SubjectKind::Vault, vault_key.clone()))
        },
    };

    let mut event = AuditEvent::new(audit::process_source(), action, outcome)
        .subject(subject)
        .actor(actor.clone())
        .detail("vault", vault_key.clone())
        .detail("via", "broker");
    if let VaultAction::ResolveSecrets { refs, .. } = &prompt.action {
        event = event.detail("secret_count", refs.len().to_string());
    }
    match response {
        Some(WireResponse::VaultItems { items }) => {
            event = event.detail("item_count", items.len().to_string());
        },
        Some(WireResponse::VaultSecret { value }) => {
            event = event.detail("found", value.is_some().to_string());
        },
        Some(WireResponse::ResolvedSecrets { values }) => {
            let resolved = values.iter().filter(|v| v.is_some()).count();
            event = event.detail("resolved_count", resolved.to_string());
        },
        _ => {},
    }
    if let Some(message) = message {
        event = event.message(message.to_string());
    }
    audit::record(event);
}

/// Load the vault from disk and serve the request on the app's context.
/// Read-only, so it does not touch the app's in-memory vault state.
fn serve_on_context(
    prompt: VaultAccessPrompt,
    context: ForeignContext,
) -> Result<WireResponse, String> {
    if let VaultAction::ResolveSecrets { refs, .. } = &prompt.action {
        return resolve_secrets(refs, context);
    }

    let mut vw = VaultWrapper::load(&vaults_dir(), Some(prompt.vault_key.clone()))
        .map_err(|e| format!("Failed to load vault: {e}"))?;
    vw.unlock_on(AuthContext::Foreign(context))
        .map_err(|e| format!("Failed to unlock vault: {e}"))?;

    match prompt.action {
        VaultAction::ListItems => Ok(WireResponse::VaultItems {
            items: collect_items(&vw)?,
        }),
        VaultAction::ReadSecret {
            item_key,
            credential_key,
        } => {
            let value = vw
                .get_secret(&item_key, &credential_key)
                .map_err(|e| format!("Failed to get secret: {e}"))?
                .map(|secret| secret.expose_secret().to_string());
            Ok(WireResponse::VaultSecret { value })
        },
        VaultAction::ResolveSecrets { .. } => unreachable!("handled above"),
    }
}

/// Resolve every reference, unlocking each distinct vault once on the app's
/// context. The result is positionally matched to `refs`. A reference whose
/// vault fails to load or unlock resolves to `None` rather than failing the
/// whole batch.
fn resolve_secrets(refs: &[VaultRef], context: ForeignContext) -> Result<WireResponse, String> {
    use std::collections::HashMap;

    let vaults_dir = vaults_dir();
    let mut vaults: HashMap<String, Option<VaultWrapper>> = HashMap::new();
    let mut values = Vec::with_capacity(refs.len());

    for r in refs {
        let vw = vaults.entry(r.vault_key.clone()).or_insert_with(|| {
            match VaultWrapper::load(&vaults_dir, Some(r.vault_key.clone())) {
                Ok(mut vw) => match vw.unlock_on(AuthContext::Foreign(context.clone())) {
                    Ok(()) => Some(vw),
                    Err(e) => {
                        log::error!("Failed to unlock vault {}: {e}", r.vault_key);
                        None
                    },
                },
                Err(e) => {
                    log::error!("Failed to load vault {}: {e}", r.vault_key);
                    None
                },
            }
        });

        let value = match vw {
            Some(vw) => match vw.get_secret(&r.item_key, &r.credential_key) {
                Ok(secret) => secret.map(|s| s.expose_secret().to_string()),
                Err(e) => {
                    log::error!(
                        "Failed to get secret {}/{}/{}: {e}",
                        r.vault_key,
                        r.item_key,
                        r.credential_key
                    );
                    None
                },
            },
            None => None,
        };
        values.push(value);
    }

    Ok(WireResponse::ResolvedSecrets { values })
}

fn collect_items(vw: &VaultWrapper) -> Result<Vec<BrokerVaultItem>, String> {
    let mut items: Vec<BrokerVaultItem> = vw
        .list_items()
        .map_err(|e| format!("Failed to list items: {e}"))?
        .into_iter()
        .map(|item| BrokerVaultItem {
            key: item.key.clone(),
            title: item.title.clone(),
            credentials: item
                .credentials
                .values()
                .map(|c| BrokerCredential {
                    key: c.key.clone(),
                    title: c.title.clone(),
                })
                .collect(),
        })
        .collect();
    items.sort_by_key(|a| a.title.to_lowercase());
    Ok(items)
}
