use std::sync::Arc;

use secrecy::ExposeSecret;

use super::super::in_flight::InFlightRequest;
use super::super::wire::WireResponse;
use super::super::{Authorizers, PromptOutcome};
use super::audit::{access_event, record_access};
use super::logins::serve_logins;
use super::manage::{add_external_vault, export_vaults, import_vaults};
use super::passkeys::{SignedPasskey, assert_passkey, create_passkey, passkey_candidates};
use super::secrets::{collect_items, resolve_secrets, write_secret};
use super::{VaultAccessPrompt, VaultAction, VaultAuthorizer, VaultPayload};
use crate::audit::{self, Actor, Outcome, SubjectIds};
use crate::core::auth::{AuthContext, ForeignContext};
use crate::secrets::vaults::{VaultCatalog, VaultHandle};

/// Response of a served request and the audit ids of the entities it acted on.
pub(super) struct Served {
    pub(super) response: WireResponse,
    pub(super) ids: AccessIds,
}

impl Served {
    pub(super) fn new(response: WireResponse, ids: AccessIds) -> Self {
        Self { response, ids }
    }
}

/// Audit ids an access event records. Known only once a vault is unlocked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) enum AccessIds {
    /// No entity, such as for a login listing or a vault that was never
    /// unlocked.
    #[default]
    None,
    /// One entity, recorded as `vault_id`, `item_id`, and `credential_id`.
    One(SubjectIds),
    /// Entities of a request that names several, recorded as comma-separated
    /// lists under `vault_ids`, `item_ids`, and `credential_ids`.
    Many(Vec<SubjectIds>),
}

/// Raise the app's prompt and return the context to unlock on. When the user
/// declines, the response to send instead.
async fn authorize(
    authorizer: &dyn VaultAuthorizer,
    prompt: &VaultAccessPrompt,
    actor: &Actor,
    in_flight: &InFlightRequest,
) -> Result<ForeignContext, WireResponse> {
    if in_flight.is_abandoned() {
        return Err(WireResponse::Cancelled);
    }
    // The app evaluates inside `begin`, holding the auth lock, so it is
    // dismissed rather than dropped when the client disconnects.
    let begin = authorizer.begin(prompt.clone(), actor.clone());
    let context = match in_flight.abandoning(begin, authorizer.abandon()).await {
        Ok(context) => context,
        Err(message) => {
            log::debug!("App broker vault authorization declined: {message}");
            record_access(
                prompt,
                actor,
                Outcome::Denied,
                None,
                &AccessIds::None,
                Some(&message),
            );
            authorizer
                .end(prompt.clone(), PromptOutcome::Failed(message.clone()))
                .await;
            return Err(WireResponse::Failed { message });
        },
    };
    // An import unlocks and writes one vault at a time on this context, so
    // invalidating it partway would leave some vaults imported and others not.
    if !matches!(prompt.action, VaultAction::ImportVaults { .. }) {
        in_flight.attach(&context);
    }
    Ok(context)
}

/// Serve a login request: a listing, a fill, a one-time code, a save, or a
/// password update. The same as [`authorize_and_serve`], plus one step: a
/// request the broker doubts is returned or written only after the user
/// confirms it, once the vault is open and the broker can tell. A login that
/// matches the page only through its `Url` field is one such case, and so is a
/// password update from a page the login is not stored for.
pub(in super::super) async fn authorize_and_serve_logins(
    authorizers: &Authorizers,
    prompt: VaultAccessPrompt,
    actor: Actor,
    payload: Option<VaultPayload>,
    in_flight: &InFlightRequest,
) -> WireResponse {
    let authorizer = &*authorizers.vault;
    let confirmer = &*authorizers.passphrase;
    let context = match authorize(authorizer, &prompt, &actor, in_flight).await {
        Ok(context) => context,
        Err(response) => return response,
    };

    let job = prompt.clone();
    let index = Arc::clone(&authorizers.logins);
    let vaults = authorizers.vaults.clone();
    let result =
        tokio::task::spawn_blocking(move || serve_logins(&vaults, &job, context, payload, &index))
            .await
            .unwrap_or_else(|e| Err(format!("Vault task failed: {e}")));

    // A login that was found records its ids even if the user does not
    // confirm it or the write fails.
    let (served, ids) = match result {
        Ok(served) => {
            let confirmed = match served.confirm {
                Some(question) => {
                    in_flight
                        .unless_abandoned(confirmer.confirm(question))
                        .await
                        == Some(true)
                },
                None => true,
            };
            let outcome = if !confirmed {
                log::debug!("App broker login request was not confirmed");
                Err(None)
            } else {
                match served.commit {
                    Some(commit) => tokio::task::spawn_blocking(commit)
                        .await
                        .unwrap_or_else(|e| Err(format!("Vault task failed: {e}")))
                        .map_err(Some),
                    None => Ok(served.response),
                }
            };
            (outcome, served.ids)
        },
        Err(message) => (Err(Some(message)), AccessIds::None),
    };

    let (response, outcome) = match served {
        Ok(response) => {
            record_access(
                &prompt,
                &actor,
                Outcome::Succeeded,
                Some(&response),
                &ids,
                None,
            );
            (response, PromptOutcome::Succeeded)
        },
        Err(None) => {
            record_access(
                &prompt,
                &actor,
                Outcome::Denied,
                None,
                &ids,
                Some("Not confirmed"),
            );
            (WireResponse::Cancelled, PromptOutcome::Cancelled)
        },
        Err(Some(message)) => {
            record_access(&prompt, &actor, Outcome::Failed, None, &ids, Some(&message));
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

pub(in super::super) async fn authorize_and_serve(
    authorizer: &dyn VaultAuthorizer,
    vaults: &VaultCatalog,
    mut prompt: VaultAccessPrompt,
    actor: Actor,
    mut payload: Option<VaultPayload>,
    in_flight: &InFlightRequest,
) -> WireResponse {
    let context = match authorize(authorizer, &prompt, &actor, in_flight).await {
        Ok(context) => context,
        Err(response) => return response,
    };

    // A registration is stored where the user chose in the prompt. The choice
    // is checked against what the prompt offered.
    if let VaultAction::CreatePasskey { choices, .. } = &prompt.action {
        let chosen = match authorizer.passkey_placement(&prompt).await {
            Some(placement) => choices.validate(placement),
            None => Ok(choices.default_placement()),
        };
        match chosen {
            Ok(placement) => {
                prompt.vault_key = placement.vault_key.clone();
                if let Some(VaultPayload::CreatePasskey(create)) = payload.as_mut() {
                    create.request.target = placement.target();
                }
            },
            Err(message) => {
                record_access(
                    &prompt,
                    &actor,
                    Outcome::Failed,
                    None,
                    &AccessIds::None,
                    Some(&message),
                );
                authorizer
                    .end(prompt, PromptOutcome::Failed(message.clone()))
                    .await;
                return WireResponse::Failed { message };
            },
        }
    }

    // A sign-in with no account list from the extension asks the user to pick
    // one here, if several passkeys match. The chosen passkey and its vault
    // are the only ones used to sign.
    if let Some(VaultPayload::AssertPasskey(assert)) = payload.as_mut()
        && assert.choose_account
    {
        let request = assert.request.clone();
        let candidates_context = context.clone();
        let candidates_vaults = vaults.clone();
        let candidates = tokio::task::spawn_blocking(move || {
            passkey_candidates(&candidates_vaults, &request, candidates_context)
        })
        .await
        .unwrap_or_default();
        let chosen = if candidates.len() > 1 {
            let choose = authorizer.choose_passkey(&prompt, candidates.clone());
            match in_flight.unless_abandoned(choose).await {
                Some(index) => index
                    .and_then(|index| candidates.get(index))
                    .map(Some)
                    .ok_or("No account chosen"),
                None => Err("Client disconnected during the account choice"),
            }
        } else {
            Ok(candidates.first())
        };
        match chosen {
            Ok(Some(account)) => {
                assert.request.allowed_credentials = vec![account.credential_id.clone()];
                assert.vault_key = Some(account.vault_key.clone());
            },
            Ok(None) => {},
            Err(message) => {
                log::debug!("App broker passkey account was not chosen: {message}");
                record_access(
                    &prompt,
                    &actor,
                    Outcome::Cancelled,
                    None,
                    &AccessIds::None,
                    Some(message),
                );
                authorizer.end(prompt, PromptOutcome::Cancelled).await;
                return WireResponse::Cancelled;
            },
        }
    }

    let job = prompt.clone();
    let rt = tokio::runtime::Handle::current();
    let vaults = vaults.clone();
    let (result, signed) = tokio::task::spawn_blocking(move || {
        let mut signed = None;
        let result = serve_on_context(&vaults, job, context, payload, rt, &mut signed);
        (result, signed)
    })
    .await
    .unwrap_or_else(|e| (Err(format!("Vault task failed: {e}")), None));
    // A sign-in can use any vault, so its prompt names none until the vault
    // it wrote is known. `end` then reloads only that vault.
    if let Some(signed) = &signed {
        prompt.vault_key = signed.vault_key.clone();
    }

    let (response, outcome) = match result {
        Ok(Served { response, ids }) => {
            let mut event = access_event(
                &prompt,
                &actor,
                Outcome::Succeeded,
                Some(&response),
                &ids,
                None,
            );
            if let Some(credential) = signed.and_then(|s| s.credential) {
                event = event.detail("credential", credential);
            }
            audit::record(event);
            (response, PromptOutcome::Succeeded)
        },
        Err(message) => {
            record_access(
                &prompt,
                &actor,
                Outcome::Failed,
                None,
                &AccessIds::None,
                Some(&message),
            );
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

/// Load the vault from disk and serve the request on the app's context.
///
/// The vault is loaded fresh from disk, so this does not touch the app's
/// in-memory vault state. A write runs in a transaction that reloads the vault
/// under the vault locks, as every app edit does, so neither replaces the
/// other's save.
/// `signed` is set to the passkey a sign-in signed with, since its prompt does
/// not name a vault. The audit ids are those of the unlocked vault data.
pub(super) fn serve_on_context(
    vaults: &VaultCatalog,
    prompt: VaultAccessPrompt,
    context: ForeignContext,
    payload: Option<VaultPayload>,
    rt: tokio::runtime::Handle,
    signed: &mut Option<SignedPasskey>,
) -> Result<Served, String> {
    match &prompt.action {
        VaultAction::ResolveSecrets { refs, .. } => return resolve_secrets(vaults, refs, context),
        VaultAction::ListLogins { .. }
        | VaultAction::FillLogin { .. }
        | VaultAction::GenerateTotp { .. }
        | VaultAction::SaveLogin { .. }
        | VaultAction::UpdateLoginPassword { .. } => {
            return Err("Login requests are served by serve_logins".to_string());
        },
        VaultAction::CreatePasskey { .. } => {
            let Some(VaultPayload::CreatePasskey(p)) = payload else {
                return Err("Missing passkey registration payload".to_string());
            };
            return create_passkey(vaults, &prompt.vault_key, p.request, context, &rt);
        },
        VaultAction::AssertPasskey { .. } => {
            let Some(VaultPayload::AssertPasskey(p)) = payload else {
                return Err("Missing passkey assertion payload".to_string());
            };
            return assert_passkey(
                vaults,
                p.request,
                p.vault_key.as_deref(),
                context,
                &rt,
                signed,
            );
        },
        VaultAction::ExportVaults { vault_keys } => {
            let Some(VaultPayload::Export(export)) = payload else {
                return Err("Missing export payload".to_string());
            };
            return export_vaults(vaults, vault_keys, export, context);
        },
        VaultAction::ImportVaults { .. } => {
            let Some(VaultPayload::Import(import)) = payload else {
                return Err("Missing import payload".to_string());
            };
            return import_vaults(vaults, import, context);
        },
        VaultAction::AddVault { path } => return add_external_vault(vaults, path, context),
        _ => {},
    }

    let write = match payload {
        Some(VaultPayload::Write(write)) => Some(write),
        None => None,
        Some(_) => return Err("Wrong payload for this vault action".to_string()),
    };

    let vh = open_vault(vaults, &prompt.vault_key, context)?;

    match prompt.action {
        VaultAction::ListItems => Ok(Served::new(
            WireResponse::VaultItems {
                items: collect_items(&vh)?,
            },
            AccessIds::One(SubjectIds::vault(vh.vault_id()?)),
        )),
        VaultAction::ReadSecret {
            item_key,
            credential_key,
        } => {
            let value = vh
                .get_secret(&item_key, &credential_key)
                .map_err(|e| format!("Failed to get secret: {e}"))?
                .map(|secret| secret.expose_secret().to_string());
            Ok(Served::new(
                WireResponse::VaultSecret { value },
                AccessIds::One(vh.credential_ids(&item_key, &credential_key)?),
            ))
        },
        VaultAction::WriteSecret {
            item_key,
            credential_key,
        } => {
            let payload = write.ok_or("Missing write payload")?;
            let (created, ids) = vaults
                .files()
                .write_unlocked(&vh, |fresh| {
                    let created = write_secret(fresh, &item_key, &credential_key, payload)?;
                    Ok::<_, String>((created, fresh.credential_ids(&item_key, &credential_key)?))
                })?
                .value;
            Ok(Served::new(
                WireResponse::VaultWritten { created },
                AccessIds::One(ids),
            ))
        },
        VaultAction::ResolveSecrets { .. }
        | VaultAction::ListLogins { .. }
        | VaultAction::FillLogin { .. }
        | VaultAction::GenerateTotp { .. }
        | VaultAction::SaveLogin { .. }
        | VaultAction::UpdateLoginPassword { .. }
        | VaultAction::ExportVaults { .. }
        | VaultAction::ImportVaults { .. }
        | VaultAction::AddVault { .. }
        | VaultAction::CreatePasskey { .. }
        | VaultAction::AssertPasskey { .. } => unreachable!("handled above"),
    }
}

/// Load a vault by key and unlock it on the app's context. This can prompt, so
/// a write calls it before the transaction takes the vault locks.
pub(super) fn open_vault(
    vaults: &VaultCatalog,
    vault_key: &str,
    context: ForeignContext,
) -> Result<VaultHandle, String> {
    vaults
        .open(vault_key, AuthContext::Foreign(context))
        .map_err(|e| format!("Failed to open vault {vault_key}: {e}"))
}
