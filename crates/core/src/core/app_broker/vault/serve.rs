use std::sync::Arc;

use super::super::in_flight::InFlightRequest;
use super::super::wire::WireResponse;
use super::super::{Authorizers, PromptOutcome};
use super::audit::{access_event, record_access, record_failure};
use super::logins::serve_logins;
use super::manage::{add_external_vault, export_vaults, import_vaults};
use super::passkeys::{
    Ended, SignedPasskey, assert_passkey, choose_account, choose_placement, create_passkey,
};
use super::secrets::{list_items, read_secret, resolve_secrets, write_vault_secret};
use super::{
    ClientIdentity, VaultAccessPrompt, VaultAction, VaultAuthorization, VaultAuthorizer,
    VaultPayload,
};
use crate::audit::{self, Actor, Outcome, SubjectIds};
use crate::core::auth::{AuthContext, ForeignContext};
use crate::secrets::vaults::{VaultCatalog, VaultHandle};

/// Response of a served request and the audit ids of the entities it acted on.
pub(super) struct Served {
    pub(super) response: WireResponse,
    pub(super) ids: AccessIds,
    /// WebAuthn credential id of the passkey a registration stored or a
    /// sign-in signed with.
    pub(super) passkey_credential_id: Option<Vec<u8>>,
}

impl Served {
    pub(super) fn new(response: WireResponse, ids: AccessIds) -> Self {
        Self {
            response,
            ids,
            passkey_credential_id: None,
        }
    }

    /// Set the WebAuthn credential id of the passkey the request acted on.
    pub(super) fn passkey(mut self, credential_id: Vec<u8>) -> Self {
        self.passkey_credential_id = Some(credential_id);
        self
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
) -> Result<VaultAuthorization, WireResponse> {
    if in_flight.is_abandoned() {
        return Err(WireResponse::Cancelled);
    }
    // The app evaluates inside `begin`, holding the auth lock, so it is
    // dismissed rather than dropped when the client disconnects.
    let begin = authorizer.begin(prompt.clone(), actor.clone());
    let authorization = match in_flight.abandoning(begin, authorizer.abandon()).await {
        Ok(authorization) => authorization,
        Err(message) => {
            log::debug!("App broker vault authorization declined: {message}");
            record_failure(prompt, actor, Outcome::Denied, &message);
            authorizer
                .end(prompt.clone(), PromptOutcome::Failed(message.clone()))
                .await;
            return Err(WireResponse::Failed { message });
        },
    };
    // An import unlocks and writes one vault at a time on this context, so
    // invalidating it partway would leave some vaults imported and others not.
    if !matches!(prompt.action, VaultAction::ImportVaults { .. }) {
        in_flight.attach(&authorization.context);
    }
    Ok(authorization)
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
    let VaultAuthorization { context, reused } =
        match authorize(authorizer, &prompt, &actor, in_flight).await {
            Ok(authorization) => authorization,
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

    let mut notify = None;
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
            if reused {
                notify = reused_fill_account(&prompt, &response);
            }
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
    authorizer.end(prompt.clone(), outcome).await;
    if let Some(account) = notify {
        authorizer.notify_preapproved(prompt, account).await;
    }
    response
}

/// The account to report for a fill served from an earlier approval, or `None`
/// if the request is not one to report. Only fills for a verified browser are
/// reported. The username is the one filled, and the client's label for the
/// login stands in when the login has no username.
fn reused_fill_account(
    prompt: &VaultAccessPrompt,
    response: &WireResponse,
) -> Option<Option<String>> {
    let VaultAction::FillLogin { account, .. } = &prompt.action else {
        return None;
    };
    if !matches!(prompt.client, ClientIdentity::Browser { .. }) {
        return None;
    }
    let WireResponse::LoginFill { username, .. } = response else {
        return None;
    };
    Some(username.clone().or_else(|| account.clone()))
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
        Ok(authorization) => authorization.context,
        Err(response) => return response,
    };

    if let Some(ended) = choose_placement(authorizer, &mut prompt, &mut payload).await {
        return end_early(authorizer, prompt, &actor, ended).await;
    }
    if let Some(ended) = choose_account(
        authorizer,
        vaults,
        context.clone(),
        &prompt,
        &mut payload,
        in_flight,
    )
    .await
    {
        return end_early(authorizer, prompt, &actor, ended).await;
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
        Ok(Served {
            response,
            ids,
            passkey_credential_id,
        }) => {
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
            if let Some(id) = &passkey_credential_id {
                event = event.passkey_credential_id(id);
            }
            audit::record(event);
            (response, PromptOutcome::Succeeded)
        },
        Err(message) => {
            record_failure(&prompt, &actor, Outcome::Failed, &message);
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

/// Record a request that a passkey step ended, take the prompt down, and
/// return the response to send. A failed response ends the prompt as failed.
/// Any other response ends it as cancelled.
async fn end_early(
    authorizer: &dyn VaultAuthorizer,
    prompt: VaultAccessPrompt,
    actor: &Actor,
    ended: Ended,
) -> WireResponse {
    let (outcome, prompt_outcome) = match &ended.response {
        WireResponse::Failed { message } => {
            (Outcome::Failed, PromptOutcome::Failed(message.clone()))
        },
        _ => (Outcome::Cancelled, PromptOutcome::Cancelled),
    };
    record_failure(&prompt, actor, outcome, &ended.message);
    authorizer.end(prompt, prompt_outcome).await;
    ended.response
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
    let vault_key = prompt.vault_key;
    match prompt.action {
        VaultAction::ListItems => list_items(vaults, &vault_key, payload, context),
        VaultAction::ReadSecret {
            item_key,
            credential_key,
        } => read_secret(
            vaults,
            &vault_key,
            &item_key,
            &credential_key,
            payload,
            context,
        ),
        VaultAction::WriteSecret {
            item_key,
            credential_key,
        } => write_vault_secret(
            vaults,
            &vault_key,
            &item_key,
            &credential_key,
            payload,
            context,
        ),
        VaultAction::ResolveSecrets { refs, .. } => resolve_secrets(vaults, &refs, context),
        VaultAction::ListLogins { .. }
        | VaultAction::FillLogin { .. }
        | VaultAction::GenerateTotp { .. }
        | VaultAction::SaveLogin { .. }
        | VaultAction::UpdateLoginPassword { .. } => {
            Err("Login requests are served by serve_logins".to_string())
        },
        VaultAction::CreatePasskey { .. } => {
            create_passkey(vaults, &vault_key, payload, context, &rt)
        },
        VaultAction::AssertPasskey { .. } => assert_passkey(vaults, payload, context, &rt, signed),
        VaultAction::ExportVaults { vault_keys } => {
            export_vaults(vaults, &vault_keys, payload, context)
        },
        VaultAction::ImportVaults { .. } => import_vaults(vaults, payload, context),
        VaultAction::AddVault { path } => add_external_vault(vaults, &path, context),
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

#[cfg(test)]
mod tests {
    use super::super::LoginPage;
    use super::*;

    fn fill(client: ClientIdentity, account: Option<&str>) -> VaultAccessPrompt {
        VaultAccessPrompt {
            vault_key: String::new(),
            caller: None,
            caller_chain: Vec::new(),
            client,
            action: VaultAction::FillLogin {
                page: LoginPage::parse("https://github.com", "https://github.com", None).unwrap(),
                record_id: "r".to_string(),
                account: account.map(String::from),
                unmatched: false,
            },
        }
    }

    fn firefox() -> ClientIdentity {
        ClientIdentity::Browser {
            name: "Firefox".to_string(),
            team_id: "43AQ936H96".to_string(),
            extension: None,
        }
    }

    fn filled(username: Option<&str>) -> WireResponse {
        WireResponse::LoginFill {
            username: username.map(String::from),
            password: "pw".to_string(),
        }
    }

    #[test]
    fn reports_reused_fill_for_verified_browser() {
        assert_eq!(
            reused_fill_account(&fill(firefox(), Some("label")), &filled(Some("tp"))),
            Some(Some("tp".to_string()))
        );
        assert_eq!(
            reused_fill_account(&fill(firefox(), Some("label")), &filled(None)),
            Some(Some("label".to_string()))
        );
    }

    #[test]
    fn reports_nothing_for_other_clients_or_requests() {
        for client in [
            ClientIdentity::Process,
            ClientIdentity::Unverified { extension: None },
        ] {
            assert_eq!(
                reused_fill_account(&fill(client, None), &filled(Some("tp"))),
                None
            );
        }
        let mut listing = fill(firefox(), None);
        listing.action = VaultAction::ListLogins {
            page: LoginPage::parse("https://github.com", "https://github.com", None).unwrap(),
            all: false,
        };
        assert_eq!(
            reused_fill_account(&listing, &WireResponse::Acknowledged),
            None
        );
    }
}
