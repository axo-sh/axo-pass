use std::collections::BTreeMap;

use super::super::login_index::LoginIndex;
use super::super::placement::{PasskeyChoices, PlacementVault};
use super::super::wire::{
    WirePasskeyAccount, WirePrfRegistrationOutput, WirePrfValues, WireResponse,
};
use super::logins::write_vault_key;
use super::requests::b64_encode;
use super::serve::{AccessIds, Served, open_vault};
use super::{PasskeyAccountChoice, VaultAuthorizer};
use crate::audit::{self, Action, Actor, AuditEvent, Outcome, Subject, SubjectIds, SubjectKind};
use crate::core::auth::{AuthContext, ForeignContext};
use crate::secrets::vaults::passkey::signals::{self, Report};
use crate::secrets::vaults::{VaultCatalog, VaultHandle, passkey};

/// Location of the passkey a sign-in signed with.
pub(super) struct SignedPasskey {
    pub(super) vault_key: String,
    /// `vault/item/credential` path of the passkey.
    pub(super) credential: Option<String>,
}

/// Record a site report about a passkey relayed by the AutoFill extension, and
/// tell the app to refresh. Does not prompt. The report is held in memory
/// until the app writes it into the vaults at its next unlock.
pub(in super::super) async fn record_passkey_report(
    authorizer: &dyn VaultAuthorizer,
    report: Report,
    actor: Actor,
) -> WireResponse {
    let (rp_id, kind) = match &report {
        Report::Unknown { rp_id, .. } => (rp_id.clone(), "unknown"),
        Report::AllAccepted { rp_id, .. } => (rp_id.clone(), "all_accepted"),
        Report::Renamed { rp_id, .. } => (rp_id.clone(), "renamed"),
    };
    if rp_id.trim().is_empty() {
        return WireResponse::Failed {
            message: "The report names no website".to_string(),
        };
    }
    log::debug!("App broker request: passkey report {kind} for {rp_id}");

    let Some(at) = unix_now() else {
        return WireResponse::Failed {
            message: "The system clock is before 1970".to_string(),
        };
    };
    signals::record_pending(report, at);

    let event = AuditEvent::new(
        audit::process_source(),
        Action::PasskeyReported,
        Outcome::Succeeded,
    )
    .subject(Subject::new(SubjectKind::Credential, rp_id))
    .actor(actor)
    .detail("report", kind)
    .detail("via", "broker");
    audit::record_async(event).await;

    authorizer.passkey_reports_changed().await;
    WireResponse::Acknowledged
}

fn unix_now() -> Option<i64> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    i64::try_from(elapsed.as_secs()).ok()
}

/// The vaults and logins a passkey for `rp_id` may be stored in, for the
/// registration prompt. The logins come from the index, so a cold start offers
/// only "New login".
pub(in super::super) fn passkey_choices(
    vaults: &VaultCatalog,
    rp_id: &str,
    user_name: &str,
    index: &LoginIndex,
) -> PasskeyChoices {
    let places = vaults
        .list()
        .into_iter()
        .map(|(key, vh)| PlacementVault {
            name: vh.vault_name().map(String::from),
            key,
        })
        .collect();
    PasskeyChoices::build(
        rp_id,
        user_name,
        &index.places(),
        places,
        write_vault_key(vaults),
    )
}

/// The passkeys of `rp_id` from the login index, for the AutoFill extension's
/// account list. `indexed` is false when nothing has been indexed since the app
/// started. The listing reads no vault, but it is recorded since it tells the
/// extension which accounts exist for a site.
pub(in super::super) fn list_passkeys_locked(
    rp_id: &str,
    actor: &Actor,
    index: &LoginIndex,
) -> WireResponse {
    let found = index.passkeys_for(rp_id);
    let indexed = found.is_some();
    let passkeys: Vec<WirePasskeyAccount> = found
        .unwrap_or_default()
        .into_iter()
        .map(|p| WirePasskeyAccount {
            credential_id: b64_encode(&p.credential_id),
            user_name: p.user_name,
        })
        .collect();
    let event = AuditEvent::new(
        audit::process_source(),
        Action::ItemListed,
        Outcome::Succeeded,
    )
    .subject(Subject::new(SubjectKind::Credential, rp_id.to_string()))
    .actor(actor.clone())
    .detail("via", "broker")
    .detail("login_request", "list_passkeys")
    .detail("item_count", passkeys.len().to_string())
    .detail("indexed", indexed.to_string());
    audit::record(event);
    WireResponse::Passkeys { passkeys, indexed }
}

/// Register a passkey in `vault_key` on the app's context.
pub(super) fn create_passkey(
    vaults: &VaultCatalog,
    vault_key: &str,
    request: passkey::CreatePasskeyRequest,
    context: ForeignContext,
    rt: &tokio::runtime::Handle,
) -> Result<Served, String> {
    let mut vh = open_vault(vaults, vault_key, context)?;
    let response = rt
        .block_on(passkey::create_from_wire(vaults.files(), &mut vh, request))
        .map_err(|e| format!("Failed to register the passkey: {e}"))?;
    Ok(Served::new(
        WireResponse::PasskeyRegistered {
            credential_id: b64_encode(&response.credential_id),
            attestation_object: b64_encode(&response.attestation_object),
            prf: response.prf.as_ref().map(WirePrfRegistrationOutput::encode),
        },
        AccessIds::One(response.ids),
    ))
}

/// Sign an assertion challenge with a stored passkey. The credential may be in
/// any vault, so each is tried until one holds a passkey for the relying party.
///
/// Passkeys a site reported it no longer accepts are used only if no other
/// passkey matches. If `only_vault` is set, no other vault is unlocked.
/// `signed` is set to the passkey that signed. Its vault records the use. The
/// audit ids are those of the passkey that signed.
pub(super) fn assert_passkey(
    vaults: &VaultCatalog,
    request: passkey::AssertPasskeyRequest,
    only_vault: Option<&str>,
    context: ForeignContext,
    rt: &tokio::runtime::Handle,
    signed: &mut Option<SignedPasskey>,
) -> Result<Served, String> {
    let mut unlocked = unlock_for_passkeys(vaults, &context, only_vault);

    let mut last_error = None;
    // The first pass skips rejected passkeys. The second allows them.
    for skip_rejected in [true, false] {
        for (vault_key, vh) in unlocked.iter_mut() {
            let signals = vh.passkey_signals().unwrap_or_default();
            let candidates = matching_passkeys(vh, &request);
            let usable: Vec<&passkey::StoredPasskey> = candidates
                .iter()
                .filter(|s| !skip_rejected || !signals.rejects(s))
                .collect();
            if usable.is_empty() {
                continue;
            }
            let mut request = request.clone();
            if usable.len() < candidates.len() {
                request.allowed_credentials = usable
                    .iter()
                    .map(|s| s.passkey.credential_id.as_slice().to_vec())
                    .collect();
            }
            match rt.block_on(passkey::assert_from_wire(vaults.files(), vh, request)) {
                Ok(response) => {
                    let stored = usable.iter().find(|s| {
                        s.passkey.credential_id.as_slice() == &response.credential_id[..]
                    });
                    *signed = Some(SignedPasskey {
                        vault_key: vault_key.clone(),
                        credential: stored
                            .map(|s| format!("{vault_key}/{}/{}", s.item_key, s.credential_key)),
                    });
                    let ids = stored.map_or(AccessIds::None, |s| {
                        AccessIds::One(SubjectIds::credential(
                            s.vault_id,
                            s.item_id,
                            s.credential_id,
                        ))
                    });
                    return Ok(Served::new(
                        WireResponse::PasskeyAsserted {
                            credential_id: b64_encode(&response.credential_id),
                            user_handle: b64_encode(&response.user_handle),
                            authenticator_data: b64_encode(&response.authenticator_data),
                            signature: b64_encode(&response.signature),
                            prf: response.prf.as_ref().map(WirePrfValues::encode),
                        },
                        ids,
                    ));
                },
                Err(e) => last_error = Some(e.to_string()),
            }
        }
    }

    Err(last_error.unwrap_or_else(|| "No stored passkey matched the request".to_string()))
}

/// The passkeys `assert_passkey` could sign `request` with, for the user to
/// pick one. Rejected passkeys are left out unless every match is rejected,
/// which mirrors the order `assert_passkey` tries them in.
pub(super) fn passkey_candidates(
    vaults: &VaultCatalog,
    request: &passkey::AssertPasskeyRequest,
    context: ForeignContext,
) -> Vec<PasskeyAccountChoice> {
    let mut found = Vec::new();
    for (vault_key, mut vh) in unlock_for_passkeys(vaults, &context, None) {
        let vh = &mut vh;
        let signals = vh.passkey_signals().unwrap_or_default();
        for stored in matching_passkeys(vh, request) {
            found.push((vault_key.clone(), signals.rejects(&stored), stored));
        }
    }
    if found.iter().any(|(_, rejected, _)| !rejected) {
        found.retain(|(_, rejected, _)| !rejected);
    }
    let mut choices: Vec<PasskeyAccountChoice> = found
        .into_iter()
        .map(|(vault_key, _, stored)| PasskeyAccountChoice {
            credential_id: stored.passkey.credential_id.as_slice().to_vec(),
            user_name: stored
                .passkey
                .username
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| stored.item_key.clone()),
            vault_key,
        })
        .collect();
    choices.sort_by_key(|a| a.user_name.to_lowercase());
    choices
}

/// Load the vaults and unlock them on the app's context. If `only` is set,
/// only that vault is unlocked. Returns the vaults that unlocked, by key.
fn unlock_for_passkeys(
    vaults: &VaultCatalog,
    context: &ForeignContext,
    only: Option<&str>,
) -> BTreeMap<String, VaultHandle> {
    let mut unlocked = vaults.list();
    unlocked.retain(|vault_key, vh| {
        if only.is_some_and(|only| only != vault_key) {
            return false;
        }
        match vaults.unlock(vh, AuthContext::Foreign(context.clone())) {
            Ok(()) => true,
            Err(e) => {
                log::error!("Failed to unlock vault {vault_key} for a passkey assertion: {e}");
                false
            },
        }
    });
    unlocked
}

/// Stored passkeys of `vh` for the request relying party that its allow list
/// permits. An empty allow list permits every passkey of the relying party.
fn matching_passkeys(
    vh: &mut VaultHandle,
    request: &passkey::AssertPasskeyRequest,
) -> Vec<passkey::StoredPasskey> {
    passkey::list(vh)
        .unwrap_or_default()
        .into_iter()
        .filter(|s| s.passkey.rp_id == request.rp_id)
        .filter(|s| {
            request.allowed_credentials.is_empty()
                || request
                    .allowed_credentials
                    .iter()
                    .any(|id| id.as_slice() == s.passkey.credential_id.as_slice())
        })
        .collect()
}
