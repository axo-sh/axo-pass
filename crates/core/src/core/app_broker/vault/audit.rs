use super::super::wire::WireResponse;
use super::serve::AccessIds;
use super::{ClientIdentity, LoginPage, ResolvePurpose, VaultAccessPrompt, VaultAction};
use crate::audit::{self, Action, Actor, AuditEvent, Outcome, Subject, SubjectIds, SubjectKind};
use crate::secrets::vaults::format::short_id::ShortId;

/// Record a vault access. Reads are recorded by `vault/item/credential` path,
/// and listings by item count.
pub(super) fn record_access(
    prompt: &VaultAccessPrompt,
    actor: &Actor,
    outcome: Outcome,
    response: Option<&WireResponse>,
    ids: &AccessIds,
    message: Option<&str>,
) {
    audit::record(access_event(prompt, actor, outcome, response, ids, message));
}

/// Record a vault access that ended without a response or any entity ids.
pub(super) fn record_failure(
    prompt: &VaultAccessPrompt,
    actor: &Actor,
    outcome: Outcome,
    message: &str,
) {
    record_access(
        prompt,
        actor,
        outcome,
        None,
        &AccessIds::None,
        Some(message),
    );
}

/// Audit event of one vault access, for [`record_access`]. `ids` come from
/// the serve step.
pub(super) fn access_event(
    prompt: &VaultAccessPrompt,
    actor: &Actor,
    outcome: Outcome,
    response: Option<&WireResponse>,
    ids: &AccessIds,
    message: Option<&str>,
) -> AuditEvent {
    let vault_key = &prompt.vault_key;
    let (action, subject) = match &prompt.action {
        VaultAction::ListItems => (
            Action::ItemListed,
            Subject::new(SubjectKind::Vault, vault_key.clone()),
        ),
        VaultAction::ReadSecret {
            item_key,
            credential_key,
        } => (
            Action::CredentialRead,
            Subject::new(
                SubjectKind::Credential,
                format!("{vault_key}/{item_key}/{credential_key}"),
            ),
        ),
        VaultAction::ReadFile {
            item_key,
            credential_key,
            ..
        } => (
            Action::CredentialFileRead,
            Subject::new(
                SubjectKind::Credential,
                format!("{vault_key}/{item_key}/{credential_key}"),
            ),
        ),
        VaultAction::ListLogins { page, .. } => (
            Action::ItemListed,
            Subject::new(SubjectKind::Vault, page.host.clone()),
        ),
        VaultAction::FillLogin { record_id, .. } | VaultAction::GenerateTotp { record_id, .. } => (
            Action::CredentialRead,
            Subject::new(SubjectKind::Credential, record_id.clone()),
        ),
        VaultAction::SaveLogin { .. } => (
            Action::ItemCreated,
            Subject::new(SubjectKind::Vault, vault_key.clone()),
        ),
        VaultAction::UpdateLoginPassword { record_id, .. } => (
            Action::ItemUpdated,
            Subject::new(SubjectKind::Credential, record_id.clone()),
        ),
        VaultAction::ResolveSecrets { purpose, .. } => {
            let action = match purpose {
                ResolvePurpose::Exec => Action::CredentialExec,
                ResolvePurpose::Inject => Action::CredentialInject,
                ResolvePurpose::Read => Action::CredentialRead,
            };
            (action, Subject::new(SubjectKind::Vault, vault_key.clone()))
        },
        VaultAction::WriteSecret {
            item_key,
            credential_key,
        } => (
            Action::ItemUpdated,
            Subject::new(
                SubjectKind::Credential,
                format!("{vault_key}/{item_key}/{credential_key}"),
            ),
        ),
        VaultAction::ExportVaults { .. } => (
            Action::VaultExported,
            Subject::new(SubjectKind::Vault, vault_key.clone()),
        ),
        VaultAction::ImportVaults { .. } => (
            Action::VaultImported,
            Subject::new(SubjectKind::Vault, vault_key.clone()),
        ),
        VaultAction::ImportItems { .. } => (
            Action::VaultItemsImported,
            Subject::new(SubjectKind::Vault, vault_key.clone()),
        ),
        VaultAction::AddVault { path } => (
            Action::VaultLinked,
            Subject::new(SubjectKind::Vault, path.clone()),
        ),
        VaultAction::CreatePasskey { rp_id, .. } => (
            Action::PasskeyRegistered,
            Subject::new(SubjectKind::Credential, rp_id.clone()),
        ),
        VaultAction::AssertPasskey { rp_id, .. } => (
            Action::PasskeyAsserted,
            Subject::new(SubjectKind::Credential, rp_id.clone()),
        ),
    };

    // A write that created the item records `item.created` instead. The
    // serve step reports which through the response.
    let action = match (&prompt.action, response) {
        (VaultAction::WriteSecret { .. }, Some(WireResponse::VaultWritten { created: true })) => {
            Action::ItemCreated
        },
        _ => action,
    };

    let mut event = AuditEvent::new(audit::process_source(), action, outcome)
        .subject(subject)
        .actor(actor.clone())
        .detail("vault", vault_key.clone())
        .detail("via", "broker");
    event = access_ids(event, ids);
    if let VaultAction::ResolveSecrets { refs, .. } = &prompt.action {
        event = event.detail("secret_count", refs.len().to_string());
    }
    match &prompt.action {
        VaultAction::ListLogins { page, all } => {
            event = event.detail("login_request", "list");
            if *all {
                event = event.detail("all_logins", "true");
            }
            event = login_page_details(event, page);
        },
        VaultAction::FillLogin {
            page, unmatched, ..
        } => {
            event = event.detail("login_request", "fill");
            if *unmatched {
                event = event.detail("unmatched", "true");
            }
            event = login_page_details(event, page);
        },
        VaultAction::GenerateTotp { page, .. } => {
            event = event.detail("login_request", "totp");
            event = login_page_details(event, page);
        },
        VaultAction::SaveLogin { page, .. } => {
            event = event.detail("login_request", "save");
            event = login_page_details(event, page);
        },
        VaultAction::UpdateLoginPassword { page, .. } => {
            event = event.detail("login_request", "update");
            event = login_page_details(event, page);
        },
        _ => {},
    }
    event = client_details(event, &prompt.client);
    match response {
        Some(WireResponse::VaultItems { items }) => {
            event = event.detail("item_count", items.len().to_string());
        },
        Some(WireResponse::Logins { logins, others }) => {
            event = event.detail("item_count", (logins.len() + others.len()).to_string());
        },
        Some(WireResponse::VaultSecret { value }) => {
            event = event.detail("found", value.is_some().to_string());
        },
        Some(WireResponse::VaultFileRead { size, .. }) => {
            event = event.detail("size", size.to_string());
        },
        Some(WireResponse::ResolvedSecrets { values }) => {
            let resolved = values.iter().filter(|v| v.is_some()).count();
            event = event.detail("resolved_count", resolved.to_string());
        },
        Some(WireResponse::VaultWritten { created }) => {
            event = event.detail("created", created.to_string());
        },
        Some(WireResponse::VaultsExported {
            count,
            missing_blobs,
        }) => {
            event = event.detail("vault_count", count.to_string());
            if *missing_blobs > 0 {
                event = event.detail("missing_blobs", missing_blobs.to_string());
            }
        },
        Some(WireResponse::VaultsImported { keys }) => {
            event = event.detail("vault_count", keys.len().to_string());
        },
        Some(WireResponse::ItemsImported { vault_key, summary }) => {
            event = event
                .detail("imported_vault", vault_key.clone())
                .detail("item_count", summary.added.to_string())
                .detail("skipped_existing", summary.skipped_existing.to_string());
        },
        _ => {},
    }
    if let Some(message) = message {
        event = event.message(message.to_string());
    }
    event
}

/// Record `ids` in `event`. Each list holds distinct ids in request order.
fn access_ids(event: AuditEvent, ids: &AccessIds) -> AuditEvent {
    let all = match ids {
        AccessIds::None => return event,
        AccessIds::One(ids) => return event.subject_ids(*ids),
        AccessIds::Many(all) => all,
    };
    let list = |id: fn(&SubjectIds) -> Option<uuid::Uuid>| {
        let mut seen = Vec::new();
        for id in all.iter().filter_map(id) {
            if !seen.contains(&id) {
                seen.push(id);
            }
        }
        (!seen.is_empty()).then(|| {
            seen.iter()
                .map(|id| ShortId::encode_uuid(*id))
                .collect::<Vec<_>>()
                .join(",")
        })
    };
    event
        .maybe_detail("vault_ids", list(|ids| ids.vault_id))
        .maybe_detail("item_ids", list(|ids| ids.item_id))
        .maybe_detail("credential_ids", list(|ids| ids.credential_id))
}

/// The browser's name and signing team, and the extension the browser reported,
/// for a request that came through the browser host.
fn client_details(event: AuditEvent, client: &ClientIdentity) -> AuditEvent {
    let extension = |event: AuditEvent, extension: &Option<String>| match extension {
        Some(extension) => event.detail("extension", extension.clone()),
        None => event,
    };
    match client {
        ClientIdentity::Process => event,
        ClientIdentity::Browser {
            name,
            team_id,
            extension: reported,
        } => extension(
            event
                .detail("browser", name.clone())
                .detail("browser_team_id", team_id.clone()),
            reported,
        ),
        ClientIdentity::Unverified {
            extension: reported,
        } => extension(event.detail("browser", "unverified"), reported),
    }
}

/// The service host, the frame URL, and the top-level host of a login request.
fn login_page_details(event: AuditEvent, page: &LoginPage) -> AuditEvent {
    let event = event
        .detail("service_host", page.host.clone())
        .detail("frame_origin", page.frame_origin.clone());
    match &page.top_host {
        Some(top_host) => event.detail("top_host", top_host.clone()),
        None => event,
    }
}

/// Record a listing served from the index. It does not read vaults, so it is
/// not an access, but it still tells a client which accounts exist for a site.
pub(super) fn record_locked_listing(
    prompt: &VaultAccessPrompt,
    actor: &Actor,
    response: &WireResponse,
) {
    let VaultAction::ListLogins { page, .. } = &prompt.action else {
        return;
    };
    let mut event = AuditEvent::new(
        audit::process_source(),
        Action::ItemListed,
        Outcome::Succeeded,
    )
    .subject(Subject::new(SubjectKind::Vault, page.host.clone()))
    .actor(actor.clone())
    .detail("via", "broker")
    .detail("login_request", "list_locked");
    event = login_page_details(event, page);
    event = client_details(event, &prompt.client);
    if let WireResponse::LockedLogins { logins, indexed } = response {
        event = event
            .detail("item_count", logins.len().to_string())
            .detail("indexed", indexed.to_string());
    }
    audit::record(event);
}
