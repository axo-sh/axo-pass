use super::super::ConfirmPrompt;
use super::super::login_index::LoginIndex;
use super::super::wire::WireResponse;
use super::audit::record_locked_listing;
use super::serve::{AccessIds, open_vault};
use super::{
    LoginPage, SaveLoginPayload, UpdateLoginPayload, VaultAccessPrompt, VaultAction, VaultPayload,
};
use crate::audit::{Actor, SubjectIds};
use crate::core::auth::{AuthContext, ForeignContext};
use crate::secrets::vaults::{DEFAULT_VAULT, Site, VaultCatalog, VaultHandle, autofill};

/// Result of a login request. Includes a question for the user if the response
/// requires user confirmation.
pub(super) struct LoginResult {
    pub(super) response: WireResponse,
    pub(super) confirm: Option<ConfirmPrompt>,
    /// Vault write that runs after the user confirms. Its result replaces
    /// `response`.
    pub(super) commit: Option<Commit>,
    /// Audit ids of the login the request used.
    pub(super) ids: AccessIds,
}

type Commit = Box<dyn FnOnce() -> Result<WireResponse, String> + Send>;

impl LoginResult {
    fn new(response: WireResponse, ids: AccessIds) -> Self {
        Self {
            response,
            confirm: None,
            commit: None,
            ids,
        }
    }
}

/// Audit ids of login `item`, read from its record id. The credential is the
/// login password.
fn login_ids(item: &autofill::AutofillItem) -> SubjectIds {
    autofill::parse_record_id(&item.record_id)
        .map(|(vault_id, item_id, credential_id)| {
            SubjectIds::credential(vault_id, item_id, credential_id)
        })
        .unwrap_or_default()
}

/// Serve a login request on the app's context. Vaults that fail to load or
/// unlock are skipped rather than failing the request.
pub(super) fn serve_logins(
    vaults: &VaultCatalog,
    prompt: &VaultAccessPrompt,
    context: ForeignContext,
    payload: Option<VaultPayload>,
    index: &LoginIndex,
) -> Result<LoginResult, String> {
    match (&prompt.action, payload) {
        (VaultAction::SaveLogin { page, username }, Some(VaultPayload::SaveLogin(save))) => {
            return save_login(
                vaults,
                prompt,
                page,
                username.as_deref(),
                save,
                context,
                index,
            );
        },
        (
            VaultAction::UpdateLoginPassword {
                page, record_id, ..
            },
            Some(VaultPayload::UpdateLogin(update)),
        ) => return update_login_password(vaults, page, record_id, update, context),
        (VaultAction::SaveLogin { .. } | VaultAction::UpdateLoginPassword { .. }, _) => {
            return Err("Missing login payload".to_string());
        },
        _ => {},
    }

    let mut logins = Vec::new();
    let mut everything = Vec::new();

    for (vault_key, mut vh) in vaults.list() {
        if let Err(e) = vaults.unlock(&mut vh, AuthContext::Foreign(context.clone())) {
            log::error!("Failed to unlock vault {vault_key}: {e}");
            continue;
        }
        let vh = &mut vh;
        match &prompt.action {
            VaultAction::ListLogins { page, all } => {
                match autofill::collect_items(vh, Some(&page.frame_url)) {
                    Ok(found) => logins.extend(found),
                    Err(e) => log::error!("Failed to collect logins in {vault_key}: {e}"),
                }
                if *all {
                    match autofill::collect_items(vh, None) {
                        Ok(found) => everything.extend(found),
                        Err(e) => log::error!("Failed to collect logins in {vault_key}: {e}"),
                    }
                }
            },
            action => {
                if let Some(served) = serve_record(vh, action)? {
                    return Ok(served);
                }
            },
        }
    }

    match prompt.action {
        VaultAction::ListLogins { .. } => {
            logins.sort_by_key(autofill::AutofillItem::sort_key);
            // Only logins set up for AutoFill are listed. An item with a
            // confidential field but no website is a secret, not a login.
            everything.retain(|item| {
                !item.websites.is_empty() && !logins.iter().any(|m| m.record_id == item.record_id)
            });
            everything.sort_by_key(|item| item.title.to_lowercase());
            // A listing names many logins and uses none, so it records no ids.
            Ok(LoginResult::new(
                WireResponse::Logins {
                    logins: logins
                        .iter()
                        .filter_map(autofill::AutofillItem::summary)
                        .collect(),
                    others: everything
                        .iter()
                        .map(autofill::AutofillItem::other)
                        .collect(),
                },
                AccessIds::None,
            ))
        },
        _ => Err("No login matches that record on this page".to_string()),
    }
}

/// Serve a fill or a one-time code from a vault handle, when the record is a
/// login in it that matches the page. The match is decided here from the vault
/// and does not rely on the client's claim.
fn serve_record(vh: &VaultHandle, action: &VaultAction) -> Result<Option<LoginResult>, String> {
    use secrecy::ExposeSecret;

    let (page, record_id, totp, unmatched) = match action {
        VaultAction::FillLogin {
            page,
            record_id,
            unmatched,
            ..
        } => (page, record_id, false, *unmatched),
        VaultAction::GenerateTotp { page, record_id } => (page, record_id, true, false),
        _ => return Err("Not a login record request".to_string()),
    };
    let found = autofill::find_login(vh, record_id, &page.frame_url)
        .map_err(|e| format!("Failed to look up the login: {e}"))?;
    // A login picked from the list of logins that do not match is filled only
    // after the user confirms it.
    let (item, other_site) = match found {
        Some(item) => (item, false),
        None if unmatched => {
            match autofill::find_login_record(vh, record_id)
                .map_err(|e| format!("Failed to look up the login: {e}"))?
            {
                Some(item) => (item, true),
                None => return Ok(None),
            }
        },
        None => return Ok(None),
    };

    let confirm = other_site.then(|| ConfirmPrompt {
        description: Some(format!(
            "\"{}\" is saved for {}, not {}.\n\nFill it on {}?",
            item.title,
            stored_hosts(&item),
            page.host,
            page.host
        )),
        ok_label: Some("Fill".to_string()),
        cancel_label: Some("Cancel".to_string()),
    });

    // A one-time code is read from the TOTP credential, not the password.
    let mut ids = login_ids(&item);
    let response = if totp {
        let code = autofill::login_totp(vh, &item).map_err(|e| e.to_string())?;
        ids.credential_id = vh
            .get_item_overview(&item.item_key)?
            .and_then(|overview| overview.autofill.totp_credential(overview))
            .map(|cred| cred.id);
        WireResponse::TotpCode { code }
    } else {
        let secrets = autofill::read_login(vh, &item)
            .map_err(|e| format!("Failed to read the login: {e}"))?
            .ok_or_else(|| "That login no longer has a password".to_string())?;
        WireResponse::LoginFill {
            username: secrets.username,
            password: secrets.password.expose_secret().to_string(),
        }
    };
    Ok(Some(LoginResult {
        response,
        confirm,
        commit: None,
        ids: AccessIds::One(ids),
    }))
}

/// The hosts a login is stored for, as a comma-separated list for a question to
/// the user.
fn stored_hosts(item: &autofill::AutofillItem) -> String {
    let sites: Vec<String> = item
        .websites
        .iter()
        .map(|website| Site::parse(&website.url).map_or(website.url.clone(), |s| s.host))
        .collect();
    if sites.is_empty() {
        "no website".to_string()
    } else {
        sites.join(", ")
    }
}

/// Save a captured login as a new item in the vault the prompt named.
pub(super) fn save_login(
    vaults: &VaultCatalog,
    prompt: &VaultAccessPrompt,
    page: &LoginPage,
    username: Option<&str>,
    save: SaveLoginPayload,
    context: ForeignContext,
    index: &LoginIndex,
) -> Result<LoginResult, String> {
    let vh = open_vault(vaults, &prompt.vault_key, context)?;
    let item = vaults
        .files()
        .write_unlocked(&vh, |vh| {
            autofill::save_login(vh, &page.frame_origin, username, save.password)
                .map_err(|e| format!("Failed to write login: {e}"))
        })?
        .value;

    let record_id = item.record_id.clone();
    let ids = SubjectIds {
        credential_id: None,
        ..login_ids(&item)
    };
    index.upsert(item);
    Ok(LoginResult::new(
        WireResponse::LoginSaved { record_id },
        AccessIds::One(ids),
    ))
}

/// Search all vaults for the login `record_id` and prepare to replace its
/// password. The login may be stored for a different site than `page`. In that
/// case the user is asked to confirm. The write is returned as a commit and
/// runs only after the user confirms.
pub(super) fn update_login_password(
    vaults: &VaultCatalog,
    page: &LoginPage,
    record_id: &str,
    update: UpdateLoginPayload,
    context: ForeignContext,
) -> Result<LoginResult, String> {
    let mut found = None;
    for (vault_key, mut vh) in vaults.list() {
        if let Err(e) = vaults.unlock(&mut vh, AuthContext::Foreign(context.clone())) {
            log::error!("Failed to unlock vault {vault_key}: {e}");
            continue;
        }
        match autofill::find_login_record(&vh, record_id) {
            Ok(Some(item)) => {
                found = Some((vh, item));
                break;
            },
            Ok(None) => {},
            Err(e) => log::error!("Failed to look up a login in {vault_key}: {e}"),
        }
    }
    let Some((vh, item)) = found else {
        return Err("No login matches that record".to_string());
    };

    let confirm = (!autofill::is_stored_for(&item, &page.frame_url)).then(|| {
        let stored = stored_hosts(&item);
        ConfirmPrompt {
            description: Some(format!(
                "A form on {host} submitted a new password for \"{title}\", which is saved for \
                 {stored}, not {host}.\n\nUpdate its password?",
                host = page.host,
                title = item.title,
            )),
            ok_label: Some("Update".to_string()),
            cancel_label: Some("Cancel".to_string()),
        }
    });

    // The copy read here only builds the prompt. The commit reloads the vault
    // in its own transaction after the user confirms, so an edit saved while
    // the prompt is shown is kept.
    let ids = AccessIds::One(login_ids(&item));
    let files = vaults.files().clone();
    let commit: Commit = Box::new(move || {
        files.write_unlocked(&vh, |fresh| {
            autofill::update_login_password(fresh, &item, update.password)
                .map_err(|e| format!("Failed to update the password: {e}"))
        })?;
        Ok(WireResponse::Acknowledged)
    });
    Ok(LoginResult {
        response: WireResponse::Acknowledged,
        confirm,
        commit: Some(commit),
        ids,
    })
}

/// The accounts for `page` from the login index, for a client that may list
/// without a prompt. `indexed` is false when nothing has been indexed since the
/// app started, so the client knows to ask with a prompt instead.
pub(in super::super) fn list_logins_locked(
    prompt: &VaultAccessPrompt,
    actor: &Actor,
    index: &LoginIndex,
) -> WireResponse {
    let VaultAction::ListLogins { page, .. } = &prompt.action else {
        return WireResponse::Failed {
            message: "Not a login listing".to_string(),
        };
    };
    let found = index.lookup(&page.frame_url);
    let response = WireResponse::LockedLogins {
        indexed: found.is_some(),
        logins: found.unwrap_or_default(),
    };
    record_locked_listing(prompt, actor, &response);
    response
}

/// The vault a new item from a client is written to: the default vault when it
/// exists or there are no vaults, otherwise the first one. The broker names
/// this vault in the prompt, so it is chosen before the prompt rather than
/// after.
pub(in super::super) fn write_vault_key(vaults: &VaultCatalog) -> String {
    let keys: Vec<String> = vaults.list().into_keys().collect();
    if keys.is_empty() || keys.iter().any(|k| k == DEFAULT_VAULT) {
        DEFAULT_VAULT.to_string()
    } else {
        keys.into_iter().next().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;
    use crate::secrets::vaults::MatchKind;

    fn vault_with_github() -> (VaultHandle, String) {
        let mut vh = VaultHandle::new_for_test("personal");
        autofill::write_login(
            &mut vh,
            autofill::LoginWrite {
                item_key: "github",
                title: "GitHub",
                password_key: "password",
                password: SecretString::from("pw"),
                username: Some("tp"),
                websites: &["github.com".to_string()],
                match_kind: MatchKind::Domain,
            },
        )
        .unwrap();
        let record_id = autofill::collect_items(&vh, None).unwrap()[0]
            .record_id
            .clone();
        (vh, record_id)
    }

    fn fill(record_id: &str, frame_url: &str, unmatched: bool) -> VaultAction {
        VaultAction::FillLogin {
            page: LoginPage::parse(frame_url, frame_url, None).unwrap(),
            record_id: record_id.to_string(),
            account: None,
            unmatched,
        }
    }

    #[test]
    fn fill_on_matching_site_needs_no_question() {
        let (vh, record_id) = vault_with_github();
        let served = serve_record(&vh, &fill(&record_id, "https://gist.github.com", false))
            .unwrap()
            .unwrap();
        assert!(served.confirm.is_none());
    }

    #[test]
    fn cross_site_fill_needs_client_opt_in() {
        let (vh, record_id) = vault_with_github();
        let page = "https://example.org";
        assert!(
            serve_record(&vh, &fill(&record_id, page, false))
                .unwrap()
                .is_none()
        );

        let served = serve_record(&vh, &fill(&record_id, page, true))
            .unwrap()
            .unwrap();
        let question = served.confirm.expect("the user must confirm");
        let text = question.description.unwrap();
        assert!(
            text.contains("github.com") && text.contains("example.org"),
            "{text}"
        );
        assert!(matches!(served.response, WireResponse::LoginFill { .. }));
    }

    #[test]
    fn unmatched_fill_still_needs_record_that_exists() {
        let (vh, _) = vault_with_github();
        let missing = format!(
            "{}/{}/{}",
            vh.vault_id().unwrap(),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4()
        );
        assert!(
            serve_record(&vh, &fill(&missing, "https://example.org", true))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn one_time_code_is_never_served_for_another_site() {
        let (vh, record_id) = vault_with_github();
        let action = VaultAction::GenerateTotp {
            page: LoginPage::parse("https://example.org", "https://example.org", None).unwrap(),
            record_id,
        };
        assert!(serve_record(&vh, &action).unwrap().is_none());
    }
}
