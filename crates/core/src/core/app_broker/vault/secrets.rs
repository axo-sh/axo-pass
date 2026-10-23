use secrecy::ExposeSecret;

use super::super::wire::WireResponse;
use super::serve::{AccessIds, Served, open_vault};
use super::{BrokerCredential, BrokerVaultItem, VaultRef, WriteSecretPayload};
use crate::core::auth::ForeignContext;
use crate::secrets::vaults::{MatchKind, VaultCatalog, VaultHandle, autofill};

/// Write the secret of a [`VaultAction::WriteSecret`] into a vault handle.
/// Returns whether the item was created.
pub(super) fn write_secret(
    vh: &mut VaultHandle,
    item_key: &str,
    credential_key: &str,
    payload: WriteSecretPayload,
) -> Result<bool, String> {
    if let Some(login) = payload.login {
        let created = vh.get_item_overview(item_key).ok().flatten().is_none();
        autofill::write_login(
            vh,
            autofill::LoginWrite {
                item_key,
                title: &payload.title,
                password_key: credential_key,
                password: payload.value,
                username: login.username.as_deref(),
                websites: &login.websites,
                match_kind: MatchKind::Domain,
            },
        )
        .map_err(|e| format!("Failed to write login: {e}"))?;
        return Ok(created);
    }
    // Keep an existing credential's kind so a value-only update does
    // not reset it; a new credential falls back to the default.
    let existing = vh
        .get_secret_overview(item_key, credential_key)
        .ok()
        .flatten();
    let created = existing.is_none() && vh.get_item_overview(item_key).ok().flatten().is_none();
    let kind = existing.map(|o| o.kind.clone()).unwrap_or_default();
    // Create a missing item titled by its key.
    if created {
        vh.add_item(item_key, item_key)
            .map_err(|e| format!("Failed to add item: {e}"))?;
    }
    vh.add_secret(
        item_key,
        credential_key,
        &payload.title,
        kind,
        payload.value,
    )
    .map_err(|e| format!("Failed to add secret: {e}"))?;
    Ok(created)
}

/// Resolve every reference, unlocking each distinct vault once on the app's
/// context. The result is positionally matched to `refs`. A reference whose
/// vault fails to load or unlock resolves to `None` rather than failing the
/// whole batch. The audit ids are those of the credentials that resolved.
pub(super) fn resolve_secrets(
    vaults: &VaultCatalog,
    refs: &[VaultRef],
    context: ForeignContext,
) -> Result<Served, String> {
    use std::collections::HashMap;

    let mut opened: HashMap<String, Option<VaultHandle>> = HashMap::new();
    let mut values = Vec::with_capacity(refs.len());
    let mut ids = Vec::new();

    for r in refs {
        let vh = opened.entry(r.vault_key.clone()).or_insert_with(|| {
            open_vault(vaults, &r.vault_key, context.clone())
                .inspect_err(|e| log::error!("{e}"))
                .ok()
        });

        let value = match vh {
            Some(vh) => match vh.get_secret(&r.item_key, &r.credential_key) {
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
        if value.is_some()
            && let Some(vh) = vh
        {
            match vh.credential_ids(&r.item_key, &r.credential_key) {
                Ok(found) => ids.push(found),
                Err(e) => log::error!("Failed to read the audit ids of a resolved secret: {e}"),
            }
        }
        values.push(value);
    }

    Ok(Served::new(
        WireResponse::ResolvedSecrets { values },
        AccessIds::Many(ids),
    ))
}

pub(super) fn collect_items(vh: &VaultHandle) -> Result<Vec<BrokerVaultItem>, String> {
    let mut items: Vec<BrokerVaultItem> = vh
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
