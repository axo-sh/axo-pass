use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use secrecy::ExposeSecret;

use super::super::wire::WireResponse;
use super::serve::{AccessIds, Served, open_vault};
use super::{BrokerCredential, BrokerVaultItem, VaultPayload, VaultRef, WriteSecretPayload};
use crate::audit::SubjectIds;
use crate::core::auth::ForeignContext;
use crate::secrets::vaults::{FieldKind, MatchKind, VaultCatalog, VaultHandle, autofill, files};

/// Whether credential `credential_key` of item `item_key` is a file. Its
/// value is a record with the file key, so the broker neither reads nor
/// overwrites it as text. It decrypts the contents only to a destination file
/// (`read_vault_file`).
fn is_file(vh: &VaultHandle, item_key: &str, credential_key: &str) -> bool {
    matches!(
        vh.get_secret_overview(item_key, credential_key),
        Ok(Some(cred)) if matches!(cred.kind, FieldKind::File)
    )
}

/// Write payload of an item request, if it carries one. Any other payload is
/// refused.
fn write_payload(payload: Option<VaultPayload>) -> Result<Option<WriteSecretPayload>, String> {
    match payload {
        Some(VaultPayload::Write(write)) => Ok(Some(write)),
        None => Ok(None),
        Some(_) => Err("Wrong payload for this vault action".to_string()),
    }
}

/// Serve a [`VaultAction::ListItems`]: the item overview of `vault_key`, never
/// a secret.
pub(super) fn list_items(
    vaults: &VaultCatalog,
    vault_key: &str,
    payload: Option<VaultPayload>,
    context: ForeignContext,
) -> Result<Served, String> {
    write_payload(payload)?;
    let vh = open_vault(vaults, vault_key, context)?;
    Ok(Served::new(
        WireResponse::VaultItems {
            items: collect_items(&vh)?,
        },
        AccessIds::One(SubjectIds::vault(vh.vault_id()?)),
    ))
}

/// Serve a [`VaultAction::ReadSecret`]: one credential's secret value.
pub(super) fn read_secret(
    vaults: &VaultCatalog,
    vault_key: &str,
    item_key: &str,
    credential_key: &str,
    payload: Option<VaultPayload>,
    context: ForeignContext,
) -> Result<Served, String> {
    write_payload(payload)?;
    let vh = open_vault(vaults, vault_key, context)?;
    if is_file(&vh, item_key, credential_key) {
        return Err("A file credential cannot be read as text".to_string());
    }
    let value = vh
        .get_secret(item_key, credential_key)
        .map_err(|e| format!("Failed to get secret: {e}"))?
        .map(|secret| secret.expose_secret().to_string());
    Ok(Served::new(
        WireResponse::VaultSecret { value },
        AccessIds::One(vh.credential_ids(item_key, credential_key)?),
    ))
}

/// Serve a [`VaultAction::ReadFile`]: decrypt one file credential to
/// `dest_path`. The destination must be absolute and must not exist. The file
/// is created with mode 0600 and removed again if the read fails.
pub(super) fn read_vault_file(
    vaults: &VaultCatalog,
    vault_key: &str,
    item_key: &str,
    credential_key: &str,
    dest_path: &str,
    payload: Option<VaultPayload>,
    context: ForeignContext,
) -> Result<Served, String> {
    write_payload(payload)?;
    let dest = Path::new(dest_path);
    if !dest.is_absolute() {
        return Err(format!("Destination path must be absolute: {dest_path}"));
    }
    let vh = open_vault(vaults, vault_key, context)?;
    if !is_file(&vh, item_key, credential_key) {
        return Err(format!("{item_key}/{credential_key} is not a file"));
    }
    let ids = vh.credential_ids(item_key, credential_key)?;

    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dest)
        .map_err(|e| format!("Failed to create {dest_path}: {e}"))?;
    let mut out = BufWriter::new(file);
    let read = files::read_file(vaults.files(), &vh, item_key, credential_key, &mut out)
        .map_err(|e| format!("Failed to read file: {e}"));
    let flushed = read.and_then(|summary| {
        out.flush()
            .and_then(|()| out.get_ref().sync_all())
            .map(|()| summary)
            .map_err(|e| format!("Failed to write {dest_path}: {e}"))
    });
    match flushed {
        Ok(summary) => Ok(Served::new(
            WireResponse::VaultFileRead {
                name: summary.name,
                mime: summary.mime,
                size: summary.size,
            },
            AccessIds::One(ids),
        )),
        Err(message) => {
            drop(out);
            if let Err(e) = fs::remove_file(dest) {
                log::error!("Failed to remove partial file {dest_path}: {e}");
            }
            Err(message)
        },
    }
}

/// Serve a [`VaultAction::WriteSecret`]: write one credential's secret value in
/// a transaction that reloads the vault under the vault locks.
pub(super) fn write_vault_secret(
    vaults: &VaultCatalog,
    vault_key: &str,
    item_key: &str,
    credential_key: &str,
    payload: Option<VaultPayload>,
    context: ForeignContext,
) -> Result<Served, String> {
    let write = write_payload(payload)?;
    let vh = open_vault(vaults, vault_key, context)?;
    let payload = write.ok_or("Missing write payload")?;
    let (created, ids) = vaults
        .files()
        .write_unlocked(&vh, |fresh| {
            let created = write_secret(fresh, item_key, credential_key, payload)?;
            Ok::<_, String>((created, fresh.credential_ids(item_key, credential_key)?))
        })?
        .value;
    Ok(Served::new(
        WireResponse::VaultWritten { created },
        AccessIds::One(ids),
    ))
}

/// Write the secret of a [`VaultAction::WriteSecret`] into a vault handle.
/// Returns whether the item was created.
fn write_secret(
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
    if is_file(vh, item_key, credential_key) {
        return Err("A file credential cannot be overwritten with text".to_string());
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
            Some(vh) if is_file(vh, &r.item_key, &r.credential_key) => {
                log::error!(
                    "Refusing to resolve file credential {}/{}/{} as text",
                    r.vault_key,
                    r.item_key,
                    r.credential_key
                );
                None
            },
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
