use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use uuid::Uuid;

use super::super::wire::{
    WireDropped, WireFileFailure, WireImportSummary, WireImportTarget, WireResponse,
};
use super::VaultPayload;
use super::serve::{AccessIds, Served, open_vault};
use crate::audit::SubjectIds;
use crate::core::auth::{AuthContext, ForeignContext};
use crate::core::config::APP_CONFIG;
use crate::secrets::vaults::bundle::{ImportIdentity, ImportSelection, ImportableBundle};
use crate::secrets::vaults::files::write_with_files;
use crate::secrets::vaults::storage::txn::{Target, Unlock};
use crate::secrets::vaults::vault_import::{
    FileFailure, ImportPlan, ImportSummary, MapOptions, StagedFiles, dropped_data,
    existing_item_ids, map_items, parse_1pif, stage_plan_files, write_plan,
};
use crate::secrets::vaults::{Error, ShortId, VaultCatalog, VaultHandle};

/// Unlock every named vault on the app's context and write the export bundle.
pub(super) fn export_vaults(
    vaults: &VaultCatalog,
    vault_keys: &[String],
    payload: Option<VaultPayload>,
    context: ForeignContext,
) -> Result<Served, String> {
    let Some(VaultPayload::Export(export)) = payload else {
        return Err("Missing export payload".to_string());
    };
    let report = vaults
        .export(
            vault_keys,
            &export.dest_path,
            export.mode,
            export.include_passkeys,
            AuthContext::Foreign(context),
            |_| {},
        )
        .map_err(|e| format!("Failed to export vaults: {e}"))?;
    // A vault whose id cannot be read after the export is left out.
    let ids = vault_keys
        .iter()
        .filter_map(|key| vaults.load(key).and_then(|vh| vh.peek_vault_id()).ok())
        .map(SubjectIds::vault)
        .collect();
    Ok(Served::new(
        WireResponse::VaultsExported {
            count: vault_keys.len() as u32,
            missing_blobs: report.missing_blobs.len() as u32,
        },
        AccessIds::Many(ids),
    ))
}

/// Re-open the bundle and import the selected vaults, re-wrapping each file key
/// with the local encryption key on the app's context. Ids are read in every
/// form [`ShortId::parse_uuid`] accepts. A vault imported under its bundle id
/// whose id exists on this Mac fails the whole import.
pub(super) fn import_vaults(
    vaults: &VaultCatalog,
    payload: Option<VaultPayload>,
    context: ForeignContext,
) -> Result<Served, String> {
    let Some(VaultPayload::Import(import)) = payload else {
        return Err("Missing import payload".to_string());
    };
    let identity =
        ImportIdentity::try_from(import.identity).map_err(|e| format!("Invalid identity: {e}"))?;

    let mut selection: BTreeMap<Uuid, ImportSelection> = BTreeMap::new();
    for selected in import.selection {
        let id = ShortId::parse_uuid(&selected.id)
            .map_err(|e| format!("Invalid vault id {}: {e}", selected.id))?;
        selection.insert(id, ImportSelection::new(selected.key, selected.action));
    }

    let bundle = ImportableBundle::open(&import.import_path, identity)
        .map_err(|e| format!("Failed to open bundle: {e}"))?;
    let imported = vaults
        .import(bundle, &selection, AuthContext::Foreign(context))
        .map_err(|e| format!("Failed to import bundle: {e}"))?;
    let ids = imported
        .iter()
        .filter_map(|vh| vh.peek_vault_id().ok())
        .map(SubjectIds::vault)
        .collect();
    let keys = imported.into_iter().map(|vh| vh.key).collect();
    Ok(Served::new(
        WireResponse::VaultsImported { keys },
        AccessIds::Many(ids),
    ))
}

/// Read a `.1pif` export and add its items to a vault, in one transaction. An
/// existing vault is written as it is. A new vault is created first, and
/// removed if the import fails, so a failed import leaves no vault behind.
/// Item secrets are read and written here and never cross the socket. A file
/// that cannot be read is reported in the summary and the import continues.
pub(super) fn import_items(
    vaults: &VaultCatalog,
    payload: Option<VaultPayload>,
    context: ForeignContext,
) -> Result<Served, String> {
    let Some(VaultPayload::ImportItems(import)) = payload else {
        return Err("Missing import payload".to_string());
    };
    let parsed =
        parse_1pif(&import.import_path).map_err(|e| format!("Failed to read the export: {e}"))?;
    let options = MapOptions {
        include_trashed: import.include_trashed,
    };
    let plan = map_items(&parsed, options);
    let imported = import_plan(vaults, &import.target, &plan, context)?;

    let dropped = parsed
        .iter()
        .filter(|item| import.include_trashed || !item.trashed)
        .flat_map(|item| {
            dropped_data(item).into_iter().map(|d| WireDropped {
                item: item.title.clone(),
                kind: d.kind.to_string(),
                detail: d.detail,
            })
        })
        .collect();
    let summary = WireImportSummary {
        added: imported.summary.added as u32,
        files_added: imported.summary.files_added as u32,
        files_skipped: imported.summary.files_skipped as u32,
        skipped_existing: imported.summary.skipped_existing as u32,
        trashed: imported.summary.trashed as u32,
        folders_created: imported.summary.folders_created as u32,
        skipped_trashed: plan.skipped_trashed as u32,
        repeated_uuids: plan.repeated_uuids,
        file_failures: imported
            .failures
            .into_iter()
            .map(|f| WireFileFailure {
                item: f.item,
                path: f.path.to_string_lossy().into_owned(),
                reason: f.reason,
            })
            .collect(),
        dropped,
    };
    Ok(Served::new(
        WireResponse::ItemsImported {
            vault_key: imported.vault_key,
            summary,
        },
        AccessIds::One(SubjectIds::vault(imported.vault_id)),
    ))
}

/// What [`run_import`] wrote.
pub(super) struct Imported {
    pub(super) summary: ImportSummary,
    pub(super) failures: Vec<FileFailure>,
    /// Key of the vault as saved.
    pub(super) vault_key: String,
    pub(super) vault_id: Uuid,
}

/// Write `plan` to `target`. A new vault is created first, and removed if the
/// write fails.
pub(super) fn import_plan(
    vaults: &VaultCatalog,
    target: &WireImportTarget,
    plan: &ImportPlan,
    context: ForeignContext,
) -> Result<Imported, String> {
    let (vh, created) = match target {
        WireImportTarget::Existing { vault_key } => {
            (open_vault(vaults, vault_key, context)?, false)
        },
        WireImportTarget::New { name } => {
            let key = free_vault_key(vaults, name)?;
            let vh = vaults
                .create_on(Some(name.clone()), &key, AuthContext::Foreign(context))
                .map_err(|e| format!("Failed to create vault {key}: {e}"))?;
            (vh, true)
        },
    };
    match run_import(vaults, &vh, plan) {
        Err(message) if created => Err(match remove_new_vault(vaults, &vh) {
            Ok(()) => message,
            Err(e) => format!("{message}. The new vault {} was not removed: {e}", vh.key),
        }),
        result => result,
    }
}

/// Stage the files of `plan` that are not in `vh` yet, then write the plan and
/// commit the files in one transaction on `vh`. An error saves nothing.
fn run_import(
    vaults: &VaultCatalog,
    vh: &VaultHandle,
    plan: &ImportPlan,
) -> Result<Imported, String> {
    let writer = vaults.files();
    let target = Target::of(vh);
    let skip = existing_item_ids(vh).map_err(|e| format!("Failed to read vault items: {e}"))?;
    let StagedFiles {
        files,
        values,
        failures,
    } = stage_plan_files(writer, &target, plan, &skip);
    let committed = write_with_files(writer, &target, Unlock::Unlocked(vh), files, |fresh| {
        write_plan(fresh, plan, &values)
    })
    .map_err(|e| format!("Failed to import items: {e}"))?;
    Ok(Imported {
        summary: committed.value,
        failures,
        vault_key: committed.vault.key.clone(),
        vault_id: committed.vault_id,
    })
}

/// Key for a new vault named `name`. A key that another vault holds gets a
/// numeric suffix.
fn free_vault_key(vaults: &VaultCatalog, name: &str) -> Result<String, String> {
    let base = vault_key_for(name);
    (1..100)
        .map(|n| match n {
            1 => base.clone(),
            n => format!("{base}-{n}"),
        })
        .find(|key| vaults.unclaimed_key(key, None).is_ok())
        .ok_or_else(|| format!("No free vault key for the name {name}"))
}

/// Vault key made from a name. Lower-case ASCII letters and digits are kept,
/// and each run of other characters becomes `-`. The result is a valid key.
fn vault_key_for(name: &str) -> String {
    let mut key = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            key.push(c.to_ascii_lowercase());
        } else if !key.is_empty() && !key.ends_with('-') {
            key.push('-');
        }
    }
    let mut key = key.trim_end_matches('-').to_string();
    if !key.starts_with(|c: char| c.is_ascii_lowercase()) {
        key = format!("vault-{key}").trim_end_matches('-').to_string();
    }
    if key.len() < 3 {
        key.push_str("-vault");
    }
    key
}

/// Delete the vault file of a vault that this import created. The file is
/// removed outright, since the vault never held other data.
fn remove_new_vault(vaults: &VaultCatalog, vh: &VaultHandle) -> Result<(), String> {
    vaults
        .delete_with(&vh.key, Unlock::App, |path| {
            fs::remove_file(path).map_err(Error::VaultDeleteError)
        })
        .map_err(|e| e.to_string())
}

/// Unlock the vault at `path` to validate it, then register it as an external
/// vault in the app config. The vault key is read from the file. A key that
/// another vault file claims is refused.
pub(super) fn add_external_vault(
    vaults: &VaultCatalog,
    path: &str,
    context: ForeignContext,
) -> Result<Served, String> {
    let path = Path::new(path)
        .canonicalize()
        .map_err(|e| format!("Could not resolve path {path}: {e}"))?;

    let mut vh = VaultHandle::load_from_path(&path, vaults.files().locks())
        .map_err(|e| format!("Not a valid vault file: {e}"))?;
    vaults
        .unclaimed_key(&vh.key, Some(&path))
        .map_err(|e| format!("Failed to add vault: {e}"))?;
    vaults
        .unlock(&mut vh, AuthContext::Foreign(context))
        .map_err(|e| format!("Failed to unlock vault: {e}"))?;

    let name = vh.vault_name().map(str::to_string);
    let ids = SubjectIds::vault(vh.vault_id()?);
    APP_CONFIG
        .lock()
        .map_err(|e| format!("Failed to lock config: {e}"))?
        .add_external_vault(path)
        .map_err(|e| format!("Failed to add vault: {e}"))?;

    Ok(Served::new(
        WireResponse::VaultLinked {
            vault_key: vh.key.clone(),
            name,
        },
        AccessIds::One(ids),
    ))
}
