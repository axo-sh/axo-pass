use std::collections::BTreeMap;
use std::path::Path;

use super::super::wire::WireResponse;
use super::VaultPayload;
use super::serve::{AccessIds, Served};
use crate::audit::SubjectIds;
use crate::core::auth::{AuthContext, ForeignContext};
use crate::core::config::APP_CONFIG;
use crate::secrets::vaults::bundle::{ImportIdentity, ImportableBundle};
use crate::secrets::vaults::{VaultCatalog, VaultHandle};

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
    vaults
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
        },
        AccessIds::Many(ids),
    ))
}

/// Re-open the bundle and import the selected vaults, re-wrapping each file key
/// with the local encryption key on the app's context.
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

    let mut selection: BTreeMap<uuid::Uuid, String> = BTreeMap::new();
    for (id, key) in import.selection {
        let id = uuid::Uuid::parse_str(&id).map_err(|e| format!("Invalid vault id {id}: {e}"))?;
        selection.insert(id, key);
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

/// Unlock the vault at `path` to validate it, then register it as an external
/// vault in the app config.
pub(super) fn add_external_vault(
    vaults: &VaultCatalog,
    path: &str,
    context: ForeignContext,
) -> Result<Served, String> {
    let path = Path::new(path)
        .canonicalize()
        .map_err(|e| format!("Could not resolve path {path}: {e}"))?;

    let mut vh = VaultHandle::load_from_path(None, &path, vaults.files().locks())
        .map_err(|e| format!("Not a valid vault file: {e}"))?;
    vaults
        .unlock(&mut vh, AuthContext::Foreign(context))
        .map_err(|e| format!("Failed to unlock vault: {e}"))?;

    let name = vh.vault_name().map(str::to_string);
    let ids = SubjectIds::vault(vh.vault_id()?);
    APP_CONFIG
        .lock()
        .map_err(|e| format!("Failed to lock config: {e}"))?
        .add_external_vault(&vh.key, path)
        .map_err(|e| format!("Failed to add vault: {e}"))?;

    Ok(Served::new(
        WireResponse::VaultLinked {
            vault_key: vh.key.clone(),
            name,
        },
        AccessIds::One(ids),
    ))
}
