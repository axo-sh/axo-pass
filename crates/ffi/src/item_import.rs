//! Import of items from a password manager export, for Swift.
//!
//! A preview parses and maps the export and writes nothing. An import creates
//! a new vault and writes the items and attachments in one transaction. Item
//! secrets are read and written in Rust and never cross the FFI. A failed
//! import moves the new vault to the Trash.

use std::path::Path;
use std::sync::Arc;

use axo_pass_core::audit;
use axo_pass_core::secrets::vaults::VaultsManager;
use axo_pass_core::secrets::vaults::vault_import::naming::free_vault_key;
use axo_pass_core::secrets::vaults::vault_import::{
    ImportPlan, MapOptions, ParsedItem, dropped_data, is_apple_csv, map_items, parse_export,
};

use crate::vault::change_event;
use crate::*;

/// Data of an exported record that the import does not keep.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct ItemImportDropped {
    /// Title of the record.
    pub item: String,
    /// Short name of the kind of data, such as `tags`.
    pub kind: String,
    pub detail: String,
}

/// Attachment that could not be read. The import continues without it.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct ItemImportFileFailure {
    pub item: String,
    pub path: String,
    pub reason: String,
}

/// What an import would add. Holds no secret values.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct ItemImportPreview {
    /// Items that would be added, including trashed items.
    pub items: u32,
    /// Items of `items` that would be deleted after they are added.
    pub trashed: u32,
    pub folders: u32,
    pub files: u32,
    /// Trashed records left out because trashed items were not requested.
    pub skipped_trashed: u32,
    /// Record uuids that repeat an earlier record.
    pub repeated_uuids: Vec<String>,
    pub dropped: Vec<ItemImportDropped>,
}

/// What an import added.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct ItemImportResult {
    /// Key of the new vault.
    pub vault_key: String,
    pub added: u32,
    pub files_added: u32,
    pub trashed: u32,
    pub folders_created: u32,
    pub file_failures: Vec<ItemImportFileFailure>,
}

/// Whether `path` is an Apple Passwords CSV export. Other paths are read as a
/// 1Password export.
#[uniffi::export]
pub fn is_apple_passwords_export(path: String) -> bool {
    is_apple_csv(Path::new(&path))
}

/// Parse the export at `path`. Fails with `InvalidInput` if it cannot be read.
fn parse(path: &str) -> Result<Vec<ParsedItem>, FfiError> {
    parse_export(path).map_err(|e| FfiError::InvalidInput(format!("Cannot read the export: {e}")))
}

fn options(include_trashed: bool) -> MapOptions {
    MapOptions { include_trashed }
}

fn preview_of(
    parsed: &[ParsedItem],
    plan: &ImportPlan,
    include_trashed: bool,
) -> ItemImportPreview {
    let dropped = parsed
        .iter()
        .filter(|item| include_trashed || !item.trashed)
        .flat_map(|item| {
            dropped_data(item).into_iter().map(|d| ItemImportDropped {
                item: item.title.clone(),
                kind: d.kind.to_string(),
                detail: d.detail,
            })
        })
        .collect();
    ItemImportPreview {
        items: plan.items.len() as u32,
        trashed: plan.items.iter().filter(|i| i.trashed).count() as u32,
        folders: plan.folders.len() as u32,
        files: plan.items.iter().map(|i| i.files.len()).sum::<usize>() as u32,
        skipped_trashed: plan.skipped_trashed as u32,
        repeated_uuids: plan.repeated_uuids.clone(),
        dropped,
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl AxoPass {
    /// Read the export at `path` and report what an import would add and what
    /// it would leave out. Writes nothing and needs no authentication.
    pub async fn preview_item_import(
        &self,
        path: String,
        include_trashed: bool,
    ) -> Result<ItemImportPreview, FfiError> {
        tokio::task::spawn_blocking(move || {
            let parsed = parse(&path)?;
            let plan = map_items(&parsed, options(include_trashed));
            Ok(preview_of(&parsed, &plan, include_trashed))
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Create a vault named `name` and import the export at `path` into it.
    /// The key is derived from the name, with a numeric suffix if it is taken.
    /// An error leaves no usable vault.
    pub async fn import_items_into_new_vault(
        &self,
        path: String,
        name: String,
        include_trashed: bool,
    ) -> Result<ItemImportResult, FfiError> {
        let name = name.trim().to_string();
        if name.is_empty() {
            return Err(FfiError::InvalidInput(
                "The vault name is empty".to_string(),
            ));
        }
        let manager = Arc::clone(&self.manager);
        let (vault_name, result, ids) = tokio::task::spawn_blocking(move || {
            let parsed = parse(&path)?;
            let plan = map_items(&parsed, options(include_trashed));
            let key = {
                let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
                let store = m.store().clone();
                let key = free_vault_key(&store, &name).map_err(FfiError::Internal)?;
                m.add_vault(Some(name.clone()), &key)
                    .map_err(FfiError::from)?
                    .key
                    .clone()
            };
            match VaultsManager::import_plan(&manager, &key, &plan) {
                Ok((summary, failures, vault_id)) => {
                    let result = ItemImportResult {
                        vault_key: key,
                        added: summary.added as u32,
                        files_added: summary.files_added as u32,
                        trashed: summary.trashed as u32,
                        folders_created: summary.folders_created as u32,
                        file_failures: failures
                            .into_iter()
                            .map(|f| ItemImportFileFailure {
                                item: f.item,
                                path: f.path.to_string_lossy().into_owned(),
                                reason: f.reason,
                            })
                            .collect(),
                    };
                    Ok((name, result, audit::SubjectIds::vault(vault_id)))
                },
                Err(e) => Err(match VaultsManager::delete_vault(&manager, &key) {
                    Ok(()) => FfiError::from(e),
                    Err(cleanup) => FfiError::Internal(format!(
                        "{e}. The new vault {key} was not removed: {cleanup}"
                    )),
                }),
            }
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))??;
        let subject = audit::Subject::new(audit::SubjectKind::Vault, result.vault_key.clone())
            .label(vault_name);
        change_event(
            audit::Action::VaultItemsImported,
            &result.vault_key,
            subject,
            ids,
        )
        .detail("imported_vault", result.vault_key.clone())
        .detail("item_count", result.added.to_string())
        .detail("skipped_existing", "0")
        .record_async()
        .await;
        Ok(result)
    }
}
