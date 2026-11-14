use std::sync::Arc;

use axo_pass_core::core::auth::AuthContext;
use axo_pass_core::secrets::vaults::bundle::{
    BundleVaultInfo as CoreBundleVaultInfo, ExportMode, ExportReport, ImportAction, ImportIdentity,
    ImportSelection, ImportableBundle, WorkFactor as CoreWorkFactor,
};
use axo_pass_core::secrets::vaults::{ExportProgress as CoreExportProgress, ShortId};

use crate::*;

#[derive(uniffi::Record)]
pub struct BundleVaultInfo {
    /// Vault id as a short id. Pass back verbatim in a
    /// `BundleImportSelection`.
    pub id: String,
    pub name: Option<String>,
    /// The key the vault was exported under, if any. A suggested import key.
    pub default_key: Option<String>,
    /// Whether a vault file on this Mac holds the vault id. Importing it
    /// under its id is refused, so the caller asks for a copy or leaves the
    /// vault out.
    pub id_exists: bool,
    /// Files in the vault, history included. A vault with files cannot be
    /// imported as a copy, since its blobs are bound to the vault id. If
    /// `id_exists` is set and this is above zero, the caller leaves the vault
    /// out.
    pub files: u32,
    /// Files whose blobs the bundle lacks. An import writes their records,
    /// and the files read as missing locally.
    pub missing_files: u32,
}

impl BundleVaultInfo {
    fn new(v: CoreBundleVaultInfo, id_exists: bool) -> Self {
        BundleVaultInfo {
            id: ShortId::encode_uuid(v.id),
            name: v.name,
            default_key: v.default_key,
            id_exists,
            files: v.files as u32,
            missing_files: v.missing_files as u32,
        }
    }
}

/// File blob that an export could not include.
#[derive(uniffi::Record)]
pub struct MissingFileBlob {
    /// Id of the vault that references the blob, as a short id.
    pub vault_id: String,
    /// Blob name, 64 lowercase hex characters.
    pub blob: String,
    /// Why the blob could not be read or fetched.
    pub reason: String,
}

/// Outcome of a bundle export.
#[derive(uniffi::Record)]
pub struct VaultExportReport {
    /// Blobs that exported records name and the bundle lacks. The export
    /// still wrote every other blob.
    pub missing_blobs: Vec<MissingFileBlob>,
}

impl From<ExportReport> for VaultExportReport {
    fn from(report: ExportReport) -> Self {
        VaultExportReport {
            missing_blobs: report
                .missing_blobs
                .into_iter()
                .map(|missing| MissingFileBlob {
                    vault_id: ShortId::encode_uuid(missing.vault_id),
                    blob: missing.blob.to_string(),
                    reason: missing.reason,
                })
                .collect(),
        }
    }
}

/// What an import does with one selected vault. Mirrors the core
/// `ImportAction`.
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum BundleImportAction {
    /// Import under the bundle vault id. Refused if the id exists on this
    /// Mac.
    Default,
    /// Import under a new vault id.
    Copy,
}

impl From<BundleImportAction> for ImportAction {
    fn from(action: BundleImportAction) -> Self {
        match action {
            BundleImportAction::Default => ImportAction::Default,
            BundleImportAction::Copy => ImportAction::Copy,
        }
    }
}

/// One vault the caller has chosen to import, the key to import it under, and
/// the action for it.
#[derive(uniffi::Record)]
pub struct BundleImportSelection {
    /// `id` from a `BundleVaultInfo`.
    pub id: String,
    pub target_key: String,
    pub action: BundleImportAction,
}

/// Passphrase key-derivation cost for a bundle export. Mirrors the core
/// `WorkFactor`. `Custom` is a scrypt `log_n`, clamped to the accepted range by
/// core.
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum ExportWorkFactor {
    /// About 512 MB of memory.
    Fast,
    /// About 1 GB of memory.
    Balanced,
    /// About 2 GB of memory.
    Secure,
    /// About 8 GB of memory.
    Paranoid,
    /// An explicit scrypt log_n.
    Custom { log_n: u8 },
}

impl From<ExportWorkFactor> for CoreWorkFactor {
    fn from(f: ExportWorkFactor) -> Self {
        match f {
            ExportWorkFactor::Fast => CoreWorkFactor::Fast,
            ExportWorkFactor::Balanced => CoreWorkFactor::Balanced,
            ExportWorkFactor::Secure => CoreWorkFactor::Secure,
            ExportWorkFactor::Paranoid => CoreWorkFactor::Paranoid,
            ExportWorkFactor::Custom { log_n } => CoreWorkFactor::Custom(log_n),
        }
    }
}

/// A short human note about the memory and time cost of a work factor, for the
/// export UI.
#[uniffi::export]
pub fn export_work_factor_cost_hint(factor: ExportWorkFactor) -> String {
    CoreWorkFactor::from(factor).cost_hint().to_string()
}

/// Which stage a bundle export has reached. `CollectingVault` carries a 1-based
/// `index` and `total`; the other stages report zero for both.
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum VaultExportStage {
    CollectingVault,
    DerivingKey,
    Writing,
}

/// Implemented by the app to receive bundle-export progress. Called on a
/// background thread.
#[uniffi::export(with_foreign)]
pub trait VaultExportProgressDelegate: Send + Sync {
    fn on_stage(&self, stage: VaultExportStage, index: u32, total: u32);
}

#[uniffi::export(async_runtime = "tokio")]
impl AxoPass {
    /// Export one or more vaults to a passphrase-encrypted bundle file at
    /// `dest_path`. Each vault is unlocked first, reusing the shared LAContext.
    ///
    /// `work_factor` sets the passphrase key-derivation cost. `progress`, when
    /// given, is called on a background thread as the export moves through its
    /// stages.
    ///
    /// The bundle holds the file blobs that exported records name. A blob that
    /// cannot be read or fetched is listed in the report, and the export still
    /// succeeds.
    pub async fn export_vault_bundle(
        &self,
        vault_keys: Vec<String>,
        dest_path: String,
        passphrase: String,
        work_factor: ExportWorkFactor,
        include_passkeys: bool,
        progress: Option<Arc<dyn VaultExportProgressDelegate>>,
    ) -> Result<VaultExportReport, FfiError> {
        let store = self
            .manager
            .lock()
            .map_err(|_| FfiError::Poisoned)?
            .store()
            .clone();
        tokio::task::spawn_blocking(move || {
            let export_mode = ExportMode::Passphrase {
                passphrase: passphrase.into(),
                work_factor: work_factor.into(),
            };
            store
                .export(
                    &vault_keys,
                    std::path::Path::new(&dest_path),
                    export_mode,
                    include_passkeys,
                    AuthContext::SharedThreadLocal,
                    |p| {
                        if let Some(delegate) = &progress {
                            let (stage, index, total) = match p {
                                CoreExportProgress::Vault { index, total } => (
                                    VaultExportStage::CollectingVault,
                                    index as u32,
                                    total as u32,
                                ),
                                CoreExportProgress::DerivingKey => {
                                    (VaultExportStage::DerivingKey, 0, 0)
                                },
                                CoreExportProgress::Writing => (VaultExportStage::Writing, 0, 0),
                            };
                            delegate.on_stage(stage, index, total);
                        }
                    },
                )
                .map(VaultExportReport::from)
                .map_err(FfiError::from)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Open a bundle file and list the vaults it contains, each with whether
    /// its id exists on this Mac. Reads only the headers of the vault files
    /// and makes no keychain call. Writes nothing.
    pub async fn inspect_vault_bundle(
        &self,
        src_path: String,
        passphrase: String,
    ) -> Result<Vec<BundleVaultInfo>, FfiError> {
        let store = self
            .manager
            .lock()
            .map_err(|_| FfiError::Poisoned)?
            .store()
            .clone();
        tokio::task::spawn_blocking(move || {
            let bundle = ImportableBundle::open(
                std::path::Path::new(&src_path),
                ImportIdentity::Passphrase(passphrase.into()),
            )
            .map_err(FfiError::from)?;
            let vaults = bundle.vaults();
            let existing = store.existing_ids(vaults.iter().map(|v| v.id));
            Ok(vaults
                .into_iter()
                .map(|v| {
                    let id_exists = existing.contains(&v.id);
                    BundleVaultInfo::new(v, id_exists)
                })
                .collect())
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Import the selected vaults from a bundle file. Returns the keys of the
    /// newly created vaults. A vault
    /// imported under an id that exists on this Mac fails the whole import
    /// before anything is written. So does a copy of a vault that holds
    /// files (`BundleVaultInfo::files`).
    pub async fn import_vault_bundle(
        &self,
        src_path: String,
        passphrase: String,
        selection: Vec<BundleImportSelection>,
    ) -> Result<Vec<String>, FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            let bundle = ImportableBundle::open(
                std::path::Path::new(&src_path),
                ImportIdentity::Passphrase(passphrase.into()),
            )
            .map_err(FfiError::from)?;

            let mut targets = std::collections::BTreeMap::new();
            for entry in selection {
                let id = ShortId::parse_uuid(&entry.id).map_err(|_| {
                    FfiError::InvalidInput(format!("Invalid vault id: {}", entry.id))
                })?;
                targets.insert(
                    id,
                    ImportSelection::new(entry.target_key, entry.action.into()),
                );
            }

            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            m.import_bundle(bundle, &targets).map_err(FfiError::from)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }
}

#[cfg(test)]
mod tests {
    use axo_pass_core::secrets::vaults::bundle::MissingBlob;
    use axo_pass_core::secrets::vaults::files::FileHash;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn export_report_lists_missing_blobs_by_short_vault_id() {
        let vault_id = Uuid::new_v4();
        let report = ExportReport {
            missing_blobs: vec![MissingBlob {
                vault_id,
                blob: FileHash([0xab; 32]),
                reason: "File blob is missing".to_string(),
            }],
        };

        let report = VaultExportReport::from(report);

        let [missing] = &report.missing_blobs[..] else {
            panic!("{} missing blobs", report.missing_blobs.len());
        };
        assert_eq!(missing.vault_id, ShortId::encode_uuid(vault_id));
        assert_eq!(missing.blob, "ab".repeat(32));
        assert_eq!(missing.reason, "File blob is missing");
    }
}
