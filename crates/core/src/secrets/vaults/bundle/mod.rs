//! Export bundles of vaults.
//!
//! A bundle is one JSON file that holds each vault encrypted under a new file
//! key (`exported_bundle.rs`). The bundle key is protected once with the
//! export mode (`export_mode.rs`).
//!
//! The file blobs of a vault are inside its bundle entry, as stored. Export
//! copies the blobs that exported records name (`export_blobs.rs`). Open
//! checks every blob against its name before any import writes. An import
//! writes the blobs of a vault to its local blob store before the vault file.
//!
//! Blobs are bound to the vault id, so a vault that holds files imports under
//! its bundle id only. A copy of such a vault is refused. A vault whose
//! bundle lacks a blob imports its records, and the file reads as missing
//! locally.

pub(crate) mod export_blobs;
mod export_mode;
pub mod exported_bundle;
mod import_identity;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::io::{self};
use std::path::{Path, PathBuf};

use aes_gcm::{Aes256Gcm, KeyInit};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::audit::{self, Action, AuditEvent, Outcome, Subject, SubjectIds, SubjectKind};
pub use crate::secrets::vaults::bundle::export_blobs::{ExportReport, MissingBlob};
pub use crate::secrets::vaults::bundle::export_mode::{
    ExportMode, MAX_WORK_FACTOR, MIN_WORK_FACTOR, WorkFactor,
};
pub use crate::secrets::vaults::bundle::exported_bundle::{
    BUNDLE_VERSION, BundledVault, ExportedBundle, RawFileKey,
};
pub use crate::secrets::vaults::bundle::import_identity::ImportIdentity;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::files::FileHash;
use crate::secrets::vaults::files::store::BlobStore;
use crate::secrets::vaults::format::encrypted_blob::EncryptedBlob;
use crate::secrets::vaults::format::encrypted_vault::{EncryptedVaultItem, VaultFileKey};
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::format::vault_cipher::VaultCipher;
use crate::secrets::vaults::model::{Vault, VaultMetadata, bundled_file_blobs};
use crate::secrets::vaults::storage::handle::{VaultHandle, normalized_key};
use crate::secrets::vaults::storage::txn::VaultWriter;

const FILE_KEY_LEN: usize = 32;

/// Audit detail key of the bundle vault id that an import copy was made from.
pub const SOURCE_VAULT_ID: &str = "source_vault_id";

/// Wraps a raw vault file key into the form the vault file stores.
pub type FileKeyWrapper = Box<dyn Fn(&[u8]) -> Result<VaultFileKey, Error>>;

/// What an import does with one selected vault.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportAction {
    /// Import under the bundle vault id. Refused if a vault file on this Mac
    /// holds the id.
    #[default]
    Default,
    /// Import under a new vault id.
    Copy,
}

/// Target key and action of one selected vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportSelection {
    /// Key the vault is imported as.
    pub key: String,
    pub action: ImportAction,
}

impl ImportSelection {
    pub fn new(key: impl Into<String>, action: ImportAction) -> Self {
        Self {
            key: key.into(),
            action,
        }
    }
}

/// Metadata about one vault inside an opened bundle, for the caller to build an
/// import selection.
pub struct BundleVaultInfo {
    pub id: Uuid,
    pub name: Option<String>,
    pub default_key: Option<String>,
    /// Files in the vault: the blobs that its records name, history included.
    pub files: usize,
    /// Files whose blobs the bundle lacks. An import writes their records,
    /// and the files read as missing locally.
    pub missing_files: usize,
}

/// Blobs of `blobs` that `referenced` names. Fails with `FileBlobMismatch` if
/// any blob of `blobs`, named or not, does not hash to its name.
fn verified_blobs(
    blobs: BTreeMap<FileHash, Vec<u8>>,
    referenced: &BTreeSet<FileHash>,
) -> Result<BTreeMap<FileHash, Vec<u8>>, Error> {
    if let Some(name) = blobs
        .iter()
        .find_map(|(name, bytes)| (FileHash::of(bytes) != *name).then(|| name.to_string()))
    {
        return Err(Error::FileBlobMismatch(name));
    }
    Ok(blobs
        .into_iter()
        .filter(|(name, _)| referenced.contains(name))
        .collect())
}

/// Vault written by an import, for its audit event.
struct ImportedRow {
    /// Files whose blobs the bundle lacks.
    missing_files: usize,
    /// Vault id of the written vault.
    id: Uuid,
    /// Bundle vault id, if the vault is a copy.
    source_id: Option<Uuid>,
    key: String,
    name: Option<String>,
}

struct PreparedVault {
    id: Uuid,
    name: Option<String>,
    default_key: Option<String>,
    raw_file_key: SecretBox<Vec<u8>>,
    metadata: Option<EncryptedBlob<VaultMetadata>>,
    items: BTreeMap<Uuid, EncryptedVaultItem>,
    /// Blobs that the records of `items` name.
    referenced: BTreeSet<FileHash>,
    /// Blobs of `referenced` that the bundle holds, each checked against its
    /// name. Bundle blobs that no record names are dropped.
    blobs: BTreeMap<FileHash, Vec<u8>>,
}

impl PreparedVault {
    /// Blobs that the records name and the bundle lacks.
    fn missing_blobs(&self) -> usize {
        self.referenced.len() - self.blobs.len()
    }

    /// Decrypt the vault with its raw file key and encrypt it again under a
    /// new file key, so the vault shares no key with the bundle. `key` is the
    /// vault key the vault is imported as, already validated. `wrap` receives
    /// the raw new file key and returns the form the vault file stores. The
    /// vault takes `new_id` if set, and keeps the bundle vault id otherwise.
    /// It keeps the bundle vault name and every passkey, and is not synced.
    fn into_vault(
        self,
        key: String,
        new_id: Option<Uuid>,
        wrap: impl FnOnce(&[u8]) -> Result<VaultFileKey, Error>,
    ) -> Result<Vault, Error> {
        let cipher = VaultCipher::new_with_bytes(self.raw_file_key.expose_secret(), self.id);
        // The decrypted vault has no wrapped file key. It is dropped at
        // return and is never saved.
        let decrypted = Vault::from_bundled(cipher, key, self.name, self.metadata, self.items)?;
        decrypted.rekeyed(new_id, wrap)
    }
}

/// A decrypted bundle ready to import. The bundle key has been unwrapped and
/// every vault's file key decrypted. Nothing is written until [`import`] runs.
///
/// [`import`]: ImportableBundle::import
pub struct ImportableBundle {
    vaults: Vec<PreparedVault>,
}

impl ImportableBundle {
    /// Read a bundle file and decrypt every file key with `identity`. Scans
    /// the records of each vault for the blobs they name, and checks every
    /// blob of the bundle against its name. A blob that does not match fails
    /// with `FileBlobMismatch`, and nothing is imported from the bundle.
    pub fn open(import_path: &Path, identity: ImportIdentity) -> Result<Self, Error> {
        let data = fs::read_to_string(import_path).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                Error::VaultNotFound(import_path.display().to_string())
            } else {
                Error::VaultReadError(e)
            }
        })?;

        let bundle: ExportedBundle =
            serde_json::from_str(&data).map_err(Error::VaultDeserializationError)?;

        if bundle.version == 0 {
            return Err(Error::VaultImportError(
                "Bundle format version 0 is not valid".to_string(),
            ));
        }
        if bundle.version > BUNDLE_VERSION {
            let version = bundle.version;
            return Err(Error::VaultImportError(format!(
                "Bundle format version {version} is newer than the supported version \
                 {BUNDLE_VERSION}"
            )));
        }

        let bundle_key = identity.decrypt(&bundle.age_bundle_key)?;
        if bundle_key.len() != FILE_KEY_LEN {
            return Err(Error::VaultImportError(format!(
                "Invalid bundle key length: expected {FILE_KEY_LEN} bytes, got {}",
                bundle_key.len()
            )));
        }
        let bundle_cipher = Aes256Gcm::new_from_slice(&bundle_key)
            .map_err(|_| Error::VaultImportError("Invalid bundle key".to_string()))?;

        // vault ids key the import selection, so a bundle that repeats one is
        // malformed and would silently lose vaults
        let mut seen_ids = HashSet::with_capacity(bundle.vaults.len());
        let mut vaults = Vec::with_capacity(bundle.vaults.len());
        for v in bundle.vaults {
            if !seen_ids.insert(v.id) {
                let id = v.id;
                return Err(Error::VaultImportError(format!(
                    "Bundle contains more than one vault with id {id}"
                )));
            }
            let raw = v.wrapped_file_key.decrypt(
                &bundle_cipher,
                ExportedBundle::file_key_aad(bundle.id, v.id),
            )?;
            let raw_bytes = raw.expose_secret().0.clone();
            if raw_bytes.len() != FILE_KEY_LEN {
                return Err(Error::VaultImportError(format!(
                    "Invalid file key length for vault {}: expected {FILE_KEY_LEN} bytes, got {}",
                    v.id,
                    raw_bytes.len()
                )));
            }
            // every blob is checked, so a bundle with one damaged blob is
            // refused before anything is written
            let cipher = VaultCipher::new_with_bytes(&raw_bytes, v.id);
            let referenced = bundled_file_blobs(&cipher, &v.items)?;
            let blobs = verified_blobs(v.blobs, &referenced)?;
            vaults.push(PreparedVault {
                id: v.id,
                name: v.name,
                default_key: v.default_key,
                raw_file_key: SecretBox::new(Box::new(raw_bytes)),
                metadata: v.metadata,
                items: v.items,
                referenced,
                blobs,
            });
        }

        Ok(Self { vaults })
    }

    /// Bundle of empty vaults with ids `ids` and fixed file keys, for tests.
    #[cfg(test)]
    pub(crate) fn for_test(ids: &[Uuid]) -> Self {
        let vaults = ids
            .iter()
            .map(|id| PreparedVault {
                id: *id,
                name: None,
                default_key: None,
                raw_file_key: SecretBox::new(Box::new(vec![7u8; FILE_KEY_LEN])),
                metadata: None,
                items: BTreeMap::new(),
                referenced: BTreeSet::new(),
                blobs: BTreeMap::new(),
            })
            .collect();
        Self { vaults }
    }

    /// Metadata for every vault in the bundle, in file order.
    pub fn vaults(&self) -> Vec<BundleVaultInfo> {
        self.vaults
            .iter()
            .map(|v| BundleVaultInfo {
                id: v.id,
                name: v.name.clone(),
                default_key: v.default_key.clone(),
                files: v.referenced.len(),
                missing_files: v.missing_blobs(),
            })
            .collect()
    }

    /// Import the selected vaults. `selection` maps a bundle vault id to its
    /// target key and action. A vault imported as a copy takes a new vault
    /// id. Every target key must be valid and unique among the selection. The
    /// caller checks that no vault file on this Mac claims a key or holds an
    /// imported id. Each vault is encrypted again under a new file key before
    /// anything is written. Each vault holds its key and is written to
    /// `{id}.json` in `vault_dir`, in its own transaction, which never leaves
    /// a partial file. A vault id that another tracked vault file already
    /// holds is refused. If a write fails, the vaults this import already
    /// wrote are removed on a best-effort basis.
    ///
    /// The blobs of a vault go to its local blob store before its file is
    /// written. A vault that holds files is refused as a copy, since its blobs
    /// are bound to the bundle vault id. A blob that the bundle lacks is not
    /// written, and its file reads as missing. A failed import removes the
    /// blobs it wrote.
    ///
    /// `wrapper` returns the file key wrapper and runs once, after every
    /// target key is checked.
    pub(crate) fn import_with(
        self,
        selection: &BTreeMap<Uuid, ImportSelection>,
        vault_dir: &Path,
        files: &VaultWriter,
        wrapper: impl FnOnce() -> Result<FileKeyWrapper, Error>,
    ) -> Result<Vec<VaultHandle>, Error> {
        if selection.is_empty() {
            return Err(Error::VaultImportError(
                "No vaults selected for import".to_string(),
            ));
        }

        let mut by_id: BTreeMap<Uuid, PreparedVault> =
            self.vaults.into_iter().map(|v| (v.id, v)).collect();

        // resolve and validate every target key and path up front
        struct Planned {
            prepared: PreparedVault,
            key: String,
            new_id: Option<Uuid>,
            path: PathBuf,
        }
        let mut planned: Vec<Planned> = Vec::with_capacity(selection.len());
        let mut seen_keys: BTreeMap<String, Uuid> = BTreeMap::new();
        for (id, selected) in selection {
            let prepared = by_id
                .remove(id)
                .ok_or_else(|| Error::VaultImportError(format!("Bundle has no vault {id}")))?;

            let new_id = match selected.action {
                ImportAction::Default => None,
                ImportAction::Copy => Some(Uuid::new_v4()),
            };

            let requested_key = &selected.key;
            let key = normalized_key(requested_key)
                .ok_or_else(|| Error::InvalidVaultKey(requested_key.clone()))?;

            if let Some(other) = seen_keys.insert(key.clone(), *id) {
                return Err(Error::InvalidVaultKey(format!(
                    "Key '{key}' requested for two vaults ({other} and {id})"
                )));
            }

            // blobs are sealed under the bundle vault id, so a copy cannot
            // read them
            if new_id.is_some() && !prepared.referenced.is_empty() {
                return Err(Error::VaultImportError(format!(
                    "Vault {} holds {} files, whose blobs are bound to the vault id. \
                     Import it under its bundle id, not as a copy.",
                    ShortId::encode_uuid(*id),
                    prepared.referenced.len()
                )));
            }

            let path = VaultHandle::file_path(vault_dir, new_id.unwrap_or(*id));
            if path.exists() {
                return Err(Error::DuplicateVaultId(format!(
                    "A vault file already exists at {}",
                    path.display()
                )));
            }
            planned.push(Planned {
                prepared,
                key,
                new_id,
                path,
            });
        }

        // encrypt each vault again under a new file key wrapped with the local
        // Secure Enclave key, so a damaged vault is refused before anything is
        // written
        let wrap = wrapper()?;
        let mut staged: Vec<VaultHandle> = Vec::with_capacity(planned.len());
        let mut staged_blobs: Vec<BTreeMap<FileHash, Vec<u8>>> = Vec::with_capacity(planned.len());
        let mut audit_rows: Vec<ImportedRow> = Vec::with_capacity(planned.len());
        for mut p in planned {
            audit_rows.push(ImportedRow {
                id: p.new_id.unwrap_or(p.prepared.id),
                source_id: p.new_id.map(|_| p.prepared.id),
                key: p.key.clone(),
                name: p.prepared.name.clone(),
                missing_files: p.prepared.missing_blobs(),
            });
            staged_blobs.push(std::mem::take(&mut p.prepared.blobs));
            let vault = p.prepared.into_vault(p.key, p.new_id, |raw| wrap(raw))?;
            staged.push(VaultHandle::unlocked(p.path, vault));
        }

        // A vault file is written after its blobs, so no record is saved
        // before its blob. A blob that the store already holds is kept if the
        // import fails.
        let mut written: Vec<&Path> = Vec::with_capacity(staged.len());
        let mut new_blobs: Vec<(BlobStore, FileHash)> = Vec::new();
        let mut write = || -> Result<(), Error> {
            for (vw, blobs) in staged.iter().zip(&staged_blobs) {
                let store = files.blob_store(vw.vault_id()?);
                for (name, bytes) in blobs {
                    let is_new = !store.contains(name);
                    store.put(name, bytes)?;
                    if is_new {
                        new_blobs.push((store.clone(), *name));
                    }
                }
                files.create(vw)?;
                written.push(&vw.path);
            }
            Ok(())
        };
        if let Err(e) = write() {
            for path in &written {
                let removed = files.delete(path, |path| {
                    fs::remove_file(path).map_err(Error::VaultDeleteError)
                });
                if let Err(e) = removed {
                    log::error!(
                        "Failed to remove {} after a failed import: {e}",
                        path.display()
                    );
                }
            }
            for (store, name) in &new_blobs {
                if let Err(e) = store.delete(name) {
                    log::error!("Failed to remove file blob {name} after a failed import: {e}");
                }
            }
            return Err(e);
        }

        let count = audit_rows.len();
        for row in audit_rows {
            let mut event = AuditEvent::new(
                audit::process_source(),
                Action::VaultImported,
                Outcome::Succeeded,
            )
            .subject(Subject::new(SubjectKind::Vault, row.key).maybe_label(row.name))
            .subject_ids(SubjectIds::vault(row.id))
            .detail("vault_count", count.to_string());
            if row.missing_files > 0 {
                log::warn!(
                    "Imported vault {} without {} file blobs",
                    ShortId::encode_uuid(row.id),
                    row.missing_files
                );
                event = event.detail("missing_files", row.missing_files.to_string());
            }
            if let Some(source_id) = row.source_id {
                event = event.detail(SOURCE_VAULT_ID, ShortId::encode_uuid(source_id));
            }
            audit::record(event);
        }

        Ok(staged
            .into_iter()
            .map(|mut vw| {
                vw.lock();
                vw
            })
            .collect())
    }
}
