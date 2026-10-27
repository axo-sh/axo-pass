mod export_mode;
pub mod exported_bundle;
mod import_identity;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::{self};
use std::path::{Path, PathBuf};

use aes_gcm::{Aes256Gcm, KeyInit};
use secrecy::{ExposeSecret, SecretBox};
use uuid::Uuid;

use crate::audit::{self, Action, AuditEvent, Outcome, Subject, SubjectIds, SubjectKind};
use crate::core::auth::AuthContext;
pub use crate::secrets::vaults::bundle::export_mode::{
    ExportMode, MAX_WORK_FACTOR, MIN_WORK_FACTOR, WorkFactor,
};
pub use crate::secrets::vaults::bundle::exported_bundle::{
    BUNDLE_VERSION, BundledVault, ExportedBundle, RawFileKey,
};
pub use crate::secrets::vaults::bundle::import_identity::ImportIdentity;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::encrypted_blob::EncryptedBlob;
use crate::secrets::vaults::format::encrypted_vault::{
    EncryptedVault, EncryptedVaultItem, VaultFileKey,
};
use crate::secrets::vaults::format::vault_cipher::VaultCipher;
use crate::secrets::vaults::model::{Vault, VaultMetadata};
use crate::secrets::vaults::storage::handle::{
    VaultHandle, get_vault_encryption_key_on, normalized_key,
};
use crate::secrets::vaults::storage::txn::VaultWriter;

const FILE_KEY_LEN: usize = 32;

/// Wraps a raw vault file key into the form the vault file stores.
type FileKeyWrapper = Box<dyn Fn(&[u8]) -> Result<VaultFileKey, Error>>;

/// Metadata about one vault inside an opened bundle, for the caller to build an
/// import selection.
pub struct BundleVaultInfo {
    pub id: Uuid,
    pub name: Option<String>,
    pub default_key: Option<String>,
}

struct PreparedVault {
    id: Uuid,
    name: Option<String>,
    default_key: Option<String>,
    raw_file_key: SecretBox<Vec<u8>>,
    metadata: Option<EncryptedBlob<VaultMetadata>>,
    items: BTreeMap<Uuid, EncryptedVaultItem>,
}

impl PreparedVault {
    /// Decrypt the vault with its raw file key. `key` is the vault key the
    /// vault is imported as, already validated. `file_key` is the wrapped form
    /// the vault file stores. The vault is not synced.
    fn into_vault(self, key: String, file_key: VaultFileKey) -> Result<Vault, Error> {
        let cipher = VaultCipher::new_with_bytes(self.raw_file_key.expose_secret(), self.id);
        let encrypted_vault = EncryptedVault {
            id: self.id,
            key,
            name: self.name,
            generation: 0,
            replica_id: None,
            file_key,
            metadata: self.metadata,
            items: self.items,
            deleted: BTreeMap::new(),
        };
        Vault::from_encrypted_with_cipher(cipher, encrypted_vault)
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
    /// Read a bundle file and decrypt every file key with `identity`.
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
            vaults.push(PreparedVault {
                id: v.id,
                name: v.name,
                default_key: v.default_key,
                raw_file_key: SecretBox::new(Box::new(raw_bytes)),
                metadata: v.metadata,
                items: v.items,
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
            })
            .collect()
    }

    /// Import the selected vaults. `selection` maps a bundle vault id to the
    /// key it should be imported as. Every target key must be valid and
    /// unique among the selection. The caller checks that no vault file on
    /// this Mac claims it. Each vault holds its key and is written to
    /// `{id}.json` in `vault_dir`, in its own transaction, which never leaves
    /// a partial file. A vault id that another vault file on this Mac already
    /// holds is refused. If a write fails, the vaults this import already
    /// wrote are removed on a best-effort basis.
    pub fn import(
        self,
        selection: &BTreeMap<Uuid, String>,
        vault_dir: &Path,
        files: &VaultWriter,
        auth_context: AuthContext,
    ) -> Result<Vec<VaultHandle>, Error> {
        self.import_with(selection, vault_dir, files, || {
            let managed_key = get_vault_encryption_key_on(auth_context)?;
            Ok(Box::new(move |raw: &[u8]| {
                Ok(VaultFileKey::new(
                    managed_key
                        .encrypt(raw)
                        .ok_or(Error::VaultFileKeyEncryptionError)?
                        .into_bytes(),
                ))
            }))
        })
    }

    /// [`Self::import`] with the file key wrapper from `wrapper`. `wrapper`
    /// runs once, after every target key is checked.
    fn import_with(
        self,
        selection: &BTreeMap<Uuid, String>,
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
            path: PathBuf,
        }
        let mut planned: Vec<Planned> = Vec::with_capacity(selection.len());
        let mut seen_keys: BTreeMap<String, Uuid> = BTreeMap::new();
        for (id, requested_key) in selection {
            let prepared = by_id
                .remove(id)
                .ok_or_else(|| Error::VaultImportError(format!("Bundle has no vault {id}")))?;

            let key = normalized_key(requested_key)
                .ok_or_else(|| Error::InvalidVaultKey(requested_key.clone()))?;

            if let Some(other) = seen_keys.insert(key.clone(), *id) {
                return Err(Error::InvalidVaultKey(format!(
                    "Key '{key}' requested for two vaults ({other} and {id})"
                )));
            }

            let path = VaultHandle::file_path(vault_dir, *id);
            if path.exists() {
                return Err(Error::DuplicateVaultId(format!(
                    "A vault file already exists at {}",
                    path.display()
                )));
            }
            planned.push(Planned {
                prepared,
                key,
                path,
            });
        }

        // re-wrap each file key with the local Secure Enclave key, and decrypt
        // each vault so a damaged one is refused before anything is written
        let wrap = wrapper()?;
        let mut staged: Vec<VaultHandle> = Vec::with_capacity(planned.len());
        let mut audit_rows: Vec<(Uuid, String, Option<String>)> = Vec::with_capacity(planned.len());
        for p in planned {
            audit_rows.push((p.prepared.id, p.key.clone(), p.prepared.name.clone()));
            let enc_file_key = wrap(p.prepared.raw_file_key.expose_secret())?;
            let vault = p.prepared.into_vault(p.key, enc_file_key)?;
            staged.push(VaultHandle::unlocked(p.path, vault));
        }

        let mut written: Vec<&Path> = Vec::with_capacity(staged.len());
        for vw in &staged {
            if let Err(e) = files.create(vw) {
                for path in written {
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
                return Err(e);
            }
            written.push(&vw.path);
        }

        let count = audit_rows.len();
        for (id, key, name) in audit_rows {
            audit::record(
                AuditEvent::new(
                    audit::process_source(),
                    Action::VaultImported,
                    Outcome::Succeeded,
                )
                .subject(Subject::new(SubjectKind::Vault, key).maybe_label(name))
                .subject_ids(SubjectIds::vault(id))
                .detail("vault_count", count.to_string()),
            );
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
