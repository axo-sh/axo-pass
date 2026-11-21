//! One-time upgrade of vault files that 0.2.0 wrote (format 1).
//!
//! A format 1 file is the bare vault object. It has no `format`, `signature`,
//! or `key` field, and it is not signed. The upgrade rewrites it as a signed
//! format 2 file, with the file stem as the vault key. The metadata blobs are
//! not rewritten here. They have no `created_at`, and the model reads that as
//! unset (`model/overview.rs`).
//!
//! A format 1 file is trusted once, without a signature. The original file is
//! kept next to the new one as `{file name}.v1`.
//!
//! A Mac that ran 0.2.0 has `vault-encryption-key` and no
//! `device-signing-key`. The upgrade creates the signing key if the vault
//! files are all format 1 and no retained version or sync state exists. In any
//! other state a missing signing key is `SigningKeyLost`, and the upgrade
//! changes nothing.
//!
//! MIGRATE_V1: delete this module with the other MIGRATE_V1 markers.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::{fs, io};

use serde::Deserialize;
use serde_json::value::RawValue;
use serde_with::serde_as;
use uuid::Uuid;

use super::VaultWriter;
use crate::core::files::write_atomic;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::encrypted_vault::EncryptedVault;
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::format::signing::VaultSigner;
use crate::secrets::vaults::storage::device_keys::{DeviceKeys, KeyProbe, VaultFiles};
use crate::secrets::vaults::storage::handle::{normalized_key, validate_key};

#[cfg(test)]
mod tests;

/// Fields a format 1 vault file always has.
const LEGACY_FIELDS: [&str; 3] = ["id", "file_key", "items"];

/// Whether `contents` is a format 1 vault file. The file has no `format`
/// field.
fn is_legacy(contents: &str) -> bool {
    let Ok(fields) = serde_json::from_str::<BTreeMap<String, &RawValue>>(contents) else {
        return false;
    };
    !fields.contains_key("format") && LEGACY_FIELDS.iter().all(|f| fields.contains_key(*f))
}

/// Vault key of the format 1 file at `path`. It is the file stem, normalized.
fn legacy_key(path: &Path) -> Result<String, Error> {
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    normalized_key(stem).ok_or_else(|| Error::InvalidVaultKey(stem.to_string()))
}

/// Path where the format 1 file at `path` is kept.
fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".v1");
    path.with_file_name(name)
}

/// Contents of the format 2 file for the format 1 file `contents`, with vault
/// key `key`, signed by `signer`.
fn convert(contents: &str, key: &str, signer: &dyn VaultSigner) -> Result<String, Error> {
    if !validate_key(key) {
        return Err(Error::InvalidVaultKey(key.to_string()));
    }
    let mut fields: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(contents).map_err(Error::VaultDeserializationError)?;
    fields.insert("key".to_string(), key.into());
    let vault: EncryptedVault =
        serde_json::from_str(&serde_json::Value::Object(fields).to_string())
            .map_err(Error::VaultDeserializationError)?;
    EncryptedVault::sign_vault_json(vault.to_vault_json()?, signer)
}

/// Vault id of a vault file.
#[serde_as]
#[derive(Deserialize)]
struct VaultId {
    #[serde_as(as = "ShortId")]
    id: Uuid,
}

impl VaultWriter {
    /// Upgrade the format 1 files among `paths`, the vault files of this Mac.
    /// If `device-signing-key` is missing and the upgrade may create it, it
    /// is created first. Failures are logged, and a file that fails stays as
    /// it was.
    pub(crate) fn upgrade_legacy_vaults(
        &self,
        keys: &dyn DeviceKeys,
        files: &VaultFiles,
        paths: &[PathBuf],
    ) {
        let mut legacy = Vec::new();
        let mut others = 0;
        for path in paths {
            match fs::read_to_string(path) {
                Ok(contents) if is_legacy(&contents) => legacy.push(path),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {},
                _ => others += 1,
            }
        }
        if legacy.is_empty() || !Self::signing_key_ready(keys, files, others) {
            return;
        }
        for path in legacy {
            match self.upgrade_legacy_file(path) {
                Ok(()) => log::info!("Upgraded vault file {}", path.display()),
                Err(e) => log::error!("Failed to upgrade vault file {}: {e:?}", path.display()),
            }
        }
    }

    /// Whether `device-signing-key` is present, after it is created if the
    /// upgrade may create it. `others` is the number of vault files that are
    /// not format 1. The key is created only if `vault-encryption-key` is
    /// present, every vault file is format 1, and nothing was saved or synced
    /// by a later build. Otherwise the missing key is the key loss that the
    /// confirmed re-sign handles, or new hardware.
    fn signing_key_ready(keys: &dyn DeviceKeys, files: &VaultFiles, others: usize) -> bool {
        match keys.probe_signing_key() {
            KeyProbe::Present => true,
            KeyProbe::Error(message) => {
                log::error!("Not upgrading vault files, the keychain failed: {message}");
                false
            },
            KeyProbe::Missing => {
                let creatable = others == 0
                    && keys.probe_encryption_key() == KeyProbe::Present
                    && !files.holds_saved_state();
                if !creatable {
                    log::warn!("Not upgrading vault files, device-signing-key is missing");
                    return false;
                }
                match keys.create_signing_key() {
                    Ok(()) => true,
                    Err(e) => {
                        log::error!("Failed to create device-signing-key: {e:?}");
                        false
                    },
                }
            },
        }
    }

    /// Upgrade the format 1 file at `path` under the vault locks. A file that
    /// is no longer format 1 under the locks, because another process upgraded
    /// it, is left as it is.
    fn upgrade_legacy_file(&self, path: &Path) -> Result<(), Error> {
        let contents = EncryptedVault::read_file(path)?;
        let VaultId { id } =
            serde_json::from_str(&contents).map_err(Error::VaultDeserializationError)?;
        let vault_lock = self.locks.entry(id, path);
        let _locked = self.lock_entry(&vault_lock, id)?;

        let contents = EncryptedVault::read_file(path)?;
        if !is_legacy(&contents) {
            return Ok(());
        }
        let upgraded = convert(&contents, &legacy_key(path)?, &*self.signer)?;
        write_atomic(&backup_path(path), contents.as_bytes()).map_err(Error::VaultWriteError)?;
        write_atomic(path, upgraded.as_bytes()).map_err(Error::VaultWriteError)
    }
}
