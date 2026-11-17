//! File credentials for Swift.
//!
//! Contents cross the FFI as paths, never as bytes. Add and replace open the
//! source path in Rust and stream it through the blob encryptor in 64 KiB
//! chunks. Read decrypts to a temp file next to the destination path and
//! renames it over the destination after the blob verifies. No call holds
//! more than a few chunks in memory.
//!
//! A file credential's record holds the per-file key, so the generic secret
//! calls in `vault.rs` refuse file credentials. Only these calls read file
//! contents, and no call returns the key.
//!
//! `FilePending`, `FileMissing`, and `FileBlobMismatch` map to distinct
//! `FfiError` variants (`error.rs`), so the app can show a file that is
//! downloading, not on this Mac, or damaged.

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axo_pass_core::audit;
use axo_pass_core::secrets::vaults::files::{self as core_files, FileInput, FileSummary};
use axo_pass_core::secrets::vaults::storage::txn::VaultWriter;
use axo_pass_core::secrets::vaults::{FieldKind, VaultHandle, VaultsManager};
use secrecy::ExposeSecret;
use uuid::Uuid;

use crate::vault::{change_event, credential_subject, ensure_unlocked};
use crate::*;

/// Displayable details of a file credential. Carries no key.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct FileInfo {
    pub name: String,
    /// MIME type recorded when the file was added, if known.
    pub mime: Option<String>,
    /// Plaintext size in bytes.
    pub size: u64,
    /// SHA-256 of the plaintext, as 64 lowercase hex characters.
    pub sha256: String,
    /// Whether the encrypted contents are on this Mac. If not, a read fetches
    /// them from the synced folder, and can fail with `FilePending` or
    /// `FileMissing`.
    pub local: bool,
}

impl FileInfo {
    fn new(summary: FileSummary, local: bool) -> Self {
        Self {
            name: summary.name,
            mime: summary.mime,
            size: summary.size,
            sha256: summary.sha256.to_string(),
            local,
        }
    }

    /// Details of the file record `value` in the unlocked vault `vault`.
    /// `None` if `value` is not a file record.
    pub(crate) fn of_value(writer: &VaultWriter, vault: &VaultHandle, value: &str) -> Option<Self> {
        let summary = core_files::summary(value)?;
        Some(Self::new(
            summary,
            core_files::is_local(writer, vault, value),
        ))
    }
}

/// File on disk to add or to replace a file with.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FileSource {
    /// Path of a regular file. Rust reads it in chunks.
    pub path: String,
    /// File name to record.
    pub name: String,
    /// MIME type to record, if known.
    pub mime: Option<String>,
}

impl FileSource {
    /// Open the path for streaming. Fails with `InvalidInput` if it cannot
    /// be read or is not a regular file.
    fn open(self) -> Result<FileInput<File>, FfiError> {
        Ok(FileInput {
            contents: open_source(&self.path)?,
            name: self.name,
            mime: self.mime,
        })
    }
}

/// Fail with `InvalidInput` if credential `cred_key` of item `item_key` is
/// not a file credential.
fn refuse_unless_file(vault: &VaultHandle, item_key: &str, cred_key: &str) -> Result<(), FfiError> {
    match vault.get_secret_overview(item_key, cred_key)? {
        Some(cred) if matches!(cred.kind, FieldKind::File) => Ok(()),
        _ => Err(FfiError::InvalidInput(format!(
            "Invalid credential key: {item_key}/{cred_key} is not a file"
        ))),
    }
}

/// Fail with `InvalidInput` if credential `cred_key` of item `item_key` is a
/// file credential. Its value is a record with the file key, so generic
/// secret calls refuse it.
pub(crate) fn refuse_file(
    vault: &VaultHandle,
    item_key: &str,
    cred_key: &str,
) -> Result<(), FfiError> {
    match vault.get_secret_overview(item_key, cred_key)? {
        Some(cred) if matches!(cred.kind, FieldKind::File) => Err(FfiError::InvalidInput(
            "A file credential has no text value".to_string(),
        )),
        _ => Ok(()),
    }
}

/// Open the file at `path` for streaming. Fails with `InvalidInput` if it
/// cannot be read or is not a regular file.
fn open_source(path: &str) -> Result<File, FfiError> {
    let invalid = |e: std::io::Error| FfiError::InvalidInput(format!("Cannot read {path}: {e}"));
    let file = File::open(path).map_err(invalid)?;
    if !file.metadata().map_err(invalid)?.is_file() {
        return Err(FfiError::InvalidInput(format!("{path} is not a file")));
    }
    Ok(file)
}

/// Run `write` on a temp file next to `dest`, and rename the temp file to
/// `dest` if `write` succeeds. The temp file is private to the owner and is
/// removed on failure, so `dest` never holds partial contents.
pub(crate) fn write_atomically<T>(
    dest: &Path,
    write: impl FnOnce(&mut BufWriter<File>) -> Result<T, FfiError>,
) -> Result<T, FfiError> {
    let name = dest
        .file_name()
        .ok_or_else(|| FfiError::InvalidInput(format!("Invalid path: {}", dest.display())))?
        .to_string_lossy();
    let temp: PathBuf = dest.with_file_name(format!(".{name}.{}.partial", Uuid::new_v4()));
    let io =
        |e: std::io::Error| FfiError::Internal(format!("Cannot write {}: {e}", dest.display()));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(io)?;
    let finish = || -> Result<T, FfiError> {
        let mut writer = BufWriter::new(file);
        let value = write(&mut writer)?;
        writer.flush().map_err(io)?;
        let file = writer.into_inner().map_err(|e| io(e.into_error()))?;
        file.sync_all().map_err(io)?;
        fs::rename(&temp, dest).map_err(io)?;
        Ok(value)
    };
    finish().inspect_err(|_| {
        if let Err(e) = fs::remove_file(&temp) {
            log::warn!("Failed to remove partial file {}: {e}", temp.display());
        }
    })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn open_source_refuses_directory_and_missing_path() {
        let dir = tempfile::tempdir().unwrap();

        let directory = open_source(dir.path().to_str().unwrap());
        let missing = open_source(dir.path().join("none").to_str().unwrap());

        assert!(matches!(directory, Err(FfiError::InvalidInput(_))));
        assert!(matches!(missing, Err(FfiError::InvalidInput(_))));
    }

    #[test]
    fn write_atomically_replaces_with_private_file() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out.txt");
        fs::write(&dest, b"old").unwrap();

        write_atomically(&dest, |out| {
            out.write_all(b"new")
                .map_err(|e| FfiError::Internal(e.to_string()))
        })
        .unwrap();

        assert_eq!(fs::read(&dest).unwrap(), b"new");
        let mode = fs::metadata(&dest).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn write_atomically_failure_leaves_destination() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out.txt");
        fs::write(&dest, b"old").unwrap();

        let result = write_atomically(&dest, |out| {
            out.write_all(b"partial").unwrap();
            Err::<(), _>(FfiError::FileBlobMismatch("blob".to_string()))
        });

        assert!(matches!(result, Err(FfiError::FileBlobMismatch(_))));
        assert_eq!(fs::read(&dest).unwrap(), b"old");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn write_atomically_into_missing_directory_fails() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("none").join("out.txt");

        let result = write_atomically(&dest, |_| Ok(()));

        assert!(matches!(result, Err(FfiError::Internal(_))));
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl AxoPass {
    /// Add the file at `source` to item `item_key` as a new file credential
    /// `cred_key` titled `title`. Fails with `InvalidInput` if the item
    /// already has the key, or if the path is not a readable file.
    pub async fn add_file(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
        title: String,
        source: FileSource,
    ) -> Result<(), FfiError> {
        let subject = credential_subject(&vault_key, &item_key, &cred_key).label(title.clone());
        let manager = Arc::clone(&self.manager);
        let key = vault_key.clone();
        let ids = tokio::task::spawn_blocking(move || {
            VaultsManager::add_file(
                &manager,
                &vault_key,
                &item_key,
                &cred_key,
                &title,
                source.open()?,
            )
            .map_err(FfiError::from)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))??;
        change_event(audit::Action::CredentialCreated, &key, subject, ids)
            .detail("kind", "file")
            .record_async()
            .await;
        Ok(())
    }

    /// Replace the file of file credential `cred_key` with the file at
    /// `source`. The replaced record goes to the credential history. Fails
    /// with `InvalidInput` if the credential is not a file.
    pub async fn replace_file(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
        source: FileSource,
    ) -> Result<(), FfiError> {
        let subject = credential_subject(&vault_key, &item_key, &cred_key);
        let manager = Arc::clone(&self.manager);
        let key = vault_key.clone();
        let ids = tokio::task::spawn_blocking(move || {
            VaultsManager::replace_file(&manager, &vault_key, &item_key, &cred_key, source.open()?)
                .map_err(FfiError::from)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))??;
        change_event(audit::Action::CredentialUpdated, &key, subject, ids)
            .detail("changed", "value")
            .record_async()
            .await;
        Ok(())
    }

    /// Decrypt the file of file credential `cred_key` to `dest_path`, which
    /// is replaced if it exists. The contents are verified before they appear
    /// at the path. A failed read leaves `dest_path` as it was. Fails with
    /// `FilePending` if the contents are downloading, `FileMissing` if they
    /// are not on this Mac, and `FileBlobMismatch` if they are damaged.
    pub async fn read_file_to_path(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
        dest_path: String,
    ) -> Result<FileInfo, FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            ensure_unlocked(&manager, &vault_key)?;
            let summary = write_atomically(Path::new(&dest_path), |out| {
                VaultsManager::read_file(&manager, &vault_key, &item_key, &cred_key, out)
                    .map_err(FfiError::from)
            })?;
            Ok(FileInfo::new(summary, true))
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Details of file credential `cred_key`, including whether its contents
    /// are on this Mac.
    pub async fn file_info(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
    ) -> Result<FileInfo, FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            ensure_unlocked(&manager, &vault_key)?;
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let catalog = m.store().clone();
            let vault = m
                .get_or_create_vault_mut(&vault_key)
                .map_err(FfiError::from)?;
            refuse_unless_file(vault, &item_key, &cred_key)?;
            let value = vault
                .get_secret(&item_key, &cred_key)?
                .ok_or_else(|| FfiError::NotFound(format!("{vault_key}/{item_key}/{cred_key}")))?;
            FileInfo::of_value(catalog.files(), vault, value.expose_secret())
                .ok_or_else(|| FfiError::Internal("Unreadable file record".to_string()))
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Move file credential `cred_key` to the trash. Its contents stay on
    /// this Mac until the credential is purged. Fails with `InvalidInput` if
    /// the credential is not a file.
    pub async fn delete_file(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
    ) -> Result<(), FfiError> {
        let subject = credential_subject(&vault_key, &item_key, &cred_key);
        let manager = Arc::clone(&self.manager);
        let key = vault_key.clone();
        let ids = tokio::task::spawn_blocking(move || {
            ensure_unlocked(&manager, &vault_key)?;
            let ids = {
                let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
                m.get_or_create_vault_mut(&vault_key)
                    .map_err(FfiError::from)?
                    .credential_ids(&item_key, &cred_key)?
            };
            VaultsManager::delete_file(&manager, &vault_key, &item_key, &cred_key)?;
            Ok::<_, FfiError>(ids)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))??;
        change_event(audit::Action::CredentialDeleted, &key, subject, ids)
            .detail("kind", "file")
            .record_async()
            .await;
        Ok(())
    }
}
