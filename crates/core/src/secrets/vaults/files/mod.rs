//! Files attached to vault items.
//!
//! A file is a credential of kind [`FieldKind::File`] whose value is a JSON
//! [`FileRecord`]. The record names a blob in the local blob store of the
//! vault and holds the per-file key (`store.rs`, `stream.rs`). The file
//! bytes are never in the vault file.
//!
//! Adding or replacing a file encrypts the contents to a temp file in the
//! store before the vault locks are taken. Under the locks, in the
//! transaction, the temp file is renamed to its blob name and the record is
//! written, and then the vault saves. A record is therefore never saved
//! before its blob. A crash or failure after the rename leaves a blob that
//! no record references, and garbage collection deletes it (`gc.rs`).
//!
//! Replacing a file writes a new blob with a new key. The replaced record
//! goes to the credential history. Deleting a file moves the credential to
//! the trash, which keeps the blob. Purging it from the trash or purging its
//! history entry drops the record, and the next save deletes the blob.
//!
//! In a synced vault, a file record syncs as the value of its credential.
//! The publish uploads its blob to the synced folder before any state file
//! that references it, and a Mac that lacks the blob fetches it when the
//! file is read (`sync/blobs.rs`).

pub(crate) mod gc;
pub mod record;
pub(crate) mod store;
pub(crate) mod stream;

use std::io::{Read, Write};

pub use record::{FileHash, FileRecord};
use secrecy::ExposeSecret;
use store::{BlobStore, StagedBlob};
use uuid::Uuid;

use super::format::encrypted_vault::VaultHeader;
use super::model::VaultItemCredentialOverview;
use super::storage::txn::{Committed, Target, Unlock, VaultWriter};
use super::{Error, FieldKind, VaultHandle};
use crate::audit::SubjectIds;

/// File contents to store, with the file name and MIME type.
pub struct FileInput<R> {
    pub name: String,
    pub mime: Option<String>,
    pub contents: R,
}

/// File details to display. Excludes the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSummary {
    pub name: String,
    pub mime: Option<String>,
    /// Plaintext size in bytes.
    pub size: u64,
    /// SHA-256 of the plaintext.
    pub sha256: FileHash,
}

impl FileSummary {
    fn of(record: &FileRecord) -> Self {
        Self {
            name: record.name.clone(),
            mime: record.mime.clone(),
            size: record.size,
            sha256: record.sha256,
        }
    }
}

/// Displayable fields of a stored file record. `None` if the value is not a
/// file record.
pub fn summary(value: &str) -> Option<FileSummary> {
    FileRecord::decode(value).ok().map(|r| FileSummary::of(&r))
}

/// Add the file `input` to item `item_key` as a new credential `cred_key`
/// titled `title`, in a transaction on the vault `target`. Fails with
/// `DuplicateCredentialKey` if the item already has the key. Returns the
/// audit ids of the new credential.
pub fn add_file<R: Read>(
    writer: &VaultWriter,
    target: &Target,
    unlock: Unlock<'_>,
    item_key: &str,
    cred_key: &str,
    title: &str,
    input: FileInput<R>,
) -> Result<Committed<SubjectIds>, Error> {
    let (vault_id, staged) = stage(target, input.contents)?;
    let value = staged.record(input.name, input.mime).encode()?;
    writer.write(target, unlock, |vh| {
        commit_into(vh, vault_id, staged, |vh| {
            vh.add_new_secret(item_key, cred_key, title, FieldKind::File, value)?;
            vh.credential_ids(item_key, cred_key)
        })
    })
}

/// Replace the file of credential `cred_key` of item `item_key` with
/// `input`, in a transaction on the vault `target`. The new file has a new
/// blob and key. The replaced record goes to the credential history. Fails
/// with `InvalidCredentialKey` if the credential is not a file. Returns the
/// audit ids of the credential.
pub fn replace_file<R: Read>(
    writer: &VaultWriter,
    target: &Target,
    unlock: Unlock<'_>,
    item_key: &str,
    cred_key: &str,
    input: FileInput<R>,
) -> Result<Committed<SubjectIds>, Error> {
    let (vault_id, staged) = stage(target, input.contents)?;
    let value = staged.record(input.name, input.mime).encode()?;
    writer.write(target, unlock, |vh| {
        let title = file_credential(vh, item_key, cred_key)?.title.clone();
        commit_into(vh, vault_id, staged, |vh| {
            vh.add_secret(item_key, cred_key, &title, FieldKind::File, value)?;
            vh.credential_ids(item_key, cred_key)
        })
    })
}

/// Decrypt the file of credential `cred_key` of item `item_key` in the
/// unlocked vault `vh` to `output`. The blob is verified against the record
/// (`stream.rs`). `output` holds partial contents on any error, and the
/// caller discards it. Fails with `InvalidCredentialKey` if the credential
/// is not a file.
///
/// A blob that is not on this Mac is fetched from the synced folder of a
/// synced vault through `writer` first (`sync/blobs.rs`). A blob that the
/// folder holds but that is not local yet is requested for download, and
/// the call fails with `FilePending`, which the caller shows as pending. A
/// blob that neither holds fails with `FileMissing`.
pub fn read_file(
    writer: &VaultWriter,
    vh: &VaultHandle,
    item_key: &str,
    cred_key: &str,
    output: impl Write,
) -> Result<FileSummary, Error> {
    let record = read_record(vh, item_key, cred_key)?;
    let vault_id = vh.vault_id()?;
    let store = BlobStore::of(&vh.path, vault_id);
    let synced = vh.get_unlocked_vault()?.replica_id().is_some();
    if synced && !store.contains(&record.blob) {
        writer.fetch_blob(vault_id, &vh.path, record.blob)?;
    }
    store.read(&record, vault_id, output)?;
    Ok(FileSummary::of(&record))
}

/// Move the file credential `cred_key` of item `item_key` to the trash, in a
/// transaction on the vault `target`. The blob is kept until the credential
/// is purged. Fails with `InvalidCredentialKey` if the credential is not a
/// file.
pub fn delete_file(
    writer: &VaultWriter,
    target: &Target,
    unlock: Unlock<'_>,
    item_key: &str,
    cred_key: &str,
) -> Result<Committed<()>, Error> {
    writer.write(target, unlock, |vh| {
        file_credential(vh, item_key, cred_key)?;
        vh.delete_item_credential(item_key, cred_key)
    })
}

/// Record of the file credential `cred_key` of item `item_key`.
pub(crate) fn read_record(
    vh: &VaultHandle,
    item_key: &str,
    cred_key: &str,
) -> Result<FileRecord, Error> {
    file_credential(vh, item_key, cred_key)?;
    let value = vh
        .get_secret(item_key, cred_key)?
        .ok_or_else(|| Error::InvalidCredentialKey(format!("{item_key}/{cred_key}")))?;
    FileRecord::decode(value.expose_secret())
}

/// Overview of credential `cred_key` of item `item_key`. Fails with
/// `InvalidCredentialKey` if it is missing or not a file.
fn file_credential<'a>(
    vh: &'a VaultHandle,
    item_key: &str,
    cred_key: &str,
) -> Result<&'a VaultItemCredentialOverview, Error> {
    vh.get_secret_overview(item_key, cred_key)?
        .filter(|cred| matches!(cred.kind, FieldKind::File))
        .ok_or_else(|| Error::InvalidCredentialKey(format!("{item_key}/{cred_key}")))
}

/// Encrypt `contents` to a temp file in the store of the vault `target`.
/// Returns the vault id the blob is bound to. The id is read from the file
/// header without verifying it. The transaction checks it under the locks.
fn stage(target: &Target, contents: impl Read) -> Result<(Uuid, StagedBlob), Error> {
    let vault_id = VaultHeader::peek(&target.path)?.id;
    let staged = BlobStore::of(&target.path, vault_id).stage(vault_id, contents)?;
    Ok((vault_id, staged))
}

/// Rename `staged` to its blob name in the store of `vh`, then run `write`.
/// Runs in a transaction, under the vault locks. If `write` fails, the blob
/// is deleted, since no record references it. Fails with `VaultNotFound` if
/// the vault is not vault `vault_id`, which the blob is bound to.
fn commit_into<R>(
    vh: &mut VaultHandle,
    vault_id: Uuid,
    staged: StagedBlob,
    write: impl FnOnce(&mut VaultHandle) -> Result<R, Error>,
) -> Result<R, Error> {
    if vh.vault_id()? != vault_id {
        return Err(Error::VaultNotFound(vh.path.display().to_string()));
    }
    let store = BlobStore::of(&vh.path, vault_id);
    let blob = staged.commit(&store)?;
    write(vh).inspect_err(|_| {
        if let Err(e) = store.delete(&blob) {
            log::warn!("Failed to delete unreferenced file blob {blob}: {e}");
        }
    })
}

#[cfg(test)]
mod tests;
