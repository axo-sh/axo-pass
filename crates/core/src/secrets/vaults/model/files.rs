//! File credentials in the vault model.
//!
//! A credential of kind [`FieldKind::File`] holds a `FileRecord` that names a
//! blob outside the vault file (`files/mod.rs`). A credential never changes
//! to or from the file kind, so every value and history value of a file
//! credential is a file record, and no other credential holds one.

use std::collections::BTreeSet;

use secrecy::ExposeSecret;

use super::{CredentialId, ItemId, Vault};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::files::record::{BlobRef, FileHash};
use crate::secrets::vaults::format::encrypted_blob::EncryptedBlob;
use crate::secrets::vaults::format::encrypted_vault::HistoryEntry;
use crate::secrets::vaults::model::fields::FieldKind;

/// Fail with `FileKindChange` if a credential `cred_key` of kind `from`
/// would change to kind `to` and exactly one of them is the file kind.
pub(super) fn check_kind_change(
    cred_key: &str,
    from: &FieldKind,
    to: &FieldKind,
) -> Result<(), Error> {
    if matches!(from, FieldKind::File) != matches!(to, FieldKind::File) {
        return Err(Error::FileKindChange(cred_key.to_string()));
    }
    Ok(())
}

/// Whether credentials of `kind` are scanned for blob references. An unknown
/// kind is scanned too, since a newer build may store a file under it.
fn may_reference_blobs(kind: &FieldKind) -> bool {
    matches!(kind, FieldKind::File | FieldKind::Unknown(_))
}

impl Vault {
    /// Whether any live, deleted, or deleted item credential is a file.
    pub(crate) fn holds_files(&self) -> bool {
        let is_file = |kind: &FieldKind| matches!(kind, FieldKind::File);
        let live = self
            .items
            .values()
            .flat_map(|item| item.credentials.values());
        let deleted = self
            .deleted
            .values()
            .map(|entry| &entry.overview.credential);
        let deleted_items = self.deleted_items.values().flat_map(|entry| {
            let item = &entry.item;
            item.overview
                .credentials
                .values()
                .chain(item.deleted.values().map(|e| &e.overview.credential))
        });
        live.chain(deleted)
            .chain(deleted_items)
            .any(|cred| is_file(&cred.kind))
    }

    /// Blobs named by the values and history values of file credentials,
    /// live, deleted, and in deleted items, and of credentials of unknown
    /// kinds. A value that is not a file record names no blob. A value that
    /// fails to decrypt fails the call.
    pub(crate) fn file_blobs(&self) -> Result<BTreeSet<FileHash>, Error> {
        let mut blobs = BTreeSet::new();
        for item in self.items.values() {
            for cred in item.credentials.values() {
                if !may_reference_blobs(&cred.kind) {
                    continue;
                }
                let history = self.history.get(&cred.id).map(Vec::as_slice);
                self.credential_blobs(
                    item.id,
                    cred.id,
                    self.secrets.get(&cred.id),
                    history.unwrap_or_default(),
                    &mut blobs,
                )?;
            }
        }
        let deleted_items = self
            .deleted_items
            .values()
            .flat_map(|entry| entry.item.deleted.values());
        for entry in self.deleted.values().chain(deleted_items) {
            let cred = &entry.overview.credential;
            if !may_reference_blobs(&cred.kind) {
                continue;
            }
            let blobs_of = &entry.blobs.credential;
            self.credential_blobs(
                entry.overview.item_id,
                cred.id,
                Some(&blobs_of.value),
                &blobs_of.history,
                &mut blobs,
            )?;
        }
        for entry in self.deleted_items.values() {
            let item = &entry.item;
            for (cred_id, cred) in &item.credentials {
                let kind = item.overview.credentials.get(cred_id).map(|c| &c.kind);
                if !kind.is_some_and(may_reference_blobs) {
                    continue;
                }
                self.credential_blobs(
                    item.overview.id,
                    *cred_id,
                    Some(&cred.value),
                    &cred.history,
                    &mut blobs,
                )?;
            }
        }
        Ok(blobs)
    }

    /// Add the blobs named by `value` and the history values of credential
    /// `cred_id` of item `item_id` to `blobs`.
    fn credential_blobs(
        &self,
        item_id: ItemId,
        cred_id: CredentialId,
        value: Option<&EncryptedBlob<String>>,
        history: &[HistoryEntry],
        blobs: &mut BTreeSet<FileHash>,
    ) -> Result<(), Error> {
        if let Some(value) = value {
            let value = self.cipher.decrypt_cred_value(item_id, cred_id, value)?;
            blobs.extend(BlobRef::of(value.expose_secret()));
        }
        for entry in history {
            if let Some(value) = &entry.value {
                let value = self
                    .cipher
                    .decrypt_history_value(item_id, cred_id, entry.id, value)?;
                blobs.extend(BlobRef::of(value.expose_secret()));
            }
        }
        Ok(())
    }
}
