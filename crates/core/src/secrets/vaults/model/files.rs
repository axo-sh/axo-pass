//! File credentials in the vault model.
//!
//! A credential of kind [`FieldKind::File`] holds a `FileRecord` that names a
//! blob outside the vault file (`files/mod.rs`). A credential never changes
//! to or from the file kind, so every value and history value of a file
//! credential is a file record, and no other credential holds one.
//!
//! [`Vault::file_blobs`] lists the blobs of a decrypted vault, and
//! [`bundled_file_blobs`] lists those of the encrypted items of an opened
//! export bundle (`bundle/mod.rs`).

use std::collections::{BTreeMap, BTreeSet};

use secrecy::ExposeSecret;
use uuid::Uuid;

use super::{CredentialId, ItemId, Vault};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::files::record::{BlobRef, FileHash};
use crate::secrets::vaults::format::encrypted_blob::EncryptedBlob;
use crate::secrets::vaults::format::encrypted_vault::{EncryptedVaultItem, HistoryEntry};
use crate::secrets::vaults::format::vault_cipher::VaultCipher;
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

impl Vault {
    /// Blobs named by the values and history values of every credential,
    /// live, deleted, and in deleted items, whatever its kind. A credential
    /// whose `kind` register a concurrent purge emptied shows as the default
    /// kind, so no kind decides the scan. A value that is not a file record
    /// names no blob. A value that fails to decrypt fails the call.
    pub(crate) fn file_blobs(&self) -> Result<BTreeSet<FileHash>, Error> {
        let mut blobs = BTreeSet::new();
        for item in self.items.values() {
            for cred in item.credentials.values() {
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
        cipher_credential_blobs(&self.cipher, item_id, cred_id, value, history, blobs)
    }
}

/// Blobs named by the values and history values of every credential of
/// `items`, live and deleted, as an opened bundle holds them. Scans like
/// [`Vault::file_blobs`], without decrypting the vault. A value that fails to
/// decrypt fails the call.
pub(crate) fn bundled_file_blobs(
    cipher: &VaultCipher,
    items: &BTreeMap<Uuid, EncryptedVaultItem>,
) -> Result<BTreeSet<FileHash>, Error> {
    let mut blobs = BTreeSet::new();
    for (item_id, item) in items {
        for (cred_id, cred) in &item.credentials {
            cipher_credential_blobs(
                cipher,
                *item_id,
                *cred_id,
                Some(&cred.value),
                &cred.history,
                &mut blobs,
            )?;
        }
        for (cred_id, deleted) in &item.deleted {
            let cred = &deleted.credential;
            cipher_credential_blobs(
                cipher,
                *item_id,
                *cred_id,
                Some(&cred.value),
                &cred.history,
                &mut blobs,
            )?;
        }
    }
    Ok(blobs)
}

/// Add the blobs named by `value` and `history` of credential `cred_id` of
/// item `item_id`, decrypted with `cipher`, to `blobs`.
fn cipher_credential_blobs(
    cipher: &VaultCipher,
    item_id: ItemId,
    cred_id: CredentialId,
    value: Option<&EncryptedBlob<String>>,
    history: &[HistoryEntry],
    blobs: &mut BTreeSet<FileHash>,
) -> Result<(), Error> {
    if let Some(value) = value {
        let value = cipher.decrypt_cred_value(item_id, cred_id, value)?;
        blobs.extend(BlobRef::of(value.expose_secret()));
    }
    for entry in history {
        if let Some(value) = &entry.value {
            let value = cipher.decrypt_history_value(item_id, cred_id, entry.id, value)?;
            blobs.extend(BlobRef::of(value.expose_secret()));
        }
    }
    Ok(())
}
