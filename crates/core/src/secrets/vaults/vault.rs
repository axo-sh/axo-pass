pub mod encrypted_blob;
pub mod encrypted_vault;
pub mod vault_cipher;

use std::collections::{BTreeMap, BTreeSet};

use aes_gcm::aead::OsRng;
use aes_gcm::{Aes256Gcm, KeyInit};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::fields::FieldKind;
use crate::secrets::vaults::vault::encrypted_blob::EncryptedBlob;
use crate::secrets::vaults::vault::encrypted_vault::{
    DeletedCredential, DeletedItem, EncryptedVault, EncryptedVaultItem,
    EncryptedVaultItemCredential, HistoryEntry, VaultFileKey,
};
use crate::secrets::vaults::vault::vault_cipher::VaultCipher;
use crate::secrets::vaults::vault_export::exported_bundle::{BundledVault, ExportedBundle};
use crate::secrets::vaults::vault_wrapper::normalized_key;

type FolderId = Uuid;
type ItemId = Uuid;
type SectionId = Uuid;
type CredentialId = Uuid;

/// Vault contains decrypted metadata for all folders, items, and credentials
/// in a vault, as well as the encrypted secrets for each credential. It is
/// used to display the vault contents without decrypting secrets, and to look
/// up credentials by their item and credential keys.
///
/// Folders and sections only affect display. Items are addressed by key
/// regardless of their folder, and credentials by key regardless of their
/// section.
pub struct Vault {
    id: Uuid,
    pub name: Option<String>,
    file_key: VaultFileKey,
    cipher: VaultCipher,

    folders: BTreeMap<FolderId, VaultFolder>,
    items: BTreeMap<ItemId, VaultItemOverview>,
    item_index: BTreeMap<String, ItemId>,
    item_credential_index: BTreeMap<(String, String), (ItemId, CredentialId)>,
    secrets: BTreeMap<CredentialId, EncryptedBlob<String>>,
    // Previous values of live credentials, oldest first. A credential with none
    // has no entry.
    history: BTreeMap<CredentialId, Vec<HistoryEntry>>,
    // Deleted credentials of all items, by credential id. The key of a deleted
    // credential is not in `item_credential_index`.
    deleted: BTreeMap<CredentialId, DeletedEntry>,
    // Deleted items, by item id. Each holds its credentials and its own
    // deleted credentials. The key of a deleted item is not in `item_index`.
    deleted_items: BTreeMap<ItemId, DeletedItemEntry>,

    // Cached encrypted metadata blobs. The vault blob holds the folders. An
    // entry is dropped when its metadata changes so that to_encrypted() only
    // re-encrypts what is necessary.
    metadata_blob: Option<EncryptedBlob<VaultMetadata>>,
    item_blobs: BTreeMap<ItemId, EncryptedBlob<VaultItemMetadata>>,
    cred_blobs: BTreeMap<CredentialId, EncryptedBlob<VaultCredentialMetadata>>,
}

impl Vault {
    pub fn new(name: Option<String>, user_encryption_key: ManagedKey) -> Result<Self, Error> {
        let vault_id = Uuid::new_v4();
        let actual_file_key = Zeroizing::new(Aes256Gcm::generate_key(OsRng));

        // use actual key to create personal vault file key
        let enc_file_key = VaultFileKey::Personal(
            user_encryption_key
                .encrypt(&actual_file_key)
                .ok_or(Error::VaultFileKeyEncryptionError)?
                .into_bytes(),
        );

        // wrap actual key in VaultCipher to simplify operations
        let cipher = VaultCipher::new_with_bytes(&actual_file_key, vault_id);

        Ok(Self::empty(vault_id, name, enc_file_key, cipher))
    }

    fn empty(id: Uuid, name: Option<String>, file_key: VaultFileKey, cipher: VaultCipher) -> Self {
        Self {
            id,
            name,
            file_key,
            cipher,
            folders: BTreeMap::new(),
            items: BTreeMap::new(),
            item_index: BTreeMap::new(),
            item_credential_index: BTreeMap::new(),
            secrets: BTreeMap::new(),
            history: BTreeMap::new(),
            deleted: BTreeMap::new(),
            deleted_items: BTreeMap::new(),
            metadata_blob: None,
            item_blobs: BTreeMap::new(),
            cred_blobs: BTreeMap::new(),
        }
    }

    // This converts an EncryptedVault into a Vault by decrypting all
    // metadata and organizing data into the appropriate fields.
    pub fn from_encrypted(
        user_encryption_key: ManagedKey,
        enc_vault: EncryptedVault,
    ) -> Result<Self, Error> {
        let vault_cipher = enc_vault.decrypt_file_key(&user_encryption_key)?;
        Self::from_encrypted_with_cipher(vault_cipher, enc_vault)
    }

    fn from_encrypted_with_cipher(
        cipher: VaultCipher,
        enc_vault: EncryptedVault,
    ) -> Result<Self, Error> {
        let mut vault = Self::empty(enc_vault.id, enc_vault.name, enc_vault.file_key, cipher);

        if let Some(blob) = enc_vault.metadata {
            let metadata = vault.cipher.decrypt_vault_metadata(&blob)?;
            for folder in &metadata.expose_secret().folders {
                vault
                    .folders
                    .insert(folder.id, VaultFolder::from_metadata(folder));
            }
            vault.metadata_blob = Some(blob);
        }

        for (item_id, encrypted_item) in enc_vault.items {
            let item = Self::decrypt_item(&vault.cipher, &vault.folders, item_id, encrypted_item)?;
            vault.insert_item(item);
        }

        for (item_id, deleted_item) in enc_vault.deleted {
            let info = vault
                .cipher
                .decrypt_deleted_item_info(item_id, &deleted_item.info)?;
            let item =
                Self::decrypt_item(&vault.cipher, &vault.folders, item_id, deleted_item.item)?;
            vault.deleted_items.insert(
                item_id,
                DeletedItemEntry {
                    item,
                    info: deleted_item.info,
                    deleted_at: info.expose_secret().deleted_at,
                },
            );
        }

        Ok(vault)
    }

    /// Decrypt the metadata of an item, its credentials, and its deleted
    /// credentials. Secret values stay encrypted.
    fn decrypt_item(
        cipher: &VaultCipher,
        folders: &BTreeMap<FolderId, VaultFolder>,
        item_id: ItemId,
        encrypted_item: EncryptedVaultItem,
    ) -> Result<DecryptedItem, Error> {
        let mut overview = cipher
            .decrypt_item_metadata(item_id, &encrypted_item.metadata)
            .map(|m| VaultItemOverview::from_metadata(item_id, m.expose_secret()))?;

        // An item filed in a folder that no longer exists is unfiled. Its
        // metadata blob is not current, so the next save persists that.
        let mut metadata_current = true;
        if overview.folder.is_some_and(|f| !folders.contains_key(&f)) {
            overview.folder = None;
            metadata_current = false;
        }

        let mut credentials = BTreeMap::new();
        for (cred_id, encrypted_cred) in encrypted_item.credentials {
            let mut cred_overview = cipher
                .decrypt_cred_metadata(item_id, cred_id, &encrypted_cred.metadata)
                .map(|m| VaultItemCredentialOverview::from_metadata(cred_id, m.expose_secret()))?;

            // Same as above, for a credential in a missing section.
            let mut cred_metadata_current = true;
            if cred_overview
                .section
                .is_some_and(|s| !overview.sections.contains_key(&s))
            {
                cred_overview.section = None;
                cred_metadata_current = false;
            }

            overview.credentials.insert(cred_id, cred_overview);
            credentials.insert(
                cred_id,
                DecryptedCredential {
                    metadata: encrypted_cred.metadata,
                    metadata_current: cred_metadata_current,
                    value: encrypted_cred.value,
                    history: encrypted_cred.history,
                },
            );
        }

        let mut deleted = BTreeMap::new();
        for (cred_id, encrypted_deleted) in encrypted_item.deleted {
            let credential = cipher
                .decrypt_cred_metadata(item_id, cred_id, &encrypted_deleted.credential.metadata)
                .map(|m| VaultItemCredentialOverview::from_metadata(cred_id, m.expose_secret()))?;
            let info = cipher.decrypt_deleted_info(item_id, cred_id, &encrypted_deleted.info)?;
            deleted.insert(
                cred_id,
                DeletedEntry {
                    blobs: encrypted_deleted,
                    overview: DeletedCredentialOverview {
                        item_id,
                        credential,
                        deleted_at: info.expose_secret().deleted_at,
                    },
                },
            );
        }

        Ok(DecryptedItem {
            overview,
            metadata: encrypted_item.metadata,
            metadata_current,
            credentials,
            deleted,
        })
    }

    /// Make a decrypted item live. Its indices, secrets, cached metadata
    /// blobs, and deleted credentials are added.
    fn insert_item(&mut self, item: DecryptedItem) {
        let DecryptedItem {
            overview,
            metadata,
            metadata_current,
            credentials,
            deleted,
        } = item;
        let item_id = overview.id;

        if metadata_current {
            self.item_blobs.insert(item_id, metadata);
        }
        for (cred_id, cred) in credentials {
            if cred.metadata_current {
                self.cred_blobs.insert(cred_id, cred.metadata);
            }
            self.secrets.insert(cred_id, cred.value);
            if !cred.history.is_empty() {
                self.history.insert(cred_id, cred.history);
            }
        }
        for cred in overview.credentials.values() {
            self.item_credential_index
                .insert((overview.key.clone(), cred.key.clone()), (item_id, cred.id));
        }
        self.deleted.extend(deleted);
        self.item_index.insert(overview.key.clone(), item_id);
        self.items.insert(item_id, overview);
    }

    /// Encrypted form of a decrypted item. Blobs that are not current are
    /// encrypted again.
    fn item_to_encrypted(&self, item: &DecryptedItem) -> Result<EncryptedVaultItem, Error> {
        let item_id = item.overview.id;
        let metadata = if item.metadata_current {
            item.metadata.clone()
        } else {
            self.cipher
                .encrypt_item_metadata(item_id, &item.overview.to_metadata())?
        };

        let mut credentials = BTreeMap::new();
        for (cred_id, cred) in &item.credentials {
            let metadata = match item.overview.credentials.get(cred_id) {
                Some(overview) if !cred.metadata_current => {
                    self.cipher
                        .encrypt_cred_metadata(item_id, *cred_id, &overview.to_metadata())?
                },
                _ => cred.metadata.clone(),
            };
            credentials.insert(
                *cred_id,
                EncryptedVaultItemCredential {
                    metadata,
                    value: cred.value.clone(),
                    history: cred.history.clone(),
                },
            );
        }

        let deleted = item
            .deleted
            .iter()
            .map(|(cred_id, entry)| (*cred_id, entry.blobs.clone()))
            .collect();
        Ok(EncryptedVaultItem {
            metadata,
            credentials,
            deleted,
        })
    }

    /// Convert to the on disk form. Deleted items and credentials are written
    /// only if `include_deleted` is set.
    pub fn to_encrypted(&self, include_deleted: bool) -> Result<EncryptedVault, Error> {
        let mut vault = EncryptedVault {
            id: self.id,
            name: self.name.clone(),
            file_key: self.file_key.clone(),
            metadata: None,
            items: BTreeMap::new(),
            deleted: BTreeMap::new(),
        };

        let metadata = VaultMetadata {
            folders: self
                .folders
                .values()
                .map(VaultFolder::to_metadata)
                .collect(),
        };
        vault.set_metadata(&self.cipher, self.metadata_blob.as_ref(), &metadata)?;

        for item_overview in self.items.values() {
            let existing_metadata = self.item_blobs.get(&item_overview.id);
            vault.add_item(&self.cipher, existing_metadata, item_overview)?;

            for (cred_id, cred_overview) in &item_overview.credentials {
                let existing_metadata = self.cred_blobs.get(cred_id);
                // A credential created with no value yet has no entry in
                // `self.secrets` (see `add_or_update_item_credential`); encrypt
                // an empty value for it rather than treating this as an error.
                let secret = match self.secrets.get(cred_id) {
                    Some(secret) => secret.clone(),
                    None => self
                        .cipher
                        .encrypt_cred_value(item_overview.id, *cred_id, "")?,
                };
                vault.add_credential(
                    &self.cipher,
                    existing_metadata,
                    item_overview.id,
                    cred_overview,
                    secret,
                    self.history.get(cred_id).cloned().unwrap_or_default(),
                )?;
            }
        }

        if include_deleted {
            for (cred_id, entry) in &self.deleted {
                vault.add_deleted_credential(
                    entry.overview.item_id,
                    *cred_id,
                    entry.blobs.clone(),
                )?;
            }
            for (item_id, entry) in &self.deleted_items {
                vault.add_deleted_item(
                    *item_id,
                    DeletedItem {
                        item: self.item_to_encrypted(&entry.item)?,
                        info: entry.info.clone(),
                    },
                );
            }
        }

        Ok(vault)
    }

    /// Build a [`BundledVault`] for export. `key` is the preferred import key,
    /// `bundle_cipher` wraps the raw file key.
    ///
    /// Deleted items and credentials are not exported.
    ///
    /// The exported vault carries this vault's own file key. An imported copy
    /// shares that key with the source; export does not re-key.
    pub fn to_bundled_vault(
        &self,
        key: Option<String>,
        bundle_id: Uuid,
        bundle_cipher: &Aes256Gcm,
    ) -> Result<BundledVault, Error> {
        let encrypted_vault = self.to_encrypted(false)?;
        let wrapped_file_key = self.cipher.wrap_raw_key(
            bundle_cipher,
            ExportedBundle::file_key_aad(bundle_id, self.id),
        )?;
        Ok(BundledVault {
            id: encrypted_vault.id,
            name: encrypted_vault.name,
            default_key: key,
            wrapped_file_key,
            metadata: encrypted_vault.metadata,
            items: encrypted_vault.items,
        })
    }

    pub fn list_folders(&self) -> Vec<&VaultFolder> {
        self.folders.values().collect()
    }

    pub fn get_folder(&self, folder_id: FolderId) -> Result<&VaultFolder, Error> {
        self.folders
            .get(&folder_id)
            .ok_or_else(|| Error::InvalidFolder(folder_id.to_string()))
    }

    pub fn create_folder(&mut self, title: &str) -> &VaultFolder {
        let folder = VaultFolder::new(title);
        self.metadata_blob = None;
        self.folders.entry(folder.id).or_insert(folder)
    }

    pub fn rename_folder(&mut self, folder_id: FolderId, title: &str) -> Result<(), Error> {
        let folder = self
            .folders
            .get_mut(&folder_id)
            .ok_or_else(|| Error::InvalidFolder(folder_id.to_string()))?;
        folder.title = title.trim().to_string();
        self.metadata_blob = None;
        Ok(())
    }

    /// Delete a folder. Items in it become unfiled; they are not deleted.
    pub fn delete_folder(&mut self, folder_id: FolderId) -> Result<(), Error> {
        self.folders
            .remove(&folder_id)
            .ok_or_else(|| Error::InvalidFolder(folder_id.to_string()))?;
        self.metadata_blob = None;

        for item in self.items.values_mut() {
            if item.folder == Some(folder_id) {
                item.folder = None;
                self.item_blobs.remove(&item.id);
            }
        }
        Ok(())
    }

    /// Set the display order of folders. `ordered_folder_ids` must list every
    /// folder exactly once.
    pub fn reorder_folders(&mut self, ordered_folder_ids: &[FolderId]) -> Result<(), Error> {
        if !assign_positions(&mut self.folders, ordered_folder_ids, |f| &mut f.position) {
            return Err(Error::InvalidFolderOrder);
        }
        self.metadata_blob = None;
        Ok(())
    }

    /// Move an item into a folder, or out of any folder when `folder_id` is
    /// `None`.
    pub fn move_item(&mut self, item_key: &str, folder_id: Option<FolderId>) -> Result<(), Error> {
        if let Some(folder_id) = folder_id {
            self.get_folder(folder_id)?;
        }
        self.edit_item(item_key, |item| {
            item.folder = folder_id;
            Ok(())
        })
    }

    pub fn list_items(&self) -> Vec<&VaultItemOverview> {
        self.items.values().collect()
    }

    pub fn get_item_id(&self, item_key: &str) -> Result<&ItemId, Error> {
        self.item_index
            .get(item_key)
            .ok_or_else(|| Error::InvalidItemKey(item_key.to_string()))
    }

    pub fn get_item(&self, item_key: &str) -> Result<&VaultItemOverview, Error> {
        let item_id = self.get_item_id(item_key)?;
        self.items
            .get(item_id)
            .ok_or_else(|| Error::InvalidItemKey(item_key.to_string()))
    }

    /// Apply `edit` to an item's overview. If it succeeds, the item's cached
    /// metadata blob is dropped so the next save re-encrypts it.
    fn edit_item<'a, R>(
        &'a mut self,
        item_key: &str,
        edit: impl FnOnce(&'a mut VaultItemOverview) -> Result<R, Error>,
    ) -> Result<R, Error> {
        let item_id = *self.get_item_id(item_key)?;
        let item = self
            .items
            .get_mut(&item_id)
            .ok_or_else(|| Error::InvalidItemKey(item_key.to_string()))?;
        let result = edit(item)?;
        self.item_blobs.remove(&item_id);
        Ok(result)
    }

    pub fn add_or_update_item(
        &mut self,
        item_key: &str,
        item_title: &str,
    ) -> Result<&VaultItemOverview, Error> {
        let item_overview = match self.get_item(item_key) {
            Ok(existing) => VaultItemOverview {
                title: item_title.trim().to_string(),
                ..existing.clone()
            },
            Err(Error::InvalidItemKey(_)) => VaultItemOverview::try_new(item_title, item_key)?,
            Err(e) => return Err(e),
        };

        let item_id = item_overview.id;
        let item_key = item_overview.key.clone(); // normalized key

        // update maps
        self.items.insert(item_id, item_overview);
        self.item_index.insert(item_key, item_id);
        self.item_blobs.remove(&item_id); // for simplicity, always attempt this

        // get a reference to return
        let item_overview_ref = self.items.get(&item_id).expect("just inserted");
        Ok(item_overview_ref)
    }

    /// Mark an item as deleted. Its key is free for reuse. Its credentials,
    /// with their encrypted values, and its deleted credentials go with it.
    pub fn delete_item(&mut self, item_key: &str) -> Result<(), Error> {
        let item_id = *self.get_item_id(item_key)?;
        let overview = self
            .items
            .get(&item_id)
            .ok_or_else(|| Error::InvalidItemKey(item_key.to_string()))?
            .clone();

        // Build the deleted entry before changing anything.
        let metadata = match self.item_blobs.get(&item_id) {
            Some(blob) => blob.clone(),
            None => self
                .cipher
                .encrypt_item_metadata(item_id, &overview.to_metadata())?,
        };
        let mut credentials = BTreeMap::new();
        for cred in overview.credentials.values() {
            let blobs = self.live_credential_blobs(item_id, cred)?;
            credentials.insert(
                cred.id,
                DecryptedCredential {
                    metadata: blobs.metadata,
                    metadata_current: true,
                    value: blobs.value,
                    history: blobs.history,
                },
            );
        }
        let deleted_at = OffsetDateTime::now_utc().unix_timestamp();
        let info = self
            .cipher
            .encrypt_deleted_item_info(item_id, &DeletedInfo { deleted_at })?;

        // remove credentials from indices, secrets, and cached blobs
        for cred in overview.credentials.values() {
            let composite_key = (item_key.to_string(), cred.key.clone());
            self.item_credential_index.remove(&composite_key);
            self.secrets.remove(&cred.id);
            self.history.remove(&cred.id);
            self.cred_blobs.remove(&cred.id);
        }

        // The item's deleted credentials go with it.
        let deleted_cred_ids: Vec<CredentialId> = self
            .deleted
            .iter()
            .filter(|(_, entry)| entry.overview.item_id == item_id)
            .map(|(cred_id, _)| *cred_id)
            .collect();
        let mut deleted = BTreeMap::new();
        for cred_id in deleted_cred_ids {
            if let Some(entry) = self.deleted.remove(&cred_id) {
                deleted.insert(cred_id, entry);
            }
        }

        // remove from indices and items map
        self.item_index.remove(item_key);
        self.items.remove(&item_id);
        self.item_blobs.remove(&item_id);

        self.deleted_items.insert(
            item_id,
            DeletedItemEntry {
                item: DecryptedItem {
                    overview,
                    metadata,
                    metadata_current: true,
                    credentials,
                    deleted,
                },
                info,
                deleted_at,
            },
        );
        Ok(())
    }

    /// Deleted items, most recently deleted first.
    pub fn list_deleted_items(&self) -> Vec<DeletedItemOverview<'_>> {
        let mut entries: Vec<DeletedItemOverview<'_>> = self
            .deleted_items
            .values()
            .map(|entry| DeletedItemOverview {
                item: &entry.item.overview,
                deleted_at: entry.deleted_at,
                deleted_credentials: entry
                    .item
                    .deleted
                    .values()
                    .map(|deleted| &deleted.overview.credential)
                    .collect(),
            })
            .collect();
        entries.sort_by_key(|overview| std::cmp::Reverse(overview.deleted_at));
        entries
    }

    /// Restore a deleted item with its id, folder, sections, credentials, and
    /// deleted credentials. A folder that no longer exists is dropped. The item
    /// gets `new_key` if given. Fails with `DuplicateItemKey` if the resulting
    /// key is taken, and with `DeletedItemNotFound` if there is no such
    /// deleted item.
    pub fn restore_item(
        &mut self,
        item_id: ItemId,
        new_key: Option<String>,
    ) -> Result<&VaultItemOverview, Error> {
        let entry = self
            .deleted_items
            .get(&item_id)
            .ok_or_else(|| Error::DeletedItemNotFound(item_id.to_string()))?;
        let key = match new_key {
            Some(new_key) => normalized_key(&new_key).ok_or(Error::InvalidItemKey(new_key))?,
            None => entry.item.overview.key.clone(),
        };
        if self.item_index.contains_key(&key) {
            return Err(Error::DuplicateItemKey(key));
        }

        let Some(DeletedItemEntry { mut item, .. }) = self.deleted_items.remove(&item_id) else {
            return Err(Error::DeletedItemNotFound(item_id.to_string()));
        };
        if item.overview.key != key {
            item.overview.key = key;
            item.metadata_current = false;
        }
        if item
            .overview
            .folder
            .is_some_and(|f| !self.folders.contains_key(&f))
        {
            item.overview.folder = None;
            item.metadata_current = false;
        }
        self.insert_item(item);
        self.items
            .get(&item_id)
            .ok_or_else(|| Error::InvalidItemKey(item_id.to_string()))
    }

    /// Purge a deleted item with its credentials and deleted credentials.
    pub fn purge_item(&mut self, item_id: ItemId) -> Result<(), Error> {
        self.deleted_items
            .remove(&item_id)
            .map(|_| ())
            .ok_or_else(|| Error::DeletedItemNotFound(item_id.to_string()))
    }

    /// Purge every deleted item deleted before `older_than`, a Unix timestamp
    /// in seconds. Return the number purged.
    pub fn purge_deleted_items(&mut self, older_than: i64) -> usize {
        let before = self.deleted_items.len();
        self.deleted_items
            .retain(|_, entry| entry.deleted_at >= older_than);
        before - self.deleted_items.len()
    }

    /// Encrypted blobs of a live credential. A credential created with no value
    /// yet has no entry in `secrets`, so its value is encrypted as empty.
    fn live_credential_blobs(
        &self,
        item_id: ItemId,
        cred: &VaultItemCredentialOverview,
    ) -> Result<EncryptedVaultItemCredential, Error> {
        let metadata = match self.cred_blobs.get(&cred.id) {
            Some(blob) => blob.clone(),
            None => self
                .cipher
                .encrypt_cred_metadata(item_id, cred.id, &cred.to_metadata())?,
        };
        let value = match self.secrets.get(&cred.id) {
            Some(value) => value.clone(),
            None => self.cipher.encrypt_cred_value(item_id, cred.id, "")?,
        };
        let history = self.history.get(&cred.id).cloned().unwrap_or_default();
        Ok(EncryptedVaultItemCredential {
            metadata,
            value,
            history,
        })
    }

    /// History entry for the current value of a credential, if `new_value`
    /// replaces it. A credential with no value yet, an empty value, or the same
    /// value has nothing to keep.
    fn replaced_value_entry(
        &self,
        item_id: ItemId,
        cred_id: CredentialId,
        new_value: &str,
    ) -> Result<Option<HistoryEntry>, Error> {
        let Some(current) = self.secrets.get(&cred_id) else {
            return Ok(None);
        };
        let current = self.cipher.decrypt_cred_value(item_id, cred_id, current)?;
        if current.expose_secret().is_empty() || current.expose_secret() == new_value {
            return Ok(None);
        }

        let id = Uuid::new_v4();
        let replaced_at = OffsetDateTime::now_utc().unix_timestamp();
        Ok(Some(HistoryEntry {
            id,
            value: self.cipher.encrypt_history_value(
                item_id,
                cred_id,
                id,
                current.expose_secret(),
            )?,
            info: self.cipher.encrypt_history_info(
                item_id,
                cred_id,
                id,
                &HistoryInfo { replaced_at },
            )?,
        }))
    }

    /// Create a section after the existing sections of an item. Existing
    /// sections are assigned positions in current display order, since
    /// sections without positions sort by title.
    pub fn create_item_section(
        &mut self,
        item_key: &str,
        title: &str,
    ) -> Result<&VaultItemSection, Error> {
        let section = VaultItemSection::new(title);
        let section_id = section.id;
        self.edit_item(item_key, |item| {
            let mut ordered: Vec<&VaultItemSection> = item.sections.values().collect();
            ordered.sort_by(|a, b| {
                display_order(a.position, &a.title).cmp(&display_order(b.position, &b.title))
            });
            let mut ordered_ids: Vec<SectionId> = ordered.iter().map(|s| s.id).collect();
            ordered_ids.push(section_id);
            item.sections.insert(section_id, section);
            assign_positions(&mut item.sections, &ordered_ids, |s| &mut s.position);
            Ok(&item.sections[&section_id])
        })
    }

    pub fn rename_item_section(
        &mut self,
        item_key: &str,
        section_id: SectionId,
        title: &str,
    ) -> Result<(), Error> {
        self.edit_item(item_key, |item| {
            let section = item
                .sections
                .get_mut(&section_id)
                .ok_or_else(|| Error::InvalidSection(section_id.to_string()))?;
            section.title = title.trim().to_string();
            Ok(())
        })
    }

    /// Delete a section of an item. Credentials in it move out of any section;
    /// they are not deleted.
    pub fn delete_item_section(
        &mut self,
        item_key: &str,
        section_id: SectionId,
    ) -> Result<(), Error> {
        let moved_cred_ids = self.edit_item(item_key, |item| {
            item.sections
                .remove(&section_id)
                .ok_or_else(|| Error::InvalidSection(section_id.to_string()))?;
            let mut moved = Vec::new();
            for cred in item.credentials.values_mut() {
                if cred.section == Some(section_id) {
                    cred.section = None;
                    moved.push(cred.id);
                }
            }
            Ok(moved)
        })?;
        for cred_id in &moved_cred_ids {
            self.cred_blobs.remove(cred_id);
        }
        Ok(())
    }

    /// Set the display order of an item's sections. `ordered_section_ids` must
    /// list every section of the item exactly once.
    pub fn reorder_item_sections(
        &mut self,
        item_key: &str,
        ordered_section_ids: &[SectionId],
    ) -> Result<(), Error> {
        self.edit_item(item_key, |item| {
            if assign_positions(&mut item.sections, ordered_section_ids, |s| &mut s.position) {
                Ok(())
            } else {
                Err(Error::InvalidSectionOrder(item_key.to_string()))
            }
        })
    }

    /// The item and credential ids for a credential, by key.
    fn get_credential_ids(
        &self,
        item_key: &str,
        cred_key: &str,
    ) -> Result<(ItemId, CredentialId), Error> {
        self.item_credential_index
            .get(&(item_key.to_string(), cred_key.to_string()))
            .copied()
            .ok_or_else(|| Error::InvalidCredentialKey(format!("{item_key}/{cred_key}")))
    }

    pub fn get_item_credential(
        &self,
        item_key: &str,
        cred_key: &str,
    ) -> Result<&VaultItemCredentialOverview, Error> {
        let (item_id, cred_id) = self.get_credential_ids(item_key, cred_key)?;
        let item = self
            .items
            .get(&item_id)
            .ok_or_else(|| Error::InvalidItemKey(item_key.to_string()))?;
        item.credentials
            .get(&cred_id)
            .ok_or_else(|| Error::InvalidCredentialKey(cred_key.to_string()))
    }

    /// Add a credential. Fails with `DuplicateCredentialKey` if the item
    /// already has a credential with this key.
    pub fn add_item_credential(
        &mut self,
        item_key: &str,
        cred_key: &str,
        cred_title: &str,
        cred_kind: FieldKind,
        cred_value: SecretString,
    ) -> Result<&VaultItemCredentialOverview, Error> {
        if let Some(key) = normalized_key(cred_key)
            && self
                .item_credential_index
                .contains_key(&(item_key.to_string(), key.clone()))
        {
            return Err(Error::DuplicateCredentialKey(key));
        }
        self.add_or_update_item_credential(item_key, cred_key, cred_title, cred_kind, cred_value)
    }

    pub fn add_or_update_item_credential(
        &mut self,
        item_key: &str,
        cred_key: &str,
        cred_title: &str,
        cred_kind: FieldKind,
        cred_value: SecretString,
    ) -> Result<&VaultItemCredentialOverview, Error> {
        // get existing cred by key or create new one
        let cred_overview = match self.get_item_credential(item_key, cred_key) {
            Ok(existing) => VaultItemCredentialOverview {
                title: cred_title.to_string(),
                kind: cred_kind,
                ..existing.clone()
            },
            Err(Error::InvalidCredentialKey(_)) => {
                VaultItemCredentialOverview::try_new(cred_title, cred_key, cred_kind)?
            },
            Err(e) => return Err(e),
        };
        let cred_id = cred_overview.id;
        let cred_key = cred_overview.key.clone(); // normalized key

        let item_id = *self.get_item_id(item_key)?;
        let secret = cred_value.expose_secret();
        let replaced = self.replaced_value_entry(item_id, cred_id, secret)?;
        let encrypted_secret = self.cipher.encrypt_cred_value(item_id, cred_id, secret)?;

        let item = self
            .items
            .get_mut(&item_id)
            .ok_or_else(|| Error::InvalidItemKey(item_key.to_string()))?;
        self.secrets.insert(cred_id, encrypted_secret);
        if let Some(entry) = replaced {
            self.history.entry(cred_id).or_default().push(entry);
        }

        // add or update credential in item.credentials
        item.credentials.insert(cred_id, cred_overview);

        // update indices. note: if credential already exists, the following should just
        // overwrite the existing keys.
        self.item_credential_index
            .insert((item_key.to_string(), cred_key), (item_id, cred_id));
        self.cred_blobs.remove(&cred_id); // for simplicity, always attempt this

        // get a reference to return
        let cred_overview_ref = item.credentials.get(&cred_id).expect("just inserted");
        Ok(cred_overview_ref)
    }

    /// Change the key, title, or kind of a credential without touching its
    /// value. Fields left `None` in `update` are unchanged. The value is
    /// encrypted under the credential id, not its key, so it remains valid
    /// after a key change.
    pub fn update_item_credential(
        &mut self,
        item_key: &str,
        cred_key: &str,
        update: CredentialUpdate,
    ) -> Result<&VaultItemCredentialOverview, Error> {
        let (item_id, cred_id) = self.get_credential_ids(item_key, cred_key)?;

        let new_key = match update.key {
            Some(key) => {
                let key =
                    normalized_key(&key).ok_or_else(|| Error::InvalidCredentialKey(key.clone()))?;
                if key != cred_key
                    && self
                        .item_credential_index
                        .contains_key(&(item_key.to_string(), key.clone()))
                {
                    return Err(Error::DuplicateCredentialKey(key));
                }
                Some(key)
            },
            None => None,
        };

        let item = self
            .items
            .get_mut(&item_id)
            .ok_or_else(|| Error::InvalidItemKey(item_key.to_string()))?;
        let cred = item
            .credentials
            .get_mut(&cred_id)
            .ok_or_else(|| Error::InvalidCredentialKey(format!("{item_key}/{cred_key}")))?;

        if let Some(title) = update.title {
            cred.title = title.trim().to_string();
        }
        if let Some(kind) = update.kind {
            cred.kind = kind;
        }
        if let Some(key) = new_key
            && key != cred.key
        {
            self.item_credential_index
                .remove(&(item_key.to_string(), cred.key.clone()));
            self.item_credential_index
                .insert((item_key.to_string(), key.clone()), (item_id, cred_id));
            cred.key = key;
        }
        self.cred_blobs.remove(&cred_id);
        Ok(cred)
    }

    /// Mark a credential as deleted. Its key is free for reuse. The
    /// encrypted value is kept unchanged.
    pub fn delete_item_credential(&mut self, item_key: &str, cred_key: &str) -> Result<(), Error> {
        let (item_id, cred_id) = self.get_credential_ids(item_key, cred_key)?;
        let credential = self.get_item_credential(item_key, cred_key)?.clone();

        // Build the deleted entry before changing anything.
        let credential_blobs = self.live_credential_blobs(item_id, &credential)?;
        let deleted_at = OffsetDateTime::now_utc().unix_timestamp();
        let info =
            self.cipher
                .encrypt_deleted_info(item_id, cred_id, &DeletedInfo { deleted_at })?;

        // remove from item
        let item = self
            .items
            .get_mut(&item_id)
            .ok_or_else(|| Error::InvalidItemKey(item_key.to_string()))?;
        item.credentials.remove(&cred_id);

        // remove from indices and secrets map
        self.item_credential_index
            .remove(&(item_key.to_string(), cred_key.to_string()));
        self.secrets.remove(&cred_id);
        self.history.remove(&cred_id);
        self.cred_blobs.remove(&cred_id);

        self.deleted.insert(
            cred_id,
            DeletedEntry {
                blobs: DeletedCredential {
                    credential: credential_blobs,
                    info,
                },
                overview: DeletedCredentialOverview {
                    item_id,
                    credential,
                    deleted_at,
                },
            },
        );
        Ok(())
    }

    /// Deleted credentials of an item, most recently deleted first.
    #[cfg(test)]
    pub fn list_deleted(&self, item_key: &str) -> Result<Vec<&DeletedCredentialOverview>, Error> {
        let item_id = *self.get_item_id(item_key)?;
        let mut entries: Vec<&DeletedCredentialOverview> = self
            .deleted
            .values()
            .map(|entry| &entry.overview)
            .filter(|overview| overview.item_id == item_id)
            .collect();
        entries.sort_by_key(|overview| std::cmp::Reverse(overview.deleted_at));
        Ok(entries)
    }

    /// Deleted credentials of all live items, most recently deleted first.
    pub fn list_all_deleted(&self) -> Vec<DeletedCredentialEntry<'_>> {
        let mut entries: Vec<DeletedCredentialEntry<'_>> = self
            .deleted
            .values()
            .filter_map(|entry| {
                Some(DeletedCredentialEntry {
                    item: self.items.get(&entry.overview.item_id)?,
                    credential: &entry.overview,
                })
            })
            .collect();
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.credential.deleted_at));
        entries
    }

    /// Secret of a deleted credential. The credential is either deleted from
    /// the live item `item_id`, or part of the deleted item `item_id`, live or
    /// deleted before the item.
    pub fn get_deleted_credential_secret(
        &self,
        item_id: ItemId,
        cred_id: CredentialId,
    ) -> Result<SecretBox<String>, Error> {
        let from_live_item = self
            .deleted
            .get(&cred_id)
            .filter(|entry| entry.overview.item_id == item_id)
            .map(|entry| &entry.blobs.credential.value);
        let from_deleted_item = || {
            let item = &self.deleted_items.get(&item_id)?.item;
            item.credentials
                .get(&cred_id)
                .map(|cred| &cred.value)
                .or_else(|| {
                    item.deleted
                        .get(&cred_id)
                        .map(|entry| &entry.blobs.credential.value)
                })
        };
        let blob = from_live_item
            .or_else(from_deleted_item)
            .ok_or_else(|| Error::InvalidCredentialKey(format!("{item_id}/{cred_id}")))?;
        self.cipher.decrypt_cred_value(item_id, cred_id, blob)
    }

    /// Restore a deleted credential with its id, position, and section. A
    /// section that no longer exists is dropped. The credential gets `new_key`
    /// if given. Fails with `DuplicateCredentialKey` if the resulting key is
    /// taken in the item.
    pub fn restore_item_credential(
        &mut self,
        item_key: &str,
        cred_id: CredentialId,
        new_key: Option<String>,
    ) -> Result<&VaultItemCredentialOverview, Error> {
        let item_id = *self.get_item_id(item_key)?;
        let mut credential = self
            .deleted_overview(item_key, item_id, cred_id)?
            .credential
            .clone();

        let mut metadata_changed = false;
        if let Some(new_key) = new_key {
            let key = normalized_key(&new_key).ok_or(Error::InvalidCredentialKey(new_key))?;
            metadata_changed = key != credential.key;
            credential.key = key;
        }
        if self
            .item_credential_index
            .contains_key(&(item_key.to_string(), credential.key.clone()))
        {
            return Err(Error::DuplicateCredentialKey(credential.key));
        }

        let item = self
            .items
            .get_mut(&item_id)
            .ok_or_else(|| Error::InvalidItemKey(item_key.to_string()))?;
        if credential
            .section
            .is_some_and(|s| !item.sections.contains_key(&s))
        {
            credential.section = None;
            metadata_changed = true;
        }

        let entry = self
            .deleted
            .remove(&cred_id)
            .ok_or_else(|| Error::InvalidCredentialKey(format!("{item_key}/{cred_id}")))?;
        let DeletedCredential {
            credential: blobs, ..
        } = entry.blobs;
        self.secrets.insert(cred_id, blobs.value);
        if !blobs.history.is_empty() {
            self.history.insert(cred_id, blobs.history);
        }
        // The stored metadata blob is reused only if it still matches.
        if !metadata_changed {
            self.cred_blobs.insert(cred_id, blobs.metadata);
        }
        self.item_credential_index.insert(
            (item_key.to_string(), credential.key.clone()),
            (item_id, cred_id),
        );
        item.credentials.insert(cred_id, credential);
        Ok(item.credentials.get(&cred_id).expect("just inserted"))
    }

    /// Purge a deleted credential.
    pub fn purge_item_credential(
        &mut self,
        item_key: &str,
        cred_id: CredentialId,
    ) -> Result<(), Error> {
        let item_id = *self.get_item_id(item_key)?;
        self.deleted_overview(item_key, item_id, cred_id)?;
        self.deleted.remove(&cred_id);
        Ok(())
    }

    /// Purge every deleted credential deleted before `older_than`, a Unix
    /// timestamp in seconds. Deleted credentials of deleted items are
    /// included. Return the number purged.
    pub fn purge_deleted(&mut self, older_than: i64) -> usize {
        let mut purged = 0;
        let deleted_maps = std::iter::once(&mut self.deleted).chain(
            self.deleted_items
                .values_mut()
                .map(|entry| &mut entry.item.deleted),
        );
        for deleted in deleted_maps {
            let before = deleted.len();
            deleted.retain(|_, entry| entry.overview.deleted_at >= older_than);
            purged += before - deleted.len();
        }
        purged
    }

    fn deleted_overview(
        &self,
        item_key: &str,
        item_id: ItemId,
        cred_id: CredentialId,
    ) -> Result<&DeletedCredentialOverview, Error> {
        self.deleted
            .get(&cred_id)
            .map(|entry| &entry.overview)
            .filter(|overview| overview.item_id == item_id)
            .ok_or_else(|| Error::InvalidCredentialKey(format!("{item_key}/{cred_id}")))
    }

    pub fn get_item_credential_secret(
        &self,
        item_key: &str,
        cred_key: &str,
    ) -> Result<Option<SecretBox<String>>, Error> {
        let item_id = match self.get_item(item_key) {
            Ok(item) => item.id,
            Err(Error::InvalidItemKey(_)) => return Ok(None),
            Err(e) => return Err(e),
        };
        let cred_overview = match self.get_item_credential(item_key, cred_key) {
            Ok(cred) => cred,
            Err(Error::InvalidCredentialKey(_)) | Err(Error::InvalidItemKey(_)) => {
                return Ok(None);
            },
            Err(e) => return Err(e),
        };
        let cred_id = cred_overview.id;
        let Some(encrypted_secret) = self.secrets.get(&cred_overview.id) else {
            return Ok(None);
        };
        let plaintext = self
            .cipher
            .decrypt_cred_value(item_id, cred_id, encrypted_secret)?;
        Ok(Some(plaintext))
    }

    /// Previous values of a credential, most recently replaced first. Entries
    /// whose details fail to decrypt are skipped and logged.
    pub fn list_history(
        &self,
        item_key: &str,
        cred_key: &str,
    ) -> Result<Vec<HistoryOverview>, Error> {
        let (item_id, cred_id) = self.get_credential_ids(item_key, cred_key)?;
        let mut entries = Vec::new();
        for entry in self.history.get(&cred_id).into_iter().flatten().rev() {
            let info =
                match self
                    .cipher
                    .decrypt_history_info(item_id, cred_id, entry.id, &entry.info)
                {
                    Ok(info) => info,
                    Err(e) => {
                        let id = entry.id;
                        log::warn!("Skipping previous value {id} of {item_key}/{cred_key}: {e}");
                        continue;
                    },
                };
            entries.push(HistoryOverview {
                id: entry.id,
                replaced_at: info.expose_secret().replaced_at,
            });
        }
        Ok(entries)
    }

    /// A previous value of a credential.
    pub fn get_history_value(
        &self,
        item_key: &str,
        cred_key: &str,
        history_id: Uuid,
    ) -> Result<SecretBox<String>, Error> {
        let (item_id, cred_id) = self.get_credential_ids(item_key, cred_key)?;
        let entry = self.history_entry(cred_id, history_id)?;
        self.cipher
            .decrypt_history_value(item_id, cred_id, history_id, &entry.value)
    }

    /// Make a previous value the current value. The entry is removed from the
    /// history, and the value it replaces is added to it.
    pub fn restore_history_value(
        &mut self,
        item_key: &str,
        cred_key: &str,
        history_id: Uuid,
    ) -> Result<(), Error> {
        let (item_id, cred_id) = self.get_credential_ids(item_key, cred_key)?;
        let value = self.get_history_value(item_key, cred_key, history_id)?;
        let replaced = self.replaced_value_entry(item_id, cred_id, value.expose_secret())?;
        let encrypted_value =
            self.cipher
                .encrypt_cred_value(item_id, cred_id, value.expose_secret())?;

        self.secrets.insert(cred_id, encrypted_value);
        if let Some(history) = self.history.get_mut(&cred_id) {
            history.retain(|entry| entry.id != history_id);
        }
        if let Some(entry) = replaced {
            self.history.entry(cred_id).or_default().push(entry);
        }
        if self.history.get(&cred_id).is_some_and(Vec::is_empty) {
            self.history.remove(&cred_id);
        }
        Ok(())
    }

    /// Delete a previous value permanently.
    pub fn purge_history(
        &mut self,
        item_key: &str,
        cred_key: &str,
        history_id: Uuid,
    ) -> Result<(), Error> {
        let (_, cred_id) = self.get_credential_ids(item_key, cred_key)?;
        self.history_entry(cred_id, history_id)?;
        if let Some(history) = self.history.get_mut(&cred_id) {
            history.retain(|entry| entry.id != history_id);
            if history.is_empty() {
                self.history.remove(&cred_id);
            }
        }
        Ok(())
    }

    fn history_entry(
        &self,
        cred_id: CredentialId,
        history_id: Uuid,
    ) -> Result<&HistoryEntry, Error> {
        self.history
            .get(&cred_id)
            .and_then(|history| history.iter().find(|entry| entry.id == history_id))
            .ok_or_else(|| Error::InvalidHistoryEntry(history_id.to_string()))
    }

    /// Move a credential into a section of its item, or out of any section
    /// when `section_id` is `None`. Its position is unchanged.
    pub fn move_item_credential(
        &mut self,
        item_key: &str,
        cred_key: &str,
        section_id: Option<SectionId>,
    ) -> Result<(), Error> {
        let (item_id, cred_id) = self.get_credential_ids(item_key, cred_key)?;
        let item = self
            .items
            .get_mut(&item_id)
            .ok_or_else(|| Error::InvalidItemKey(item_key.to_string()))?;
        if let Some(section_id) = section_id
            && !item.sections.contains_key(&section_id)
        {
            return Err(Error::InvalidSection(section_id.to_string()));
        }
        let cred = item
            .credentials
            .get_mut(&cred_id)
            .ok_or_else(|| Error::InvalidCredentialKey(format!("{item_key}/{cred_key}")))?;
        cred.section = section_id;
        self.cred_blobs.remove(&cred_id);
        Ok(())
    }

    /// Set the display order and section of an item's credentials.
    /// `placements` must list exactly the item's credential keys, once each.
    /// Each credential's `position` is set to its index in `placements` and
    /// its section to the one given. Sections are ordered separately, so
    /// positions only matter relative to other credentials in the same
    /// section.
    pub fn reorder_item_credentials(
        &mut self,
        item_key: &str,
        placements: &[CredentialPlacement],
    ) -> Result<(), Error> {
        let item_id = *self.get_item_id(item_key)?;

        // Resolve every requested key to a credential id in this item.
        let mut ordered_ids = Vec::with_capacity(placements.len());
        for placement in placements {
            let (found_item_id, cred_id) = self.get_credential_ids(item_key, &placement.key)?;
            if found_item_id != item_id {
                return Err(Error::InvalidCredentialKey(format!(
                    "{item_key}/{}",
                    placement.key
                )));
            }
            ordered_ids.push(cred_id);
        }

        let item = self
            .items
            .get_mut(&item_id)
            .ok_or_else(|| Error::InvalidItemKey(item_key.to_string()))?;

        // Require a full permutation of the item's credentials.
        if !is_permutation(&ordered_ids, item.credentials.keys().copied()) {
            return Err(Error::InvalidCredentialOrder(item_key.to_string()));
        }

        if let Some(section_id) = placements
            .iter()
            .filter_map(|p| p.section)
            .find(|s| !item.sections.contains_key(s))
        {
            return Err(Error::InvalidSection(section_id.to_string()));
        }

        for (idx, (cred_id, placement)) in ordered_ids.iter().zip(placements).enumerate() {
            // Every id resolved through the index above, so a miss here means
            // the index and the item's credentials have diverged.
            let cred = item
                .credentials
                .get_mut(cred_id)
                .ok_or_else(|| Error::InvalidCredentialOrder(item_key.to_string()))?;
            cred.position = Some(idx as u32);
            cred.section = placement.section;

            // Invalidate the cached metadata blob so the next save re-encrypts
            // it with the new position and section.
            self.cred_blobs.remove(cred_id);
        }

        Ok(())
    }
}

/// Whether `ordered` lists every id in `existing` exactly once.
fn is_permutation(ordered: &[Uuid], existing: impl Iterator<Item = Uuid>) -> bool {
    let ordered_set: BTreeSet<Uuid> = ordered.iter().copied().collect();
    let existing: BTreeSet<Uuid> = existing.collect();
    ordered_set.len() == ordered.len() && ordered_set == existing
}

/// Sort key for folders, sections, and credentials. Entries with a position
/// come first, ordered by position, then the rest by title.
pub fn display_order(position: Option<u32>, title: &str) -> (u32, &str) {
    (position.unwrap_or(u32::MAX), title)
}

/// Set each entry's position, reached through `position`, to its index in
/// `ordered`. Returns false without changing anything unless `ordered` lists
/// every entry exactly once.
fn assign_positions<T>(
    entries: &mut BTreeMap<Uuid, T>,
    ordered: &[Uuid],
    position: impl Fn(&mut T) -> &mut Option<u32>,
) -> bool {
    if !is_permutation(ordered, entries.keys().copied()) {
        return false;
    }
    for (idx, id) in ordered.iter().enumerate() {
        if let Some(entry) = entries.get_mut(id) {
            *position(entry) = Some(idx as u32);
        }
    }
    true
}

#[derive(Clone)]
pub struct VaultFolder {
    pub id: Uuid,
    pub title: String,
    /// User-defined order among folders. `None` until folders are reordered.
    pub position: Option<u32>,
}

impl VaultFolder {
    pub fn new(title: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            title: title.trim().to_string(),
            position: None,
        }
    }

    fn from_metadata(metadata: &VaultFolderMetadata) -> Self {
        Self {
            id: metadata.id,
            title: metadata.title.clone(),
            position: metadata.position,
        }
    }

    pub fn to_metadata(&self) -> VaultFolderMetadata {
        VaultFolderMetadata {
            id: self.id,
            title: self.title.clone(),
            position: self.position,
        }
    }
}

#[derive(Clone, Debug)]
pub struct VaultItemSection {
    pub id: Uuid,
    pub title: String,
    /// User-defined order among the item's sections. `None` until the
    /// sections are reordered.
    pub position: Option<u32>,
}

impl VaultItemSection {
    pub fn new(title: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            title: title.trim().to_string(),
            position: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct VaultItemOverview {
    pub id: Uuid,
    pub title: String,
    pub key: String,
    /// Folder the item is filed in. `None` for an unfiled item.
    pub folder: Option<Uuid>,
    pub sections: BTreeMap<Uuid, VaultItemSection>,
    pub credentials: BTreeMap<Uuid, VaultItemCredentialOverview>,
}

impl VaultItemOverview {
    pub fn try_new(title: &str, key: &str) -> Result<Self, Error> {
        let item_key = normalized_key(key).ok_or_else(|| Error::InvalidItemKey(key.to_string()))?;
        Ok(Self {
            id: Uuid::new_v4(),
            title: title.to_string(),
            key: item_key,
            folder: None,
            sections: BTreeMap::new(),
            credentials: BTreeMap::new(),
        })
    }

    fn from_metadata(id: Uuid, metadata: &VaultItemMetadata) -> Self {
        let sections = metadata
            .sections
            .iter()
            .map(|s| {
                let section = VaultItemSection {
                    id: s.id,
                    title: s.title.clone(),
                    position: s.position,
                };
                (s.id, section)
            })
            .collect();
        Self {
            id,
            title: metadata.title.clone(),
            key: metadata.key.clone(),
            folder: metadata.folder,
            sections,
            credentials: BTreeMap::new(),
        }
    }

    pub fn to_metadata(&self) -> VaultItemMetadata {
        VaultItemMetadata {
            title: self.title.clone(),
            key: self.key.clone(),
            folder: self.folder,
            sections: self
                .sections
                .values()
                .map(|s| VaultSectionMetadata {
                    id: s.id,
                    title: s.title.clone(),
                    position: s.position,
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct VaultItemCredentialOverview {
    pub id: Uuid,
    pub title: String,
    pub key: String,
    pub kind: FieldKind,
    /// User-defined order within the item's section. `None` until the item is
    /// reordered.
    pub position: Option<u32>,
    /// Section of the item the credential is shown in. `None` for a
    /// credential outside any section.
    pub section: Option<Uuid>,
}

impl VaultItemCredentialOverview {
    pub fn try_new(title: &str, key: &str, kind: FieldKind) -> Result<Self, Error> {
        let cred_key =
            normalized_key(key).ok_or_else(|| Error::InvalidCredentialKey(key.to_string()))?;
        Ok(Self {
            id: Uuid::new_v4(),
            title: title.to_string(),
            key: cred_key,
            kind,
            position: None,
            section: None,
        })
    }

    fn from_metadata(id: Uuid, metadata: &VaultCredentialMetadata) -> Self {
        Self {
            id,
            title: metadata.title.clone(),
            key: metadata.key.clone(),
            kind: metadata.kind.clone(),
            position: metadata.position,
            section: metadata.section,
        }
    }

    pub fn to_metadata(&self) -> VaultCredentialMetadata {
        VaultCredentialMetadata {
            title: self.title.clone(),
            key: self.key.clone(),
            kind: self.kind.clone(),
            position: self.position,
            section: self.section,
        }
    }
}

/// A deleted credential as shown in the Recently Deleted list.
#[derive(Clone, Debug)]
pub struct DeletedCredentialOverview {
    pub item_id: ItemId,
    /// The credential as it was when deleted. It is also the entry id.
    pub credential: VaultItemCredentialOverview,
    /// Unix timestamp in seconds.
    pub deleted_at: i64,
}

struct DeletedEntry {
    blobs: DeletedCredential,
    overview: DeletedCredentialOverview,
}

/// A deleted item as shown in the Recently Deleted list.
pub struct DeletedItemOverview<'a> {
    /// The item as it was when deleted, with its credentials.
    pub item: &'a VaultItemOverview,
    /// Unix timestamp in seconds.
    pub deleted_at: i64,
    /// Credentials of the item that were deleted before the item.
    pub deleted_credentials: Vec<&'a VaultItemCredentialOverview>,
}

/// A deleted credential with the live item it was deleted from.
pub struct DeletedCredentialEntry<'a> {
    pub item: &'a VaultItemOverview,
    pub credential: &'a DeletedCredentialOverview,
}

struct DeletedItemEntry {
    item: DecryptedItem,
    info: EncryptedBlob<DeletedInfo>,
    deleted_at: i64,
}

/// An item with decrypted metadata and encrypted secrets, as it is held while
/// moving between live and deleted.
struct DecryptedItem {
    overview: VaultItemOverview,
    metadata: EncryptedBlob<VaultItemMetadata>,
    /// Whether `metadata` matches `overview`.
    metadata_current: bool,
    credentials: BTreeMap<CredentialId, DecryptedCredential>,
    deleted: BTreeMap<CredentialId, DeletedEntry>,
}

struct DecryptedCredential {
    metadata: EncryptedBlob<VaultCredentialMetadata>,
    /// Whether `metadata` matches the credential overview.
    metadata_current: bool,
    value: EncryptedBlob<String>,
    history: Vec<HistoryEntry>,
}

/// A previous value of a credential, without the value.
#[derive(Clone, Debug)]
pub struct HistoryOverview {
    pub id: Uuid,
    /// Unix timestamp in seconds.
    pub replaced_at: i64,
}

/// Details of a previous value, stored as one encrypted blob.
#[derive(Serialize, Deserialize, Zeroize)]
pub struct HistoryInfo {
    pub replaced_at: i64,
}

/// Details of a deleted credential or item, stored as one encrypted blob.
#[derive(Serialize, Deserialize, Zeroize)]
pub struct DeletedInfo {
    pub deleted_at: i64,
}

/// Changes for [`Vault::update_item_credential`]. `None` fields are left
/// unchanged.
#[derive(Default)]
pub struct CredentialUpdate {
    pub key: Option<String>,
    pub title: Option<String>,
    pub kind: Option<FieldKind>,
}

/// Where a credential goes in [`Vault::reorder_item_credentials`].
pub struct CredentialPlacement {
    pub key: String,
    pub section: Option<Uuid>,
}

/// Vault-level metadata, stored as one encrypted blob.
#[derive(Default, Serialize, Deserialize, Zeroize)]
pub struct VaultMetadata {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub folders: Vec<VaultFolderMetadata>,
}

impl VaultMetadata {
    pub fn is_empty(&self) -> bool {
        self.folders.is_empty()
    }
}

#[derive(Serialize, Deserialize, Zeroize)]
pub struct VaultFolderMetadata {
    #[zeroize(skip)]
    pub id: Uuid,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<u32>,
}

#[derive(Serialize, Deserialize, Zeroize)]
pub struct VaultItemMetadata {
    pub title: String,
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub folder: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<VaultSectionMetadata>,
}

#[derive(Serialize, Deserialize, Zeroize)]
pub struct VaultSectionMetadata {
    #[zeroize(skip)]
    pub id: Uuid,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<u32>,
}

#[derive(Serialize, Deserialize, Zeroize)]
pub struct VaultCredentialMetadata {
    pub title: String,
    pub key: String,
    #[serde(default, skip_serializing_if = "FieldKind::is_default")]
    pub kind: FieldKind,
    /// User-defined order of a credential within its section. Absent on
    /// legacy vaults and until the first reorder; unset credentials sort
    /// after set ones, by title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub section: Option<Uuid>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::vaults::fields::TextField;

    const TEST_FILE_KEY: [u8; 32] = [7u8; 32];

    fn test_vault() -> Vault {
        let id = Uuid::new_v4();
        Vault::empty(
            id,
            Some("test vault".to_string()),
            VaultFileKey::Personal(vec![0u8; 32]),
            VaultCipher::new_with_bytes(&TEST_FILE_KEY, id),
        )
    }

    /// Save and load the vault, as a restart would.
    fn reload(vault: &Vault) -> Vault {
        let encrypted = vault.to_encrypted(true).unwrap();
        let cipher = VaultCipher::new_with_bytes(&TEST_FILE_KEY, encrypted.id);
        Vault::from_encrypted_with_cipher(cipher, encrypted).unwrap()
    }

    /// A vault with one item holding the given credential keys, plus a second
    /// item with a single credential to test cross-item rejection.
    fn vault_with_credentials(item_key: &str, cred_keys: &[&str]) -> Vault {
        let mut vault = test_vault();
        vault.add_or_update_item(item_key, "Item").unwrap();
        for cred_key in cred_keys {
            vault
                .add_or_update_item_credential(
                    item_key,
                    cred_key,
                    cred_key,
                    FieldKind::default(),
                    SecretString::from("secret"),
                )
                .unwrap();
        }

        vault.add_or_update_item("other-item", "Other").unwrap();
        vault
            .add_or_update_item_credential(
                "other-item",
                "elsewhere",
                "Elsewhere",
                FieldKind::default(),
                SecretString::from("secret"),
            )
            .unwrap();
        vault
    }

    fn unsectioned(cred_keys: &[&str]) -> Vec<CredentialPlacement> {
        cred_keys
            .iter()
            .map(|k| CredentialPlacement {
                key: k.to_string(),
                section: None,
            })
            .collect()
    }

    fn positions(vault: &Vault, item_key: &str, cred_keys: &[&str]) -> Vec<Option<u32>> {
        cred_keys
            .iter()
            .map(|k| vault.get_item_credential(item_key, k).unwrap().position)
            .collect()
    }

    fn cred_metadata(title: &str, key: &str, kind: FieldKind) -> VaultCredentialMetadata {
        VaultCredentialMetadata {
            title: title.to_string(),
            key: key.to_string(),
            kind,
            position: None,
            section: None,
        }
    }

    /// Populate the metadata caches the way a load/save cycle would, so a
    /// change has to invalidate them to take effect.
    fn populate_caches(vault: &mut Vault) {
        let encrypted = vault.to_encrypted(true).unwrap();
        vault.metadata_blob = encrypted.metadata;
        for (item_id, item) in encrypted.items {
            vault.item_blobs.insert(item_id, item.metadata);
            for (cred_id, cred) in item.credentials {
                vault.cred_blobs.insert(cred_id, cred.metadata);
            }
        }
    }

    #[test]
    fn reorder_assigns_positions_in_the_given_order() {
        let keys = ["alpha", "beta", "gamma"];
        let mut vault = vault_with_credentials("item", &keys);
        assert_eq!(positions(&vault, "item", &keys), vec![None, None, None]);

        vault
            .reorder_item_credentials("item", &unsectioned(&["gamma", "alpha", "beta"]))
            .unwrap();

        assert_eq!(
            positions(&vault, "item", &keys),
            vec![Some(1), Some(2), Some(0)]
        );
    }

    #[test]
    fn reorder_invalidates_cached_metadata_so_positions_are_persisted() {
        let keys = ["alpha", "beta"];
        let mut vault = vault_with_credentials("item", &keys);
        populate_caches(&mut vault);

        vault
            .reorder_item_credentials("item", &unsectioned(&["beta", "alpha"]))
            .unwrap();

        let vault = reload(&vault);
        assert_eq!(positions(&vault, "item", &keys), vec![Some(1), Some(0)]);
    }

    #[test]
    fn reorder_rejects_a_partial_list() {
        let mut vault = vault_with_credentials("item", &["alpha", "beta", "gamma"]);
        let err = vault
            .reorder_item_credentials("item", &unsectioned(&["beta", "alpha"]))
            .unwrap_err();
        assert!(matches!(err, Error::InvalidCredentialOrder(_)));
        assert_eq!(
            positions(&vault, "item", &["alpha", "beta", "gamma"]),
            vec![None, None, None]
        );
    }

    #[test]
    fn reorder_rejects_a_duplicated_key() {
        let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
        let err = vault
            .reorder_item_credentials("item", &unsectioned(&["alpha", "alpha"]))
            .unwrap_err();
        assert!(matches!(err, Error::InvalidCredentialOrder(_)));
    }

    #[test]
    fn reorder_rejects_an_unknown_key() {
        let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
        let err = vault
            .reorder_item_credentials("item", &unsectioned(&["alpha", "nope"]))
            .unwrap_err();
        assert!(matches!(err, Error::InvalidCredentialKey(_)));
    }

    #[test]
    fn reorder_rejects_a_key_from_another_item() {
        let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
        let err = vault
            .reorder_item_credentials("item", &unsectioned(&["alpha", "elsewhere"]))
            .unwrap_err();
        assert!(matches!(err, Error::InvalidCredentialKey(_)));
    }

    #[test]
    fn reorder_rejects_an_unknown_item() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        let err = vault
            .reorder_item_credentials("nope", &unsectioned(&["alpha"]))
            .unwrap_err();
        assert!(matches!(err, Error::InvalidItemKey(_)));
    }

    #[test]
    fn reordered_positions_survive_a_save_and_load() {
        let keys = ["alpha", "beta", "gamma"];
        let mut vault = vault_with_credentials("item", &keys);
        vault
            .reorder_item_credentials("item", &unsectioned(&["gamma", "beta", "alpha"]))
            .unwrap();

        let vault = reload(&vault);
        assert_eq!(
            positions(&vault, "item", &keys),
            vec![Some(2), Some(1), Some(0)]
        );
    }

    #[test]
    fn updating_a_credential_kind_persists_through_a_save() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        assert_eq!(
            vault.get_item_credential("item", "alpha").unwrap().kind,
            FieldKind::default()
        );
        populate_caches(&mut vault);

        let new_kind = FieldKind::Text(TextField {
            multiline: Some(true),
        });
        vault
            .add_or_update_item_credential(
                "item",
                "alpha",
                "alpha",
                new_kind.clone(),
                SecretString::from("secret"),
            )
            .unwrap();
        assert_eq!(
            vault.get_item_credential("item", "alpha").unwrap().kind,
            new_kind
        );

        let vault = reload(&vault);
        assert_eq!(
            vault.get_item_credential("item", "alpha").unwrap().kind,
            new_kind
        );
    }

    #[test]
    fn default_kind_is_omitted_from_json() {
        let meta = cred_metadata("Password", "password", FieldKind::default());
        let json = serde_json::to_value(&meta).unwrap();
        assert!(json.get("kind").is_none());
    }

    #[test]
    fn legacy_metadata_without_kind_loads_as_default() {
        let meta: VaultCredentialMetadata =
            serde_json::from_str(r#"{"title":"Password","key":"password"}"#).unwrap();
        assert_eq!(meta.kind, FieldKind::default());
    }

    #[test]
    fn position_is_omitted_when_unset_and_roundtrips_when_set() {
        let meta = cred_metadata("Password", "password", FieldKind::default());
        let json = serde_json::to_value(&meta).unwrap();
        assert!(json.get("position").is_none());

        let mut meta = meta;
        meta.position = Some(2);
        let json = serde_json::to_value(&meta).unwrap();
        assert_eq!(json.get("position").and_then(|v| v.as_u64()), Some(2));
        let back: VaultCredentialMetadata = serde_json::from_value(json).unwrap();
        assert_eq!(back.position, Some(2));
    }

    #[test]
    fn legacy_metadata_without_position_loads_as_none() {
        let meta: VaultCredentialMetadata =
            serde_json::from_str(r#"{"title":"Password","key":"password"}"#).unwrap();
        assert_eq!(meta.position, None);
        assert_eq!(meta.section, None);
    }

    #[test]
    fn non_default_kind_roundtrips_through_metadata() {
        let meta = cred_metadata(
            "Notes",
            "notes",
            FieldKind::Text(TextField {
                multiline: Some(true),
            }),
        );
        let json = serde_json::to_value(&meta).unwrap();
        let back: VaultCredentialMetadata = serde_json::from_value(json).unwrap();
        assert_eq!(back.kind, meta.kind);
    }

    #[test]
    fn legacy_item_metadata_loads_unfiled_without_sections() {
        let meta: VaultItemMetadata =
            serde_json::from_str(r#"{"title":"Item","key":"item"}"#).unwrap();
        assert_eq!(meta.folder, None);
        assert!(meta.sections.is_empty());

        let json = serde_json::to_value(&meta).unwrap();
        assert!(json.get("folder").is_none());
        assert!(json.get("sections").is_none());
    }

    #[test]
    fn folders_and_filing_survive_a_save_and_load() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        let folder_id = vault.create_folder(" Work ").id;
        vault.move_item("item", Some(folder_id)).unwrap();

        let vault = reload(&vault);
        assert_eq!(vault.get_folder(folder_id).unwrap().title, "Work");
        assert_eq!(vault.get_item("item").unwrap().folder, Some(folder_id));
        assert_eq!(vault.get_item("other-item").unwrap().folder, None);
    }

    #[test]
    fn moving_an_item_invalidates_its_cached_metadata() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        let folder_id = vault.create_folder("Work").id;
        populate_caches(&mut vault);

        vault.move_item("item", Some(folder_id)).unwrap();
        let vault = reload(&vault);
        assert_eq!(vault.get_item("item").unwrap().folder, Some(folder_id));
    }

    #[test]
    fn moving_an_item_to_an_unknown_folder_fails() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        let err = vault.move_item("item", Some(Uuid::new_v4())).unwrap_err();
        assert!(matches!(err, Error::InvalidFolder(_)));
        assert_eq!(vault.get_item("item").unwrap().folder, None);
    }

    #[test]
    fn renaming_a_folder_persists() {
        let mut vault = test_vault();
        let folder_id = vault.create_folder("Work").id;
        populate_caches(&mut vault);

        vault.rename_folder(folder_id, "Personal").unwrap();
        let vault = reload(&vault);
        assert_eq!(vault.get_folder(folder_id).unwrap().title, "Personal");
    }

    #[test]
    fn deleting_a_folder_unfiles_its_items() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        let folder_id = vault.create_folder("Work").id;
        vault.move_item("item", Some(folder_id)).unwrap();
        populate_caches(&mut vault);

        vault.delete_folder(folder_id).unwrap();
        assert_eq!(vault.get_item("item").unwrap().folder, None);

        let vault = reload(&vault);
        assert!(vault.list_folders().is_empty());
        assert_eq!(vault.get_item("item").unwrap().folder, None);
        assert!(vault.get_item_credential("item", "alpha").is_ok());
    }

    #[test]
    fn an_item_in_a_missing_folder_loads_unfiled() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        let folder_id = vault.create_folder("Work").id;
        vault.move_item("item", Some(folder_id)).unwrap();

        let mut encrypted = vault.to_encrypted(true).unwrap();
        encrypted.metadata = None;
        let cipher = VaultCipher::new_with_bytes(&TEST_FILE_KEY, encrypted.id);
        let vault = Vault::from_encrypted_with_cipher(cipher, encrypted).unwrap();

        assert_eq!(vault.get_item("item").unwrap().folder, None);
        // The stale blob is not cached, so the next save writes the fix.
        assert!(
            !vault
                .item_blobs
                .contains_key(&vault.get_item("item").unwrap().id)
        );
    }

    #[test]
    fn reorder_folders_requires_every_folder_once() {
        let mut vault = test_vault();
        let a = vault.create_folder("A").id;
        let b = vault.create_folder("B").id;

        assert!(matches!(
            vault.reorder_folders(&[a]),
            Err(Error::InvalidFolderOrder)
        ));
        assert!(matches!(
            vault.reorder_folders(&[a, a]),
            Err(Error::InvalidFolderOrder)
        ));
        assert!(matches!(
            vault.reorder_folders(&[a, Uuid::new_v4()]),
            Err(Error::InvalidFolderOrder)
        ));

        vault.reorder_folders(&[b, a]).unwrap();
        let vault = reload(&vault);
        assert_eq!(vault.get_folder(b).unwrap().position, Some(0));
        assert_eq!(vault.get_folder(a).unwrap().position, Some(1));
    }

    #[test]
    fn sections_and_placement_survive_a_save_and_load() {
        let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
        let section_id = vault.create_item_section("item", "Login").unwrap().id;
        vault
            .move_item_credential("item", "beta", Some(section_id))
            .unwrap();

        let vault = reload(&vault);
        let item = vault.get_item("item").unwrap();
        assert_eq!(item.sections.get(&section_id).unwrap().title, "Login");
        assert_eq!(
            vault.get_item_credential("item", "beta").unwrap().section,
            Some(section_id)
        );
        assert_eq!(
            vault.get_item_credential("item", "alpha").unwrap().section,
            None
        );
    }

    #[test]
    fn moving_a_credential_to_another_items_section_fails() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        let other_section = vault.create_item_section("other-item", "S").unwrap().id;
        let err = vault
            .move_item_credential("item", "alpha", Some(other_section))
            .unwrap_err();
        assert!(matches!(err, Error::InvalidSection(_)));
    }

    #[test]
    fn deleting_a_section_keeps_its_credentials() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        let section_id = vault.create_item_section("item", "Login").unwrap().id;
        vault
            .move_item_credential("item", "alpha", Some(section_id))
            .unwrap();
        populate_caches(&mut vault);

        vault.delete_item_section("item", section_id).unwrap();

        let vault = reload(&vault);
        assert!(vault.get_item("item").unwrap().sections.is_empty());
        assert_eq!(
            vault.get_item_credential("item", "alpha").unwrap().section,
            None
        );
    }

    #[test]
    fn updating_a_credential_keeps_its_value_and_persists() {
        let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
        populate_caches(&mut vault);

        let new_kind = FieldKind::Text(TextField {
            multiline: Some(true),
        });
        vault
            .update_item_credential(
                "item",
                "alpha",
                CredentialUpdate {
                    key: Some("renamed".to_string()),
                    title: Some(" Renamed ".to_string()),
                    kind: Some(new_kind.clone()),
                },
            )
            .unwrap();

        let vault = reload(&vault);
        assert!(matches!(
            vault.get_item_credential("item", "alpha"),
            Err(Error::InvalidCredentialKey(_))
        ));
        let cred = vault.get_item_credential("item", "renamed").unwrap();
        assert_eq!(cred.title, "Renamed");
        assert_eq!(cred.kind, new_kind);
        let secret = vault
            .get_item_credential_secret("item", "renamed")
            .unwrap()
            .unwrap();
        assert_eq!(secret.expose_secret(), "secret");
    }

    #[test]
    fn adding_a_credential_with_a_taken_key_fails() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        let err = vault
            .add_item_credential(
                "item",
                "alpha",
                "Title",
                FieldKind::default(),
                SecretString::from("other".to_string()),
            )
            .unwrap_err();
        assert!(matches!(err, Error::DuplicateCredentialKey(_)));
        let secret = vault
            .get_item_credential_secret("item", "alpha")
            .unwrap()
            .unwrap();
        assert_ne!(secret.expose_secret(), "other");
        vault
            .add_item_credential(
                "item",
                "gamma",
                "Title",
                FieldKind::default(),
                SecretString::from("new".to_string()),
            )
            .unwrap();
    }

    #[test]
    fn updating_a_credential_to_a_taken_key_fails() {
        let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
        let err = vault
            .update_item_credential(
                "item",
                "alpha",
                CredentialUpdate {
                    key: Some("beta".to_string()),
                    ..Default::default()
                },
            )
            .unwrap_err();
        assert!(matches!(err, Error::DuplicateCredentialKey(_)));
        // The same key is not a conflict with itself.
        vault
            .update_item_credential(
                "item",
                "alpha",
                CredentialUpdate {
                    key: Some("alpha".to_string()),
                    ..Default::default()
                },
            )
            .unwrap();
    }

    #[test]
    fn renaming_and_reordering_sections_persists() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        let a = vault.create_item_section("item", "A").unwrap().id;
        let b = vault.create_item_section("item", "B").unwrap().id;
        populate_caches(&mut vault);

        vault.rename_item_section("item", a, "Renamed").unwrap();
        assert!(matches!(
            vault.reorder_item_sections("item", &[b]),
            Err(Error::InvalidSectionOrder(_))
        ));
        vault.reorder_item_sections("item", &[b, a]).unwrap();

        let vault = reload(&vault);
        let sections = &vault.get_item("item").unwrap().sections;
        assert_eq!(sections.get(&a).unwrap().title, "Renamed");
        assert_eq!(sections.get(&a).unwrap().position, Some(1));
        assert_eq!(sections.get(&b).unwrap().position, Some(0));
    }

    #[test]
    fn new_sections_go_last_regardless_of_title() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        let a = vault.create_item_section("item", "zeta").unwrap().id;
        let b = vault.create_item_section("item", "Alpha").unwrap().id;
        // Without a position this section would sort first by title.
        let mut legacy = VaultItemSection::new("beta");
        legacy.position = None;
        let legacy_id = legacy.id;
        vault
            .edit_item("item", |item| {
                item.sections.insert(legacy_id, legacy);
                Ok(())
            })
            .unwrap();
        let c = vault.create_item_section("item", "Another").unwrap().id;

        let sections = &vault.get_item("item").unwrap().sections;
        let position = |id: Uuid| sections.get(&id).unwrap().position;
        assert_eq!(
            [position(a), position(b), position(legacy_id), position(c)],
            [Some(0), Some(1), Some(2), Some(3)]
        );
    }

    #[test]
    fn reorder_sets_sections_and_positions() {
        let keys = ["alpha", "beta", "gamma"];
        let mut vault = vault_with_credentials("item", &keys);
        let section_id = vault.create_item_section("item", "Login").unwrap().id;

        let placements = vec![
            CredentialPlacement {
                key: "gamma".to_string(),
                section: None,
            },
            CredentialPlacement {
                key: "alpha".to_string(),
                section: Some(section_id),
            },
            CredentialPlacement {
                key: "beta".to_string(),
                section: Some(section_id),
            },
        ];
        vault.reorder_item_credentials("item", &placements).unwrap();

        let vault = reload(&vault);
        assert_eq!(
            positions(&vault, "item", &keys),
            vec![Some(1), Some(2), Some(0)]
        );
        let sections: Vec<Option<Uuid>> = keys
            .iter()
            .map(|k| vault.get_item_credential("item", k).unwrap().section)
            .collect();
        assert_eq!(sections, vec![Some(section_id), Some(section_id), None]);
    }

    #[test]
    fn reorder_rejects_an_unknown_section_without_changes() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        let placements = vec![CredentialPlacement {
            key: "alpha".to_string(),
            section: Some(Uuid::new_v4()),
        }];
        let err = vault
            .reorder_item_credentials("item", &placements)
            .unwrap_err();
        assert!(matches!(err, Error::InvalidSection(_)));
        assert_eq!(positions(&vault, "item", &["alpha"]), vec![None]);
    }

    #[test]
    fn a_credential_in_a_missing_section_loads_unsectioned() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        let section_id = vault.create_item_section("item", "Login").unwrap().id;
        vault
            .move_item_credential("item", "alpha", Some(section_id))
            .unwrap();
        // Drop the section from the item without touching the credential, as
        // a stale or hand-edited file could.
        vault
            .items
            .values_mut()
            .for_each(|item| item.sections.clear());

        let vault = reload(&vault);
        assert_eq!(
            vault.get_item_credential("item", "alpha").unwrap().section,
            None
        );
    }

    #[test]
    fn deleting_an_item_drops_its_cached_credential_metadata() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        populate_caches(&mut vault);
        let cred_id = vault.get_item_credential("item", "alpha").unwrap().id;

        vault.delete_item("item").unwrap();
        assert!(!vault.cred_blobs.contains_key(&cred_id));
    }

    fn deleted_ids(vault: &Vault, item_key: &str) -> Vec<Uuid> {
        vault
            .list_deleted(item_key)
            .unwrap()
            .iter()
            .map(|t| t.credential.id)
            .collect()
    }

    fn secret_of(vault: &Vault, item_key: &str, cred_key: &str) -> String {
        vault
            .get_item_credential_secret(item_key, cred_key)
            .unwrap()
            .unwrap()
            .expose_secret()
            .clone()
    }

    #[test]
    fn deleted_credentials_survive_a_save_and_load_as_deleted() {
        let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
        populate_caches(&mut vault);
        let cred_id = vault.get_item_credential("item", "alpha").unwrap().id;

        vault.delete_item_credential("item", "alpha").unwrap();
        assert!(vault.get_item_credential("item", "alpha").is_err());
        assert_eq!(deleted_ids(&vault, "item"), vec![cred_id]);

        let vault = reload(&vault);
        assert!(vault.get_item_credential("item", "alpha").is_err());
        assert!(vault.get_item_credential("item", "beta").is_ok());
        let deleted = vault.list_deleted("item").unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].credential.id, cred_id);
        assert_eq!(deleted[0].credential.key, "alpha");
        assert!(deleted[0].deleted_at > 0);
        assert!(vault.list_deleted("other-item").unwrap().is_empty());
    }

    #[test]
    fn deleting_a_credential_frees_its_key() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        vault.delete_item_credential("item", "alpha").unwrap();
        vault
            .add_item_credential(
                "item",
                "alpha",
                "New",
                FieldKind::default(),
                SecretString::from("new".to_string()),
            )
            .unwrap();
        assert_eq!(secret_of(&vault, "item", "alpha"), "new");
        assert_eq!(deleted_ids(&vault, "item").len(), 1);
    }

    #[test]
    fn restoring_keeps_id_value_position_and_section() {
        let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
        let section_id = vault.create_item_section("item", "Login").unwrap().id;
        let placements = vec![
            CredentialPlacement {
                key: "beta".to_string(),
                section: None,
            },
            CredentialPlacement {
                key: "alpha".to_string(),
                section: Some(section_id),
            },
        ];
        vault.reorder_item_credentials("item", &placements).unwrap();
        populate_caches(&mut vault);
        let cred_id = vault.get_item_credential("item", "alpha").unwrap().id;

        vault.delete_item_credential("item", "alpha").unwrap();
        let mut vault = reload(&vault);
        vault
            .restore_item_credential("item", cred_id, None)
            .unwrap();
        assert!(deleted_ids(&vault, "item").is_empty());

        let vault = reload(&vault);
        let cred = vault.get_item_credential("item", "alpha").unwrap();
        assert_eq!(cred.id, cred_id);
        assert_eq!(cred.position, Some(1));
        assert_eq!(cred.section, Some(section_id));
        assert_eq!(secret_of(&vault, "item", "alpha"), "secret");
    }

    #[test]
    fn restoring_into_a_deleted_section_drops_the_section() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        let section_id = vault.create_item_section("item", "Login").unwrap().id;
        vault
            .move_item_credential("item", "alpha", Some(section_id))
            .unwrap();
        populate_caches(&mut vault);
        let cred_id = vault.get_item_credential("item", "alpha").unwrap().id;

        vault.delete_item_credential("item", "alpha").unwrap();
        vault.delete_item_section("item", section_id).unwrap();
        vault
            .restore_item_credential("item", cred_id, None)
            .unwrap();

        let vault = reload(&vault);
        assert_eq!(
            vault.get_item_credential("item", "alpha").unwrap().section,
            None
        );
    }

    #[test]
    fn restoring_with_a_taken_key_fails_unless_a_new_key_is_given() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        populate_caches(&mut vault);
        let cred_id = vault.get_item_credential("item", "alpha").unwrap().id;
        vault.delete_item_credential("item", "alpha").unwrap();
        vault
            .add_item_credential(
                "item",
                "alpha",
                "New",
                FieldKind::default(),
                SecretString::from("new".to_string()),
            )
            .unwrap();

        let err = vault
            .restore_item_credential("item", cred_id, None)
            .unwrap_err();
        assert!(matches!(err, Error::DuplicateCredentialKey(_)));
        let err = vault
            .restore_item_credential("item", cred_id, Some("alpha".to_string()))
            .unwrap_err();
        assert!(matches!(err, Error::DuplicateCredentialKey(_)));
        // A failed restore leaves the credential deleted.
        assert_eq!(deleted_ids(&vault, "item"), vec![cred_id]);

        vault
            .restore_item_credential("item", cred_id, Some("alpha-old".to_string()))
            .unwrap();
        let vault = reload(&vault);
        assert_eq!(secret_of(&vault, "item", "alpha-old"), "secret");
        assert_eq!(secret_of(&vault, "item", "alpha"), "new");
        assert_eq!(
            vault.get_item_credential("item", "alpha-old").unwrap().id,
            cred_id
        );
    }

    #[test]
    fn restoring_with_an_invalid_new_key_fails() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        let cred_id = vault.get_item_credential("item", "alpha").unwrap().id;
        vault.delete_item_credential("item", "alpha").unwrap();
        let err = vault
            .restore_item_credential("item", cred_id, Some("  ".to_string()))
            .unwrap_err();
        assert!(matches!(err, Error::InvalidCredentialKey(_)));
        assert_eq!(deleted_ids(&vault, "item"), vec![cred_id]);
    }

    #[test]
    fn restoring_through_another_item_fails() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        let cred_id = vault.get_item_credential("item", "alpha").unwrap().id;
        vault.delete_item_credential("item", "alpha").unwrap();
        let err = vault
            .restore_item_credential("other-item", cred_id, None)
            .unwrap_err();
        assert!(matches!(err, Error::InvalidCredentialKey(_)));
        let err = vault
            .purge_item_credential("other-item", cred_id)
            .unwrap_err();
        assert!(matches!(err, Error::InvalidCredentialKey(_)));
        assert_eq!(deleted_ids(&vault, "item"), vec![cred_id]);
    }

    #[test]
    fn purging_removes_a_deleted_credential_for_good() {
        let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
        let alpha = vault.get_item_credential("item", "alpha").unwrap().id;
        vault.delete_item_credential("item", "alpha").unwrap();
        vault.delete_item_credential("item", "beta").unwrap();

        vault.purge_item_credential("item", alpha).unwrap();
        assert!(matches!(
            vault.restore_item_credential("item", alpha, None),
            Err(Error::InvalidCredentialKey(_))
        ));

        let vault = reload(&vault);
        assert_eq!(vault.list_deleted("item").unwrap().len(), 1);
        assert_eq!(
            vault.list_deleted("item").unwrap()[0].credential.key,
            "beta"
        );
    }

    #[test]
    fn purge_deleted_removes_entries_older_than_the_cutoff() {
        let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
        vault.delete_item_credential("item", "alpha").unwrap();
        vault.delete_item_credential("item", "beta").unwrap();
        let now = OffsetDateTime::now_utc().unix_timestamp();

        assert_eq!(vault.purge_deleted(0), 0);
        assert_eq!(vault.list_deleted("item").unwrap().len(), 2);
        assert_eq!(vault.purge_deleted(now + 10), 2);
        assert!(vault.list_deleted("item").unwrap().is_empty());
    }

    fn item_id_of(vault: &Vault, item_key: &str) -> Uuid {
        *vault.get_item_id(item_key).unwrap()
    }

    #[test]
    fn a_deleted_item_survives_a_save_and_load_and_frees_its_key() {
        let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
        populate_caches(&mut vault);
        let item_id = item_id_of(&vault, "item");

        vault.delete_item("item").unwrap();
        assert!(vault.get_item("item").is_err());
        assert!(vault.get_item_credential("item", "alpha").is_err());
        assert!(vault.get_item("other-item").is_ok());

        let mut vault = reload(&vault);
        assert!(vault.get_item("item").is_err());
        let deleted = vault.list_deleted_items();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].item.id, item_id);
        assert_eq!(deleted[0].item.key, "item");
        assert_eq!(deleted[0].item.credentials.len(), 2);
        assert!(deleted[0].deleted_at > 0);

        // The key can be used by a new item.
        vault.add_or_update_item("item", "New").unwrap();
        assert_ne!(item_id_of(&vault, "item"), item_id);
    }

    #[test]
    fn restoring_an_item_brings_back_credentials_values_and_layout() {
        let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
        let folder_id = vault.create_folder("Work").id;
        vault.move_item("item", Some(folder_id)).unwrap();
        let section_id = vault.create_item_section("item", "Login").unwrap().id;
        vault
            .move_item_credential("item", "beta", Some(section_id))
            .unwrap();
        let alpha_id = vault.get_item_credential("item", "alpha").unwrap().id;
        populate_caches(&mut vault);
        let item_id = item_id_of(&vault, "item");

        vault.delete_item("item").unwrap();
        let mut vault = reload(&vault);
        vault.restore_item(item_id, None).unwrap();
        assert!(vault.list_deleted_items().is_empty());

        let vault = reload(&vault);
        let item = vault.get_item("item").unwrap();
        assert_eq!(item.id, item_id);
        assert_eq!(item.folder, Some(folder_id));
        assert_eq!(item.sections.get(&section_id).unwrap().title, "Login");
        assert_eq!(
            vault.get_item_credential("item", "alpha").unwrap().id,
            alpha_id
        );
        assert_eq!(
            vault.get_item_credential("item", "beta").unwrap().section,
            Some(section_id)
        );
        assert_eq!(secret_of(&vault, "item", "alpha"), "secret");
        assert_eq!(secret_of(&vault, "item", "beta"), "secret");
    }

    #[test]
    fn a_deleted_item_keeps_its_own_deleted_credentials() {
        let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
        populate_caches(&mut vault);
        let alpha_id = vault.get_item_credential("item", "alpha").unwrap().id;
        let item_id = item_id_of(&vault, "item");
        vault.delete_item_credential("item", "alpha").unwrap();

        vault.delete_item("item").unwrap();
        assert!(vault.deleted.is_empty());
        assert_eq!(vault.list_deleted_items()[0].deleted_credentials.len(), 1);

        let mut vault = reload(&vault);
        vault.restore_item(item_id, None).unwrap();
        assert_eq!(deleted_ids(&vault, "item"), vec![alpha_id]);
        assert!(vault.get_item_credential("item", "beta").is_ok());

        vault
            .restore_item_credential("item", alpha_id, None)
            .unwrap();
        let vault = reload(&vault);
        assert_eq!(secret_of(&vault, "item", "alpha"), "secret");
    }

    #[test]
    fn restoring_an_item_with_a_taken_key_fails_unless_a_new_key_is_given() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        let item_id = item_id_of(&vault, "item");
        vault.delete_item("item").unwrap();
        vault.add_or_update_item("item", "New").unwrap();

        let err = vault.restore_item(item_id, None).unwrap_err();
        assert!(matches!(err, Error::DuplicateItemKey(_)));
        let err = vault
            .restore_item(item_id, Some("item".to_string()))
            .unwrap_err();
        assert!(matches!(err, Error::DuplicateItemKey(_)));
        let err = vault
            .restore_item(item_id, Some("  ".to_string()))
            .unwrap_err();
        assert!(matches!(err, Error::InvalidItemKey(_)));
        // A failed restore leaves the item deleted.
        assert_eq!(vault.list_deleted_items().len(), 1);

        vault
            .restore_item(item_id, Some("item-old".to_string()))
            .unwrap();
        let vault = reload(&vault);
        assert_eq!(vault.get_item("item-old").unwrap().id, item_id);
        assert_eq!(secret_of(&vault, "item-old", "alpha"), "secret");
        assert_ne!(item_id_of(&vault, "item"), item_id);
    }

    #[test]
    fn restoring_an_item_into_a_deleted_folder_unfiles_it() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        let folder_id = vault.create_folder("Work").id;
        vault.move_item("item", Some(folder_id)).unwrap();
        populate_caches(&mut vault);
        let item_id = item_id_of(&vault, "item");

        vault.delete_item("item").unwrap();
        vault.delete_folder(folder_id).unwrap();
        vault.restore_item(item_id, None).unwrap();

        let vault = reload(&vault);
        assert_eq!(vault.get_item("item").unwrap().folder, None);
    }

    fn deleted_secret_of(vault: &Vault, item_id: Uuid, cred_id: Uuid) -> String {
        vault
            .get_deleted_credential_secret(item_id, cred_id)
            .unwrap()
            .expose_secret()
            .clone()
    }

    #[test]
    fn list_all_deleted_lists_credentials_of_live_items_with_their_item() {
        let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
        let alpha_id = vault.get_item_credential("item", "alpha").unwrap().id;
        let elsewhere_id = vault
            .get_item_credential("other-item", "elsewhere")
            .unwrap()
            .id;
        vault.delete_item_credential("item", "alpha").unwrap();
        vault
            .delete_item_credential("other-item", "elsewhere")
            .unwrap();

        let vault = reload(&vault);
        let all = vault.list_all_deleted();
        let mut found: Vec<(Uuid, &str)> = all
            .iter()
            .map(|e| (e.credential.credential.id, e.item.key.as_str()))
            .collect();
        found.sort();
        let mut expected = vec![(alpha_id, "item"), (elsewhere_id, "other-item")];
        expected.sort();
        assert_eq!(found, expected);
    }

    #[test]
    fn list_all_deleted_leaves_out_credentials_of_deleted_items() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        vault.delete_item_credential("item", "alpha").unwrap();
        vault.delete_item("item").unwrap();
        assert!(vault.list_all_deleted().is_empty());
    }

    #[test]
    fn deleted_secrets_can_be_read_in_every_deleted_location() {
        let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
        let item_id = item_id_of(&vault, "item");
        let alpha_id = vault.get_item_credential("item", "alpha").unwrap().id;
        let beta_id = vault.get_item_credential("item", "beta").unwrap().id;
        let other_item_id = item_id_of(&vault, "other-item");

        // Deleted from a live item.
        vault.delete_item_credential("item", "alpha").unwrap();
        let vault = reload(&vault);
        assert_eq!(deleted_secret_of(&vault, item_id, alpha_id), "secret");

        // In a deleted item, and deleted before the item.
        let mut vault = vault;
        vault.delete_item("item").unwrap();
        let vault = reload(&vault);
        assert_eq!(deleted_secret_of(&vault, item_id, alpha_id), "secret");
        assert_eq!(deleted_secret_of(&vault, item_id, beta_id), "secret");

        // A credential id is only valid with its own item.
        assert!(matches!(
            vault.get_deleted_credential_secret(other_item_id, alpha_id),
            Err(Error::InvalidCredentialKey(_))
        ));
        assert!(matches!(
            vault.get_deleted_credential_secret(item_id, Uuid::new_v4()),
            Err(Error::InvalidCredentialKey(_))
        ));
    }

    #[test]
    fn a_live_credential_has_no_deleted_secret() {
        let vault = vault_with_credentials("item", &["alpha"]);
        let item_id = item_id_of(&vault, "item");
        let alpha_id = vault.get_item_credential("item", "alpha").unwrap().id;
        assert!(matches!(
            vault.get_deleted_credential_secret(item_id, alpha_id),
            Err(Error::InvalidCredentialKey(_))
        ));
    }

    fn set_value(vault: &mut Vault, item_key: &str, cred_key: &str, value: &str) {
        vault
            .add_or_update_item_credential(
                item_key,
                cred_key,
                cred_key,
                FieldKind::default(),
                SecretString::from(value.to_string()),
            )
            .unwrap();
    }

    fn history_values(vault: &Vault, item_key: &str, cred_key: &str) -> Vec<String> {
        vault
            .list_history(item_key, cred_key)
            .unwrap()
            .iter()
            .map(|h| {
                vault
                    .get_history_value(item_key, cred_key, h.id)
                    .unwrap()
                    .expose_secret()
                    .clone()
            })
            .collect()
    }

    #[test]
    fn changing_a_value_keeps_the_old_value_in_the_history() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        assert!(vault.list_history("item", "alpha").unwrap().is_empty());

        set_value(&mut vault, "item", "alpha", "second");
        set_value(&mut vault, "item", "alpha", "third");

        assert_eq!(secret_of(&vault, "item", "alpha"), "third");
        // Most recently replaced first.
        assert_eq!(
            history_values(&vault, "item", "alpha"),
            vec!["second", "secret"]
        );
        assert!(
            vault
                .list_history("item", "alpha")
                .unwrap()
                .iter()
                .all(|h| h.replaced_at > 0)
        );
    }

    #[test]
    fn saving_the_same_or_a_first_or_an_empty_value_adds_no_history() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        set_value(&mut vault, "item", "alpha", "secret");
        assert!(vault.list_history("item", "alpha").unwrap().is_empty());

        // A credential created with no value yet, then given one.
        vault
            .add_item_credential(
                "item",
                "empty",
                "Empty",
                FieldKind::default(),
                SecretString::from(String::new()),
            )
            .unwrap();
        set_value(&mut vault, "item", "empty", "first");
        assert!(vault.list_history("item", "empty").unwrap().is_empty());
        set_value(&mut vault, "item", "empty", "second");
        assert_eq!(history_values(&vault, "item", "empty"), vec!["first"]);
    }

    #[test]
    fn history_survives_a_save_and_load() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        set_value(&mut vault, "item", "alpha", "second");
        set_value(&mut vault, "item", "alpha", "third");

        let vault = reload(&vault);
        assert_eq!(secret_of(&vault, "item", "alpha"), "third");
        assert_eq!(
            history_values(&vault, "item", "alpha"),
            vec!["second", "secret"]
        );
    }

    #[test]
    fn restoring_a_previous_value_swaps_it_with_the_current_value() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        set_value(&mut vault, "item", "alpha", "second");
        let first = vault.list_history("item", "alpha").unwrap()[0].id;

        vault.restore_history_value("item", "alpha", first).unwrap();

        assert_eq!(secret_of(&vault, "item", "alpha"), "secret");
        assert_eq!(history_values(&vault, "item", "alpha"), vec!["second"]);
        let vault = reload(&vault);
        assert_eq!(secret_of(&vault, "item", "alpha"), "secret");
        assert_eq!(history_values(&vault, "item", "alpha"), vec!["second"]);
    }

    #[test]
    fn restoring_the_only_previous_value_over_an_empty_value_clears_the_history() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        set_value(&mut vault, "item", "alpha", "");
        let first = vault.list_history("item", "alpha").unwrap()[0].id;

        vault.restore_history_value("item", "alpha", first).unwrap();

        assert_eq!(secret_of(&vault, "item", "alpha"), "secret");
        assert!(vault.history.is_empty());
    }

    #[test]
    fn listing_history_skips_an_entry_that_fails_to_decrypt() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        set_value(&mut vault, "item", "alpha", "second");
        set_value(&mut vault, "item", "alpha", "third");
        let item_id = item_id_of(&vault, "item");
        let cred_id = vault.get_item_credential("item", "alpha").unwrap().id;

        let mut encrypted = vault.to_encrypted(true).unwrap();
        let cred = encrypted
            .items
            .get_mut(&item_id)
            .unwrap()
            .credentials
            .get_mut(&cred_id)
            .unwrap();
        let first_info = cred.history[0].info.clone();
        cred.history[1].info = first_info;
        let cipher = VaultCipher::new_with_bytes(&TEST_FILE_KEY, encrypted.id);
        let vault = Vault::from_encrypted_with_cipher(cipher, encrypted).unwrap();

        assert_eq!(history_values(&vault, "item", "alpha"), vec!["secret"]);
    }

    #[test]
    fn restoring_an_unknown_previous_value_fails() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        set_value(&mut vault, "item", "alpha", "second");
        assert!(matches!(
            vault.restore_history_value("item", "alpha", Uuid::new_v4()),
            Err(Error::InvalidHistoryEntry(_))
        ));
        assert!(matches!(
            vault.get_history_value("item", "alpha", Uuid::new_v4()),
            Err(Error::InvalidHistoryEntry(_))
        ));
        assert!(matches!(
            vault.purge_history("item", "alpha", Uuid::new_v4()),
            Err(Error::InvalidHistoryEntry(_))
        ));
        assert_eq!(secret_of(&vault, "item", "alpha"), "second");
    }

    #[test]
    fn purging_a_previous_value_removes_it_for_good() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        set_value(&mut vault, "item", "alpha", "second");
        set_value(&mut vault, "item", "alpha", "third");
        let newest = vault.list_history("item", "alpha").unwrap()[0].id;

        vault.purge_history("item", "alpha", newest).unwrap();
        assert_eq!(history_values(&vault, "item", "alpha"), vec!["secret"]);

        let vault = reload(&vault);
        assert_eq!(history_values(&vault, "item", "alpha"), vec!["secret"]);
        assert_eq!(secret_of(&vault, "item", "alpha"), "third");
    }

    #[test]
    fn history_follows_a_credential_through_delete_and_restore() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        set_value(&mut vault, "item", "alpha", "second");
        let cred_id = vault.get_item_credential("item", "alpha").unwrap().id;

        vault.delete_item_credential("item", "alpha").unwrap();
        assert!(vault.history.is_empty());

        let mut vault = reload(&vault);
        vault
            .restore_item_credential("item", cred_id, None)
            .unwrap();
        assert_eq!(history_values(&vault, "item", "alpha"), vec!["secret"]);
        assert_eq!(secret_of(&vault, "item", "alpha"), "second");
    }

    #[test]
    fn history_follows_a_credential_through_item_delete_and_restore() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        set_value(&mut vault, "item", "alpha", "second");
        let item_id = item_id_of(&vault, "item");

        vault.delete_item("item").unwrap();
        assert!(vault.history.is_empty());

        let mut vault = reload(&vault);
        vault.restore_item(item_id, None).unwrap();
        assert_eq!(history_values(&vault, "item", "alpha"), vec!["secret"]);

        let vault = reload(&vault);
        assert_eq!(history_values(&vault, "item", "alpha"), vec!["secret"]);
        assert_eq!(secret_of(&vault, "item", "alpha"), "second");
    }

    #[test]
    fn history_is_exported_and_omitted_from_the_file_when_empty() {
        let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
        set_value(&mut vault, "item", "alpha", "second");

        let json = serde_json::to_value(vault.to_encrypted(false).unwrap()).unwrap();
        let creds = json["items"]
            .as_object()
            .unwrap()
            .values()
            .flat_map(|item| item["credentials"].as_object().unwrap().values())
            .collect::<Vec<_>>();
        assert_eq!(
            creds.iter().filter(|c| c.get("history").is_some()).count(),
            1
        );
    }

    #[test]
    fn a_previous_value_cannot_be_swapped_into_another_place() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        set_value(&mut vault, "item", "alpha", "second");
        set_value(&mut vault, "item", "alpha", "third");
        let item_id = item_id_of(&vault, "item");
        let cred_id = vault.get_item_credential("item", "alpha").unwrap().id;

        let load = |encrypted: EncryptedVault| {
            let cipher = VaultCipher::new_with_bytes(&TEST_FILE_KEY, encrypted.id);
            Vault::from_encrypted_with_cipher(cipher, encrypted).unwrap()
        };

        // A history value in the live value's place.
        let mut encrypted = vault.to_encrypted(true).unwrap();
        let cred = encrypted
            .items
            .get_mut(&item_id)
            .unwrap()
            .credentials
            .get_mut(&cred_id)
            .unwrap();
        cred.value = cred.history[0].value.clone();
        let swapped = load(encrypted);
        assert!(swapped.get_item_credential_secret("item", "alpha").is_err());

        // A history value in another history entry's place.
        let mut encrypted = vault.to_encrypted(true).unwrap();
        let cred = encrypted
            .items
            .get_mut(&item_id)
            .unwrap()
            .credentials
            .get_mut(&cred_id)
            .unwrap();
        let first_value = cred.history[0].value.clone();
        cred.history[1].value = first_value;
        let swapped = load(encrypted);
        let ids: Vec<Uuid> = swapped
            .list_history("item", "alpha")
            .unwrap()
            .iter()
            .map(|h| h.id)
            .collect();
        let decrypted: Vec<bool> = ids
            .iter()
            .map(|id| swapped.get_history_value("item", "alpha", *id).is_ok())
            .collect();
        // Only the entry that kept its own value decrypts.
        assert_eq!(decrypted.iter().filter(|ok| **ok).count(), 1);
    }

    #[test]
    fn purging_an_item_removes_it_and_its_deleted_credentials() {
        let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
        vault.delete_item_credential("item", "alpha").unwrap();
        let item_id = item_id_of(&vault, "item");
        vault.delete_item("item").unwrap();

        vault.purge_item(item_id).unwrap();
        assert!(matches!(
            vault.restore_item(item_id, None),
            Err(Error::DeletedItemNotFound(_))
        ));
        assert!(matches!(
            vault.purge_item(item_id),
            Err(Error::DeletedItemNotFound(_))
        ));

        let encrypted = vault.to_encrypted(true).unwrap();
        assert!(encrypted.deleted.is_empty());
        assert!(vault.deleted.is_empty());
    }

    #[test]
    fn purge_deleted_includes_deleted_credentials_of_deleted_items() {
        let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
        vault.delete_item_credential("item", "alpha").unwrap();
        vault
            .delete_item_credential("other-item", "elsewhere")
            .unwrap();
        let item_id = item_id_of(&vault, "item");
        vault.delete_item("item").unwrap();
        let now = OffsetDateTime::now_utc().unix_timestamp();

        assert_eq!(vault.purge_deleted(now + 10), 2);
        assert!(vault.deleted.is_empty());
        assert_eq!(vault.list_deleted_items()[0].deleted_credentials.len(), 0);

        // The deleted item itself is kept.
        vault.restore_item(item_id, None).unwrap();
        assert!(vault.list_deleted("item").unwrap().is_empty());
        assert!(vault.get_item_credential("item", "beta").is_ok());
    }

    #[test]
    fn purge_deleted_items_removes_entries_older_than_the_cutoff() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        vault.delete_item("item").unwrap();
        vault.delete_item("other-item").unwrap();
        let now = OffsetDateTime::now_utc().unix_timestamp();

        assert_eq!(vault.purge_deleted_items(0), 0);
        assert_eq!(vault.list_deleted_items().len(), 2);
        assert_eq!(vault.purge_deleted_items(now + 10), 2);
        assert!(vault.list_deleted_items().is_empty());
    }

    #[test]
    fn bundled_export_leaves_out_deleted_items() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        vault.delete_item("item").unwrap();

        assert_eq!(vault.to_encrypted(true).unwrap().deleted.len(), 1);
        let without = vault.to_encrypted(false).unwrap();
        assert!(without.deleted.is_empty());
        assert_eq!(without.items.len(), 1);
    }

    #[test]
    fn a_vault_file_without_a_deleted_field_loads_with_no_deleted_items() {
        let vault = vault_with_credentials("item", &["alpha"]);
        let json = serde_json::to_value(vault.to_encrypted(true).unwrap()).unwrap();
        assert!(json.get("deleted").is_none());

        let encrypted: EncryptedVault = serde_json::from_value(json).unwrap();
        let cipher = VaultCipher::new_with_bytes(&TEST_FILE_KEY, encrypted.id);
        let vault = Vault::from_encrypted_with_cipher(cipher, encrypted).unwrap();
        assert!(vault.list_deleted_items().is_empty());
    }

    #[test]
    fn deleted_item_info_is_bound_to_its_item() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        vault.delete_item("item").unwrap();
        vault.delete_item("other-item").unwrap();

        // Swap the info blobs of the two deleted items.
        let mut encrypted = vault.to_encrypted(true).unwrap();
        let mut entries = encrypted.deleted.values_mut();
        let (first, second) = (entries.next().unwrap(), entries.next().unwrap());
        std::mem::swap(&mut first.info, &mut second.info);

        let cipher = VaultCipher::new_with_bytes(&TEST_FILE_KEY, encrypted.id);
        assert!(Vault::from_encrypted_with_cipher(cipher, encrypted).is_err());
    }

    #[test]
    fn bundled_export_leaves_out_the_deleted() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        vault.delete_item_credential("item", "alpha").unwrap();

        let with_deleted = vault.to_encrypted(true).unwrap();
        assert!(
            with_deleted
                .items
                .values()
                .any(|item| !item.deleted.is_empty())
        );
        let without_deleted = vault.to_encrypted(false).unwrap();
        assert!(
            without_deleted
                .items
                .values()
                .all(|item| item.deleted.is_empty())
        );
    }

    #[test]
    fn a_vault_file_without_a_deleted_field_loads_with_an_empty_deleted() {
        let vault = vault_with_credentials("item", &["alpha"]);
        let json = serde_json::to_value(vault.to_encrypted(true).unwrap()).unwrap();
        for item in json["items"].as_object().unwrap().values() {
            assert!(item.get("deleted").is_none());
        }

        let encrypted: EncryptedVault = serde_json::from_value(json).unwrap();
        let cipher = VaultCipher::new_with_bytes(&TEST_FILE_KEY, encrypted.id);
        let vault = Vault::from_encrypted_with_cipher(cipher, encrypted).unwrap();
        assert!(vault.deleted.is_empty());
        assert!(vault.get_item_credential("item", "alpha").is_ok());
    }

    #[test]
    fn deleted_info_is_bound_to_its_credential() {
        let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
        vault.delete_item_credential("item", "alpha").unwrap();
        vault.delete_item_credential("item", "beta").unwrap();

        // Swap the info blobs of the two deleted entries.
        let mut encrypted = vault.to_encrypted(true).unwrap();
        let item = encrypted
            .items
            .values_mut()
            .find(|item| item.deleted.len() == 2)
            .unwrap();
        let mut entries = item.deleted.values_mut();
        let (first, second) = (entries.next().unwrap(), entries.next().unwrap());
        std::mem::swap(&mut first.info, &mut second.info);

        let cipher = VaultCipher::new_with_bytes(&TEST_FILE_KEY, encrypted.id);
        assert!(Vault::from_encrypted_with_cipher(cipher, encrypted).is_err());
    }
}
