//! Vault mutations by id for the sync apply step.
//!
//! Each mutation writes values as given. It trims no title, normalizes no
//! key, adds no history entry, and reads no clock. Items and credentials are
//! addressed by id, live or trashed. A mutation drops only the cached blobs it
//! changes. It leaves a `DeletedInfo` unchanged unless it sets it.
//!
//! Only [`SyncWriter::set_keys`] checks that keys are unique. Adding,
//! restoring, or moving an entry writes its key unchecked, so the caller calls
//! `set_keys` after those mutations.

use std::collections::{BTreeMap, BTreeSet};

use secrecy::{ExposeSecret, SecretBox};
use uuid::Uuid;

use super::{
    CredentialId, DecryptedCredential, DecryptedHistoryEntry, DecryptedItem,
    DeletedCredentialOverview, DeletedEntry, DeletedInfo, DeletedItemEntry, FolderId,
    HistoryMetadata, ItemId, SectionId, Vault, VaultCredentialMetadata, VaultFolder,
    VaultItemCredentialOverview, VaultItemOverview, VaultItemSection,
};
use crate::secrets::vaults::autofill::item::{ItemAutofill, Website};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::encrypted_blob::EncryptedBlob;
use crate::secrets::vaults::format::encrypted_vault::{
    DeletedCredential, EncryptedVaultItemCredential, HistoryEntry,
};
use crate::secrets::vaults::format::vault_cipher::VaultCipher;
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::storage::handle::validate_key;

impl Vault {
    /// Writer of the mutations by id that the sync apply step calls.
    pub(crate) fn sync_writer(&mut self) -> SyncWriter<'_> {
        SyncWriter { vault: self }
    }

    /// Remove the key index entries of `item` that point at it or its
    /// credentials.
    fn unindex_item(&mut self, item: &VaultItemOverview) {
        if self.item_index.get(&item.key) == Some(&item.id) {
            self.item_index.remove(&item.key);
        }
        for cred in item.credentials.values() {
            let index_key = (item.key.clone(), cred.key.clone());
            if self.item_credential_index.get(&index_key) == Some(&(item.id, cred.id)) {
                self.item_credential_index.remove(&index_key);
            }
        }
    }

    /// Build both key indexes again from the live items.
    fn rebuild_key_indexes(&mut self) {
        self.item_index = self
            .items
            .values()
            .map(|item| (item.key.clone(), item.id))
            .collect();
        self.item_credential_index = self
            .items
            .values()
            .flat_map(|item| {
                item.credentials
                    .values()
                    .map(move |cred| ((item.key.clone(), cred.key.clone()), (item.id, cred.id)))
            })
            .collect();
    }
}

/// Mutations by id on a vault. See the module docs.
pub(crate) struct SyncWriter<'a> {
    vault: &'a mut Vault,
}

/// History entry of a credential, as given to [`SyncWriter::set_history`].
pub(crate) struct SyncHistoryEntry<'a> {
    pub(crate) id: Uuid,
    pub(crate) metadata: HistoryMetadata,
    pub(crate) value: Option<&'a str>,
}

/// Place of a credential in the vault, with the id of its item.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Place {
    /// In a live item, not trashed.
    Live(ItemId),
    /// Trashed, from a live item.
    Trashed(ItemId),
    /// In a trashed item, not trashed itself.
    InTrashedItem(ItemId),
    /// Trashed, from a trashed item.
    TrashedInTrashedItem(ItemId),
}

impl Place {
    fn item(self) -> ItemId {
        match self {
            Self::Live(item)
            | Self::Trashed(item)
            | Self::InTrashedItem(item)
            | Self::TrashedInTrashedItem(item) => item,
        }
    }

    fn is_trashed(self) -> bool {
        matches!(self, Self::Trashed(_) | Self::TrashedInTrashedItem(_))
    }
}

/// Item blob a change of the item overview makes stale.
#[derive(Clone, Copy)]
enum ItemBlob {
    Metadata,
    Autofill,
}

/// Credential read out of its place, with blobs bound to `item`.
struct Detached {
    item: ItemId,
    overview: VaultItemCredentialOverview,
    /// `None` if not current.
    metadata: Option<EncryptedBlob<VaultCredentialMetadata>>,
    /// `None` for a credential with no value.
    value: Option<EncryptedBlob<String>>,
    history: Vec<HistoryEntry>,
    /// Info blob and time of a trashed credential.
    trashed: Option<(EncryptedBlob<DeletedInfo>, i64)>,
}

/// Blobs of a credential for the place it is put in.
enum Blobs {
    /// Credential of a live item that is not trashed. A missing blob is
    /// encrypted at save.
    Live {
        metadata: Option<EncryptedBlob<VaultCredentialMetadata>>,
        value: Option<EncryptedBlob<String>>,
    },
    /// Credential in any other place. Every blob is present.
    Stored {
        metadata: EncryptedBlob<VaultCredentialMetadata>,
        value: EncryptedBlob<String>,
        trashed: Option<(EncryptedBlob<DeletedInfo>, i64)>,
    },
}

impl Detached {
    /// Same credential with every blob encrypted again for item `dest`.
    fn rekeyed(self, cipher: &VaultCipher, dest: ItemId) -> Result<Self, Error> {
        let Self {
            item,
            overview,
            metadata: _,
            value,
            history,
            trashed,
        } = self;
        let id = overview.id;
        let value = match value {
            Some(blob) => {
                let plain = cipher.decrypt_cred_value(item, id, &blob)?;
                Some(cipher.encrypt_cred_value(dest, id, plain.expose_secret())?)
            },
            None => None,
        };
        let trashed = match trashed {
            Some((blob, deleted_at)) => {
                let info = cipher.decrypt_deleted_info(item, id, &blob)?;
                let blob = cipher.encrypt_deleted_info(dest, id, info.expose_secret())?;
                Some((blob, deleted_at))
            },
            None => None,
        };
        let mut moved = Vec::with_capacity(history.len());
        for entry in &history {
            let decrypted = cipher.decrypt_history_entry(item, id, entry)?;
            moved.push(cipher.encrypt_history_entry(dest, id, &decrypted)?);
        }
        Ok(Self {
            item: dest,
            metadata: Some(cipher.encrypt_cred_metadata(dest, id, &overview.to_metadata())?),
            overview,
            value,
            history: moved,
            trashed,
        })
    }

    /// Blobs for a place in item `self.item`, which is live if `item_live`.
    /// Missing blobs are encrypted unless the place is a live item and the
    /// credential is not trashed. An absent value is encrypted as empty.
    fn into_parts(
        self,
        cipher: &VaultCipher,
        item_live: bool,
    ) -> Result<(VaultItemCredentialOverview, Vec<HistoryEntry>, Blobs), Error> {
        let Self {
            item,
            overview,
            metadata,
            value,
            history,
            trashed,
        } = self;
        if item_live && trashed.is_none() {
            return Ok((overview, history, Blobs::Live { metadata, value }));
        }
        let metadata = match metadata {
            Some(blob) => blob,
            None => cipher.encrypt_cred_metadata(item, overview.id, &overview.to_metadata())?,
        };
        let value = match value {
            Some(blob) => blob,
            None => cipher.encrypt_cred_value(item, overview.id, "")?,
        };
        let blobs = Blobs::Stored {
            metadata,
            value,
            trashed,
        };
        Ok((overview, history, blobs))
    }
}

impl SyncWriter<'_> {
    /// Add or replace a folder.
    pub(crate) fn set_folder(&mut self, id: FolderId, title: &str, position: Option<u32>) {
        let folder = VaultFolder {
            id,
            title: title.to_string(),
            position,
        };
        self.vault.folders.insert(id, folder);
        self.vault.metadata_blob = None;
    }

    /// Remove a folder. Live and trashed items in it become unfiled.
    pub(crate) fn purge_folder(&mut self, id: FolderId) -> Result<(), Error> {
        let vault = &mut *self.vault;
        vault
            .folders
            .remove(&id)
            .ok_or_else(|| Error::InvalidFolder(id.to_string()))?;
        vault.metadata_blob = None;
        for item in vault.items.values_mut() {
            if item.folder == Some(id) {
                item.folder = None;
                vault.item_blobs.remove(&item.id);
            }
        }
        for entry in vault.deleted_items.values_mut() {
            if entry.item.overview.folder == Some(id) {
                entry.item.overview.folder = None;
                entry.item.metadata_current = false;
            }
        }
        Ok(())
    }

    /// Add or replace a section of a live or trashed item.
    pub(crate) fn set_section(
        &mut self,
        item: ItemId,
        id: SectionId,
        title: &str,
        position: Option<u32>,
    ) -> Result<(), Error> {
        let section = VaultItemSection {
            id,
            title: title.to_string(),
            position,
        };
        self.edit_item(item, ItemBlob::Metadata, |overview| {
            overview.sections.insert(id, section);
            Ok(())
        })
    }

    /// Remove a section of a live or trashed item. Its credentials, trashed or
    /// not, move to the default section.
    pub(crate) fn purge_section(&mut self, item: ItemId, id: SectionId) -> Result<(), Error> {
        self.edit_item(item, ItemBlob::Metadata, |overview| {
            overview
                .sections
                .remove(&id)
                .map(|_| ())
                .ok_or_else(|| Error::InvalidSection(id.to_string()))
        })?;
        let in_section: Vec<CredentialId> = self
            .item_credentials(item)
            .into_iter()
            .filter(|cred| cred.section == Some(id))
            .map(|cred| cred.id)
            .collect();
        for cred in in_section {
            self.edit_credential(cred, |cred| cred.section = None)?;
        }
        Ok(())
    }

    /// Add a live item with no folder, sections, category, autofill data, or
    /// credentials. Fails if the id is taken.
    pub(crate) fn add_item(
        &mut self,
        id: ItemId,
        title: &str,
        key: &str,
        created_at: i64,
    ) -> Result<(), Error> {
        let vault = &mut *self.vault;
        if vault.items.contains_key(&id) || vault.deleted_items.contains_key(&id) {
            return Err(Error::InvalidItemKey(format!("item {id} exists")));
        }
        let overview = VaultItemOverview {
            id,
            title: title.to_string(),
            key: key.to_string(),
            folder: None,
            sections: BTreeMap::new(),
            category: None,
            autofill: ItemAutofill::default(),
            credentials: BTreeMap::new(),
            created_at,
        };
        vault.item_index.insert(key.to_string(), id);
        vault.items.insert(id, overview);
        Ok(())
    }

    pub(crate) fn set_item_title(&mut self, id: ItemId, title: &str) -> Result<(), Error> {
        self.edit_item(id, ItemBlob::Metadata, |item| {
            item.title = title.to_string();
            Ok(())
        })
    }

    pub(crate) fn set_item_created_at(&mut self, id: ItemId, at: i64) -> Result<(), Error> {
        self.edit_item(id, ItemBlob::Metadata, |item| {
            item.created_at = at;
            Ok(())
        })
    }

    pub(crate) fn set_item_category(
        &mut self,
        id: ItemId,
        category: Option<String>,
    ) -> Result<(), Error> {
        self.edit_item(id, ItemBlob::Metadata, |item| {
            item.category = category;
            Ok(())
        })
    }

    /// File an item in a folder, or unfile it if `folder` is `None`. The
    /// folder must exist.
    pub(crate) fn set_item_folder(
        &mut self,
        id: ItemId,
        folder: Option<FolderId>,
    ) -> Result<(), Error> {
        if let Some(folder) = folder {
            self.vault.get_folder(folder)?;
        }
        self.edit_item(id, ItemBlob::Metadata, |item| {
            item.folder = folder;
            Ok(())
        })
    }

    /// Replace the websites of an item. Fails on two websites with one URL.
    pub(crate) fn set_websites(&mut self, id: ItemId, websites: Vec<Website>) -> Result<(), Error> {
        let mut urls = BTreeSet::new();
        if let Some(website) = websites.iter().find(|w| !urls.insert(w.url.as_str())) {
            return Err(Error::InvalidAutofill(format!(
                "two websites have the URL {}",
                website.url
            )));
        }
        self.edit_item(id, ItemBlob::Autofill, |item| {
            item.autofill.websites = websites;
            Ok(())
        })
    }

    /// Set the username, password, and TOTP slots of an item. Each slot must
    /// name a credential of the item that is not trashed, and the username
    /// and password slots must differ.
    pub(crate) fn set_slots(
        &mut self,
        id: ItemId,
        username: Option<CredentialId>,
        password: Option<CredentialId>,
        totp: Option<CredentialId>,
    ) -> Result<(), Error> {
        if username.is_some() && username == password {
            return Err(Error::InvalidAutofill(
                "one credential cannot be both the username and the password".to_string(),
            ));
        }
        self.edit_item(id, ItemBlob::Autofill, |item| {
            for slot in [username, password, totp].into_iter().flatten() {
                if !item.credentials.contains_key(&slot) {
                    return Err(Error::InvalidAutofill(format!(
                        "credential {slot} is not in item {id}"
                    )));
                }
            }
            item.autofill.username = username;
            item.autofill.password = password;
            item.autofill.totp = totp;
            Ok(())
        })
    }

    /// Trash an item with `info`, set the info of a trashed item, or restore
    /// a trashed item if `info` is `None`. A restored item keeps its key and
    /// folder unchecked.
    pub(crate) fn set_item_trashed(
        &mut self,
        id: ItemId,
        info: Option<&DeletedInfo>,
    ) -> Result<(), Error> {
        if self.vault.items.contains_key(&id) {
            return match info {
                Some(info) => self.trash_live_item(id, info),
                None => Ok(()),
            };
        }
        let vault = &mut *self.vault;
        match info {
            Some(info) => {
                let blob = vault.cipher.encrypt_deleted_item_info(id, info)?;
                let entry = vault
                    .deleted_items
                    .get_mut(&id)
                    .ok_or_else(|| Error::DeletedItemNotFound(id.to_string()))?;
                entry.info = blob;
                entry.deleted_at = info.deleted_at;
            },
            None => {
                let entry = vault
                    .deleted_items
                    .remove(&id)
                    .ok_or_else(|| Error::DeletedItemNotFound(id.to_string()))?;
                vault.insert_item(entry.item);
            },
        }
        Ok(())
    }

    /// Move a live item to the trash with `info`. Its credentials and its
    /// trashed credentials go with it.
    fn trash_live_item(&mut self, id: ItemId, info: &DeletedInfo) -> Result<(), Error> {
        let vault = &mut *self.vault;
        let overview = vault
            .items
            .get(&id)
            .ok_or_else(|| Error::InvalidItemKey(id.to_string()))?
            .clone();

        // Build the trashed entry before changing anything.
        let metadata = match vault.item_blobs.get(&id) {
            Some(blob) => blob.clone(),
            None => vault
                .cipher
                .encrypt_item_metadata(id, &overview.to_metadata())?,
        };
        let autofill = vault.autofill_blobs.get(&id).cloned();
        let mut credentials = BTreeMap::new();
        for cred in overview.credentials.values() {
            let blobs = vault.live_credential_blobs(id, cred)?;
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
        let info_blob = vault.cipher.encrypt_deleted_item_info(id, info)?;

        vault.unindex_item(&overview);
        for cred in overview.credentials.keys() {
            vault.secrets.remove(cred);
            vault.history.remove(cred);
            vault.cred_blobs.remove(cred);
        }
        let trashed: Vec<CredentialId> = vault
            .deleted
            .iter()
            .filter(|(_, entry)| entry.overview.item_id == id)
            .map(|(cred, _)| *cred)
            .collect();
        let deleted = trashed
            .into_iter()
            .filter_map(|cred| vault.deleted.remove(&cred).map(|entry| (cred, entry)))
            .collect();
        vault.items.remove(&id);
        vault.item_blobs.remove(&id);
        vault.autofill_blobs.remove(&id);

        vault.deleted_items.insert(
            id,
            DeletedItemEntry {
                item: DecryptedItem {
                    overview,
                    metadata,
                    metadata_current: true,
                    autofill,
                    credentials,
                    deleted,
                },
                info: info_blob,
                deleted_at: info.deleted_at,
            },
        );
        Ok(())
    }

    /// Remove a live or trashed item with all its credentials.
    pub(crate) fn purge_item(&mut self, id: ItemId) -> Result<(), Error> {
        let vault = &mut *self.vault;
        let Some(overview) = vault.items.remove(&id) else {
            return vault
                .deleted_items
                .remove(&id)
                .map(|_| ())
                .ok_or_else(|| Error::DeletedItemNotFound(id.to_string()));
        };
        vault.unindex_item(&overview);
        for cred in overview.credentials.keys() {
            vault.secrets.remove(cred);
            vault.history.remove(cred);
            vault.cred_blobs.remove(cred);
        }
        vault.item_blobs.remove(&id);
        vault.autofill_blobs.remove(&id);
        vault
            .deleted
            .retain(|_, entry| entry.overview.item_id != id);
        Ok(())
    }

    /// Add a credential to a live or trashed item, with no section, position,
    /// or last used time. Fails if the id is taken.
    pub(crate) fn add_credential(
        &mut self,
        item: ItemId,
        id: CredentialId,
        title: &str,
        key: &str,
        kind: FieldKind,
        value: &str,
        created_at: i64,
    ) -> Result<(), Error> {
        if self.place(id).is_ok() {
            return Err(Error::InvalidCredentialKey(format!(
                "credential {id} exists"
            )));
        }
        let item_live = self.item_is_live(item)?;
        let detached = Detached {
            item,
            overview: VaultItemCredentialOverview {
                id,
                title: title.to_string(),
                key: key.to_string(),
                kind,
                position: None,
                section: None,
                last_used_day_at: None,
                created_at,
            },
            metadata: None,
            value: Some(self.vault.cipher.encrypt_cred_value(item, id, value)?),
            history: Vec::new(),
            trashed: None,
        };
        self.relocate(None, detached, item_live)
    }

    pub(crate) fn set_credential_title(
        &mut self,
        id: CredentialId,
        title: &str,
    ) -> Result<(), Error> {
        self.edit_credential(id, |cred| cred.title = title.to_string())
    }

    pub(crate) fn set_credential_kind(
        &mut self,
        id: CredentialId,
        kind: FieldKind,
    ) -> Result<(), Error> {
        self.edit_credential(id, |cred| cred.kind = kind)
    }

    /// Set the section and position of a credential. The section must be a
    /// section of its item.
    pub(crate) fn set_placement(
        &mut self,
        id: CredentialId,
        section: Option<SectionId>,
        position: Option<u32>,
    ) -> Result<(), Error> {
        let item = self.place(id)?.item();
        if let Some(section) = section
            && !self
                .item_overview(item)
                .is_some_and(|i| i.sections.contains_key(&section))
        {
            return Err(Error::InvalidSection(section.to_string()));
        }
        self.edit_credential(id, |cred| {
            cred.section = section;
            cred.position = position;
        })
    }

    pub(crate) fn set_credential_created_at(
        &mut self,
        id: CredentialId,
        at: i64,
    ) -> Result<(), Error> {
        self.edit_credential(id, |cred| cred.created_at = at)
    }

    pub(crate) fn set_last_used(&mut self, id: CredentialId, at: Option<i64>) -> Result<(), Error> {
        self.edit_credential(id, |cred| cred.last_used_day_at = at)
    }

    /// Set the value of a credential. Only the value blob is encrypted again.
    pub(crate) fn set_value(&mut self, id: CredentialId, value: &str) -> Result<(), Error> {
        let place = self.place(id)?;
        let vault = &mut *self.vault;
        let blob = vault.cipher.encrypt_cred_value(place.item(), id, value)?;
        let missing = || Error::InvalidCredentialKey(id.to_string());
        match place {
            Place::Live(_) => {
                vault.secrets.insert(id, blob);
            },
            Place::InTrashedItem(item) => {
                let entry = vault.deleted_items.get_mut(&item).ok_or_else(missing)?;
                let cred = entry.item.credentials.get_mut(&id).ok_or_else(missing)?;
                cred.value = blob;
            },
            Place::Trashed(_) | Place::TrashedInTrashedItem(_) => {
                let entry = Self::deleted_entry_mut(
                    &mut vault.deleted,
                    &mut vault.deleted_items,
                    place,
                    id,
                )
                .ok_or_else(missing)?;
                entry.blobs.credential.value = blob;
            },
        }
        Ok(())
    }

    /// Trash a credential with `info`, set the info of a trashed credential,
    /// or restore a trashed credential if `info` is `None`. A role slot that
    /// names a trashed credential is cleared. A restore fills no role slot,
    /// and keeps the key unchecked.
    pub(crate) fn set_credential_trashed(
        &mut self,
        id: CredentialId,
        info: Option<&DeletedInfo>,
    ) -> Result<(), Error> {
        let place = self.place(id)?;
        let item = place.item();
        match (place.is_trashed(), info) {
            (false, None) => Ok(()),
            (true, Some(info)) => {
                let vault = &mut *self.vault;
                let blob = vault.cipher.encrypt_deleted_info(item, id, info)?;
                let entry = Self::deleted_entry_mut(
                    &mut vault.deleted,
                    &mut vault.deleted_items,
                    place,
                    id,
                )
                .ok_or_else(|| Error::InvalidCredentialKey(id.to_string()))?;
                entry.blobs.info = blob;
                entry.overview.deleted_at = info.deleted_at;
                Ok(())
            },
            (_, info) => {
                let mut detached = self.detached(place, id)?;
                detached.trashed = match info {
                    Some(info) => {
                        let blob = self.vault.cipher.encrypt_deleted_info(item, id, info)?;
                        Some((blob, info.deleted_at))
                    },
                    None => None,
                };
                let item_live = self.item_is_live(item)?;
                self.relocate(Some(place), detached, item_live)
            },
        }
    }

    /// Move a credential, trashed or not, to another item, live or trashed.
    /// Its value, history, metadata, and trash info are encrypted again under
    /// the new item. Its key and placement are unchanged. A role slot of the
    /// source item that names it is cleared.
    pub(crate) fn move_credential(&mut self, id: CredentialId, dest: ItemId) -> Result<(), Error> {
        let place = self.place(id)?;
        if place.item() == dest {
            return Ok(());
        }
        let item_live = self.item_is_live(dest)?;
        let detached = self
            .detached(place, id)?
            .rekeyed(&self.vault.cipher, dest)?;
        self.relocate(Some(place), detached, item_live)
    }

    /// Replace the history of a credential with `entries`, in the given order.
    /// A stored blob that matches the given metadata or value is kept. Other
    /// blobs are encrypted again. Fails if the presence of a value does not
    /// match its kind.
    pub(crate) fn set_history(
        &mut self,
        id: CredentialId,
        entries: &[SyncHistoryEntry<'_>],
    ) -> Result<(), Error> {
        let place = self.place(id)?;
        let item = place.item();
        let current = self.history(place, id);
        let cipher = &self.vault.cipher;
        let mut history = Vec::with_capacity(entries.len());
        for given in entries {
            let stored = current.iter().find(|entry| entry.id == given.id);
            let encrypted = cipher.encrypt_history_entry(
                item,
                id,
                &DecryptedHistoryEntry {
                    id: given.id,
                    metadata: given.metadata.clone(),
                    value: given
                        .value
                        .map(|value| SecretBox::new(Box::new(value.to_string()))),
                },
            )?;
            let Some(stored) = stored else {
                history.push(encrypted);
                continue;
            };
            let metadata = if *cipher
                .decrypt_history_metadata(item, id, stored.id, &stored.metadata)?
                .expose_secret()
                == given.metadata
            {
                stored.metadata.clone()
            } else {
                encrypted.metadata
            };
            let value = match (&stored.value, given.value) {
                (Some(blob), Some(value))
                    if cipher
                        .decrypt_history_value(item, id, stored.id, blob)?
                        .expose_secret()
                        == value =>
                {
                    Some(blob.clone())
                },
                _ => encrypted.value,
            };
            history.push(HistoryEntry {
                id: given.id,
                metadata,
                value,
            });
        }
        self.replace_history(place, id, |stored| *stored = history)
    }

    /// Change the id of one history entry of a credential. Its blobs are
    /// encrypted again under the new id. Fails if the entry is missing or the
    /// new id is taken.
    pub(crate) fn set_history_id(
        &mut self,
        id: CredentialId,
        entry: Uuid,
        new_id: Uuid,
    ) -> Result<(), Error> {
        let place = self.place(id)?;
        let item = place.item();
        let current = self.history(place, id);
        if current.iter().any(|e| e.id == new_id) {
            return Err(Error::InvalidHistoryEntry(new_id.to_string()));
        }
        let stored = current
            .iter()
            .find(|e| e.id == entry)
            .ok_or_else(|| Error::InvalidHistoryEntry(entry.to_string()))?;
        let cipher = &self.vault.cipher;
        let mut decrypted = cipher.decrypt_history_entry(item, id, stored)?;
        decrypted.id = new_id;
        let mut renamed = Some(cipher.encrypt_history_entry(item, id, &decrypted)?);
        self.replace_history(place, id, |stored| {
            for e in stored.iter_mut() {
                if e.id == entry
                    && let Some(renamed) = renamed.take()
                {
                    *e = renamed;
                }
            }
        })
    }

    /// Remove a credential, trashed or not, with its value and history. A
    /// role slot that names it is cleared.
    pub(crate) fn purge_credential(&mut self, id: CredentialId) -> Result<(), Error> {
        let place = self.place(id)?;
        self.remove_credential(place, id);
        Ok(())
    }

    /// Set the keys of the items and credentials in `items` and
    /// `credentials`, live or trashed. Other keys are unchanged.
    ///
    /// The final keys must be valid. Live items must have unique keys, and
    /// the credentials of each item, live or trashed, that are not trashed
    /// must have unique keys. If not, the call fails and changes nothing. The
    /// key indexes are built again from the final keys.
    pub(crate) fn set_keys(
        &mut self,
        items: &BTreeMap<ItemId, String>,
        credentials: &BTreeMap<CredentialId, String>,
    ) -> Result<(), Error> {
        for (id, key) in items {
            self.item_is_live(*id)?;
            if !validate_key(key) {
                return Err(Error::InvalidItemKey(key.clone()));
            }
        }
        let mut places = BTreeMap::new();
        for (id, key) in credentials {
            places.insert(*id, self.place(*id)?);
            if !validate_key(key) {
                return Err(Error::InvalidCredentialKey(key.clone()));
            }
        }

        let vault = &*self.vault;
        let mut taken = BTreeSet::new();
        for item in vault.items.values() {
            let key = items.get(&item.id).unwrap_or(&item.key);
            if !taken.insert(key) {
                return Err(Error::DuplicateItemKey(key.clone()));
            }
        }
        let all_items = vault
            .items
            .values()
            .chain(vault.deleted_items.values().map(|e| &e.item.overview));
        for item in all_items {
            let mut taken = BTreeSet::new();
            for cred in item.credentials.values() {
                let key = credentials.get(&cred.id).unwrap_or(&cred.key);
                if !taken.insert(key) {
                    return Err(Error::DuplicateCredentialKey(key.clone()));
                }
            }
        }

        // Trashed credentials hold no metadata cache, so their metadata is
        // encrypted before anything changes.
        let mut trashed = Vec::new();
        for (id, place) in &places {
            if !place.is_trashed() {
                continue;
            }
            let entry = self
                .deleted_entry(*place, *id)
                .ok_or_else(|| Error::InvalidCredentialKey(id.to_string()))?;
            let key = &credentials[id];
            if entry.overview.credential.key != *key {
                let mut credential = entry.overview.credential.clone();
                credential.key = key.clone();
                let blob = vault.cipher.encrypt_cred_metadata(
                    entry.overview.item_id,
                    *id,
                    &credential.to_metadata(),
                )?;
                trashed.push((*place, *id, credential, blob));
            }
        }

        let vault = &mut *self.vault;
        for (id, key) in items {
            if let Some(item) = vault.items.get_mut(id) {
                if item.key != *key {
                    item.key = key.clone();
                    vault.item_blobs.remove(id);
                }
            } else if let Some(entry) = vault.deleted_items.get_mut(id)
                && entry.item.overview.key != *key
            {
                entry.item.overview.key = key.clone();
                entry.item.metadata_current = false;
            }
        }
        for (id, place) in &places {
            let key = &credentials[id];
            match *place {
                Place::Live(item) => {
                    if let Some(cred) = vault
                        .items
                        .get_mut(&item)
                        .and_then(|i| i.credentials.get_mut(id))
                        && cred.key != *key
                    {
                        cred.key = key.clone();
                        vault.cred_blobs.remove(id);
                    }
                },
                Place::InTrashedItem(item) => {
                    if let Some(entry) = vault.deleted_items.get_mut(&item)
                        && let Some(cred) = entry.item.overview.credentials.get_mut(id)
                        && cred.key != *key
                    {
                        cred.key = key.clone();
                        if let Some(blobs) = entry.item.credentials.get_mut(id) {
                            blobs.metadata_current = false;
                        }
                    }
                },
                Place::Trashed(_) | Place::TrashedInTrashedItem(_) => {},
            }
        }
        for (place, id, credential, blob) in trashed {
            if let Some(entry) =
                Self::deleted_entry_mut(&mut vault.deleted, &mut vault.deleted_items, place, id)
            {
                entry.overview.credential = credential;
                entry.blobs.credential.metadata = blob;
            }
        }
        vault.rebuild_key_indexes();
        Ok(())
    }

    /// Whether item `id` is live. Fails if it is neither live nor trashed.
    fn item_is_live(&self, id: ItemId) -> Result<bool, Error> {
        if self.vault.items.contains_key(&id) {
            Ok(true)
        } else if self.vault.deleted_items.contains_key(&id) {
            Ok(false)
        } else {
            Err(Error::InvalidItemKey(id.to_string()))
        }
    }

    /// Overview of a live or trashed item.
    fn item_overview(&self, id: ItemId) -> Option<&VaultItemOverview> {
        self.vault
            .items
            .get(&id)
            .or_else(|| self.vault.deleted_items.get(&id).map(|e| &e.item.overview))
    }

    /// Apply `edit` to the overview of a live or trashed item, and drop the
    /// `blob` it makes stale.
    fn edit_item(
        &mut self,
        id: ItemId,
        blob: ItemBlob,
        edit: impl FnOnce(&mut VaultItemOverview) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let vault = &mut *self.vault;
        if let Some(item) = vault.items.get_mut(&id) {
            edit(item)?;
            match blob {
                ItemBlob::Metadata => {
                    vault.item_blobs.remove(&id);
                },
                ItemBlob::Autofill => {
                    vault.autofill_blobs.remove(&id);
                },
            }
        } else if let Some(entry) = vault.deleted_items.get_mut(&id) {
            edit(&mut entry.item.overview)?;
            match blob {
                ItemBlob::Metadata => entry.item.metadata_current = false,
                ItemBlob::Autofill => entry.item.autofill = None,
            }
        } else {
            return Err(Error::InvalidItemKey(id.to_string()));
        }
        Ok(())
    }

    /// Place of a credential.
    fn place(&self, id: CredentialId) -> Result<Place, Error> {
        let vault = &*self.vault;
        if let Some(entry) = vault.deleted.get(&id) {
            return Ok(Place::Trashed(entry.overview.item_id));
        }
        if let Some(item) = vault
            .items
            .values()
            .find(|i| i.credentials.contains_key(&id))
        {
            return Ok(Place::Live(item.id));
        }
        for (item, entry) in &vault.deleted_items {
            if entry.item.overview.credentials.contains_key(&id) {
                return Ok(Place::InTrashedItem(*item));
            }
            if entry.item.deleted.contains_key(&id) {
                return Ok(Place::TrashedInTrashedItem(*item));
            }
        }
        Err(Error::InvalidCredentialKey(id.to_string()))
    }

    /// Credentials of a live or trashed item, trashed or not.
    fn item_credentials(&self, item: ItemId) -> Vec<&VaultItemCredentialOverview> {
        let vault = &*self.vault;
        if let Some(overview) = vault.items.get(&item) {
            let trashed = vault
                .deleted
                .values()
                .filter(|entry| entry.overview.item_id == item)
                .map(|entry| &entry.overview.credential);
            overview.credentials.values().chain(trashed).collect()
        } else if let Some(entry) = vault.deleted_items.get(&item) {
            let trashed = entry
                .item
                .deleted
                .values()
                .map(|entry| &entry.overview.credential);
            entry
                .item
                .overview
                .credentials
                .values()
                .chain(trashed)
                .collect()
        } else {
            Vec::new()
        }
    }

    fn deleted_entry(&self, place: Place, id: CredentialId) -> Option<&DeletedEntry> {
        match place {
            Place::Trashed(_) => self.vault.deleted.get(&id),
            Place::TrashedInTrashedItem(item) => {
                self.vault.deleted_items.get(&item)?.item.deleted.get(&id)
            },
            Place::Live(_) | Place::InTrashedItem(_) => None,
        }
    }

    fn deleted_entry_mut<'v>(
        deleted: &'v mut BTreeMap<CredentialId, DeletedEntry>,
        deleted_items: &'v mut BTreeMap<ItemId, DeletedItemEntry>,
        place: Place,
        id: CredentialId,
    ) -> Option<&'v mut DeletedEntry> {
        match place {
            Place::Trashed(_) => deleted.get_mut(&id),
            Place::TrashedInTrashedItem(item) => {
                deleted_items.get_mut(&item)?.item.deleted.get_mut(&id)
            },
            Place::Live(_) | Place::InTrashedItem(_) => None,
        }
    }

    /// Apply `edit` to the overview of a credential, and drop or encrypt
    /// again its metadata blob.
    fn edit_credential(
        &mut self,
        id: CredentialId,
        edit: impl FnOnce(&mut VaultItemCredentialOverview),
    ) -> Result<(), Error> {
        let place = self.place(id)?;
        let vault = &mut *self.vault;
        let missing = || Error::InvalidCredentialKey(id.to_string());
        match place {
            Place::Live(item) => {
                let cred = vault
                    .items
                    .get_mut(&item)
                    .and_then(|i| i.credentials.get_mut(&id))
                    .ok_or_else(missing)?;
                edit(cred);
                vault.cred_blobs.remove(&id);
            },
            Place::InTrashedItem(item) => {
                let item = &mut vault.deleted_items.get_mut(&item).ok_or_else(missing)?.item;
                let (Some(cred), Some(blobs)) = (
                    item.overview.credentials.get_mut(&id),
                    item.credentials.get_mut(&id),
                ) else {
                    return Err(missing());
                };
                edit(cred);
                blobs.metadata_current = false;
            },
            Place::Trashed(_) | Place::TrashedInTrashedItem(_) => {
                let entry = Self::deleted_entry_mut(
                    &mut vault.deleted,
                    &mut vault.deleted_items,
                    place,
                    id,
                )
                .ok_or_else(missing)?;
                let mut credential = entry.overview.credential.clone();
                edit(&mut credential);
                entry.blobs.credential.metadata = vault.cipher.encrypt_cred_metadata(
                    entry.overview.item_id,
                    id,
                    &credential.to_metadata(),
                )?;
                entry.overview.credential = credential;
            },
        }
        Ok(())
    }

    /// Stored previous values of a credential.
    fn history(&self, place: Place, id: CredentialId) -> Vec<HistoryEntry> {
        let vault = &*self.vault;
        let stored = match place {
            Place::Live(_) => vault.history.get(&id),
            Place::InTrashedItem(item) => vault
                .deleted_items
                .get(&item)
                .and_then(|e| e.item.credentials.get(&id))
                .map(|cred| &cred.history),
            Place::Trashed(_) | Place::TrashedInTrashedItem(_) => self
                .deleted_entry(place, id)
                .map(|entry| &entry.blobs.credential.history),
        };
        stored.cloned().unwrap_or_default()
    }

    /// Apply `change` to the stored previous values of a credential. A live
    /// credential left with none has no entry in `history`.
    fn replace_history(
        &mut self,
        place: Place,
        id: CredentialId,
        change: impl FnOnce(&mut Vec<HistoryEntry>),
    ) -> Result<(), Error> {
        let vault = &mut *self.vault;
        let missing = || Error::InvalidCredentialKey(id.to_string());
        match place {
            Place::Live(_) => {
                let history = vault.history.entry(id).or_default();
                change(history);
                if history.is_empty() {
                    vault.history.remove(&id);
                }
            },
            Place::InTrashedItem(item) => {
                let cred = vault
                    .deleted_items
                    .get_mut(&item)
                    .and_then(|e| e.item.credentials.get_mut(&id))
                    .ok_or_else(missing)?;
                change(&mut cred.history);
            },
            Place::Trashed(_) | Place::TrashedInTrashedItem(_) => {
                let entry = Self::deleted_entry_mut(
                    &mut vault.deleted,
                    &mut vault.deleted_items,
                    place,
                    id,
                )
                .ok_or_else(missing)?;
                change(&mut entry.blobs.credential.history);
            },
        }
        Ok(())
    }

    /// Copy of a credential and its blobs.
    fn detached(&self, place: Place, id: CredentialId) -> Result<Detached, Error> {
        let vault = &*self.vault;
        let missing = || Error::InvalidCredentialKey(id.to_string());
        let detached = match place {
            Place::Live(item) => Detached {
                item,
                overview: vault
                    .items
                    .get(&item)
                    .and_then(|i| i.credentials.get(&id))
                    .ok_or_else(missing)?
                    .clone(),
                metadata: vault.cred_blobs.get(&id).cloned(),
                value: vault.secrets.get(&id).cloned(),
                history: vault.history.get(&id).cloned().unwrap_or_default(),
                trashed: None,
            },
            Place::InTrashedItem(item) => {
                let item_entry = &vault.deleted_items.get(&item).ok_or_else(missing)?.item;
                let overview = item_entry
                    .overview
                    .credentials
                    .get(&id)
                    .ok_or_else(missing)?;
                let blobs = item_entry.credentials.get(&id).ok_or_else(missing)?;
                Detached {
                    item,
                    overview: overview.clone(),
                    metadata: blobs.metadata_current.then(|| blobs.metadata.clone()),
                    value: Some(blobs.value.clone()),
                    history: blobs.history.clone(),
                    trashed: None,
                }
            },
            Place::Trashed(item) | Place::TrashedInTrashedItem(item) => {
                let entry = self.deleted_entry(place, id).ok_or_else(missing)?;
                let blobs = &entry.blobs.credential;
                Detached {
                    item,
                    overview: entry.overview.credential.clone(),
                    metadata: Some(blobs.metadata.clone()),
                    value: Some(blobs.value.clone()),
                    history: blobs.history.clone(),
                    trashed: Some((entry.blobs.info.clone(), entry.overview.deleted_at)),
                }
            },
        };
        Ok(detached)
    }

    /// Put `detached` in its item, which is live if `item_live`, and remove
    /// the credential from `from` first. Blobs are encrypted before anything
    /// changes.
    fn relocate(
        &mut self,
        from: Option<Place>,
        detached: Detached,
        item_live: bool,
    ) -> Result<(), Error> {
        let item = detached.item;
        let (overview, history, blobs) = detached.into_parts(&self.vault.cipher, item_live)?;
        if let Some(from) = from {
            self.remove_credential(from, overview.id);
        }

        let vault = &mut *self.vault;
        let id = overview.id;
        match blobs {
            Blobs::Live { metadata, value } => {
                let Some(target) = vault.items.get_mut(&item) else {
                    return Err(Error::InvalidItemKey(item.to_string()));
                };
                vault
                    .item_credential_index
                    .insert((target.key.clone(), overview.key.clone()), (item, id));
                target.credentials.insert(id, overview);
                if let Some(metadata) = metadata {
                    vault.cred_blobs.insert(id, metadata);
                }
                if let Some(value) = value {
                    vault.secrets.insert(id, value);
                }
                if !history.is_empty() {
                    vault.history.insert(id, history);
                }
            },
            Blobs::Stored {
                metadata,
                value,
                trashed: None,
            } => {
                let Some(entry) = vault.deleted_items.get_mut(&item) else {
                    return Err(Error::DeletedItemNotFound(item.to_string()));
                };
                entry.item.overview.credentials.insert(id, overview);
                entry.item.credentials.insert(
                    id,
                    DecryptedCredential {
                        metadata,
                        metadata_current: true,
                        value,
                        history,
                    },
                );
            },
            Blobs::Stored {
                metadata,
                value,
                trashed: Some((info, deleted_at)),
            } => {
                let entry = DeletedEntry {
                    blobs: DeletedCredential {
                        credential: EncryptedVaultItemCredential {
                            metadata,
                            value,
                            history,
                        },
                        info,
                    },
                    overview: DeletedCredentialOverview {
                        item_id: item,
                        credential: overview,
                        deleted_at,
                    },
                };
                if item_live {
                    vault.deleted.insert(id, entry);
                } else if let Some(item_entry) = vault.deleted_items.get_mut(&item) {
                    item_entry.item.deleted.insert(id, entry);
                } else {
                    return Err(Error::DeletedItemNotFound(item.to_string()));
                }
            },
        }
        Ok(())
    }

    /// Remove a credential from `place` with its blobs. A role slot that
    /// names it is cleared.
    fn remove_credential(&mut self, place: Place, id: CredentialId) {
        let vault = &mut *self.vault;
        match place {
            Place::Live(item) => {
                if let Some(overview) = vault.items.get_mut(&item) {
                    if let Some(cred) = overview.credentials.remove(&id) {
                        let index_key = (overview.key.clone(), cred.key);
                        if vault.item_credential_index.get(&index_key) == Some(&(item, id)) {
                            vault.item_credential_index.remove(&index_key);
                        }
                    }
                    if overview.autofill.role_of(id).is_some() {
                        overview.autofill.clear_credential(id);
                        vault.autofill_blobs.remove(&item);
                    }
                }
                vault.secrets.remove(&id);
                vault.history.remove(&id);
                vault.cred_blobs.remove(&id);
            },
            Place::InTrashedItem(item) => {
                if let Some(entry) = vault.deleted_items.get_mut(&item) {
                    let item = &mut entry.item;
                    item.overview.credentials.remove(&id);
                    item.credentials.remove(&id);
                    if item.overview.autofill.role_of(id).is_some() {
                        item.overview.autofill.clear_credential(id);
                        item.autofill = None;
                    }
                }
            },
            Place::Trashed(_) => {
                vault.deleted.remove(&id);
            },
            Place::TrashedInTrashedItem(item) => {
                if let Some(entry) = vault.deleted_items.get_mut(&item) {
                    entry.item.deleted.remove(&id);
                }
            },
        }
    }
}
