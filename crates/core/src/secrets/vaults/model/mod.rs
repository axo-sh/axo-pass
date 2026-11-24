pub mod fields;
mod files;
pub mod history;
pub mod last_used;
mod overview;
mod sync;
pub mod totp;

use std::collections::{BTreeMap, BTreeSet};

use aes_gcm::aead::OsRng;
use aes_gcm::{Aes256Gcm, KeyInit};
pub(crate) use files::bundled_file_blobs;
use history::HistoryKind;
use jiff::tz::TimeZone;
pub use overview::{
    DeletedCredentialEntry, DeletedCredentialOverview, DeletedInfo, DeletedItemOverview,
    HistoryMetadata, HistoryOverview, ItemChange, ItemHistoryEvent, VaultCredentialMetadata,
    VaultFolder, VaultFolderMetadata, VaultItemCredentialOverview, VaultItemMetadata,
    VaultItemOverview, VaultItemSection, VaultMetadata, VaultSectionMetadata, display_order,
};
use secrecy::{ExposeSecret, SecretBox, SecretString};
pub(crate) use sync::{NewCredential, SyncHistoryEntry, SyncWriter};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::vaults::autofill::item::ItemAutofill;
use crate::secrets::vaults::bundle::exported_bundle::{BundledVault, ExportedBundle};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::files::FileHash;
use crate::secrets::vaults::format::encrypted_blob::EncryptedBlob;
use crate::secrets::vaults::format::encrypted_vault::{
    DeletedCredential, DeletedItem, EncryptedVault, EncryptedVaultItem,
    EncryptedVaultItemCredential, HistoryEntry, VaultFileKey, VerifiedVault,
};
use crate::secrets::vaults::format::vault_cipher::VaultCipher;
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::passkey::signals::SignalStore;
use crate::secrets::vaults::storage::handle::normalized_key;

type FolderId = Uuid;
type ItemId = Uuid;
type SectionId = Uuid;
type CredentialId = Uuid;

/// Unwrapped file key of a vault and the wrapped form it came from. A
/// transaction unwraps the key before it takes the vault locks, and decrypts
/// the reloaded file with it under the locks.
pub struct UnlockedKey {
    file_key: VaultFileKey,
    cipher: VaultCipher,
}

impl UnlockedKey {
    /// Unwrap the file key of the verified vault file `enc_vault` with the
    /// vault encryption key.
    pub(crate) fn unwrap(
        user_encryption_key: &ManagedKey,
        enc_vault: &VerifiedVault,
    ) -> Result<Self, Error> {
        Ok(Self {
            file_key: enc_vault.file_key.clone(),
            cipher: enc_vault.decrypt_file_key(user_encryption_key)?,
        })
    }

    /// New random file key of vault `vault_id`, wrapped with the vault
    /// encryption key.
    pub(crate) fn generate(
        user_encryption_key: &ManagedKey,
        vault_id: Uuid,
    ) -> Result<Self, Error> {
        let raw = Zeroizing::new(Aes256Gcm::generate_key(OsRng));
        let file_key = VaultFileKey::new(
            user_encryption_key
                .encrypt(&raw)
                .ok_or(Error::VaultFileKeyEncryptionError)?
                .into_bytes(),
        );
        Ok(Self {
            file_key,
            cipher: VaultCipher::new_with_bytes(&raw, vault_id),
        })
    }

    /// Vault id the file key encrypts for.
    pub(crate) fn vault_id(&self) -> Uuid {
        self.cipher.vault_id()
    }

    /// Key of a vault file whose wrapped key is ignored, for tests.
    #[cfg(test)]
    pub(crate) fn for_test(file_key: VaultFileKey, cipher: VaultCipher) -> Self {
        Self { file_key, cipher }
    }

    #[cfg(test)]
    pub(crate) fn cipher_for_test(&self) -> VaultCipher {
        self.cipher.duplicate()
    }

    /// Copy of this key, for tests.
    #[cfg(test)]
    pub(crate) fn duplicate_for_test(&self) -> Self {
        Self {
            file_key: self.file_key.clone(),
            cipher: self.cipher.duplicate(),
        }
    }
}

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
    // Vault key, already validated. Written to the vault file.
    key: String,
    pub name: Option<String>,
    file_key: VaultFileKey,
    cipher: VaultCipher,
    // Sync fields as read from the file, written back unchanged. A vault that
    // is not synced has generation 0 and no replica id.
    generation: u64,
    replica_id: Option<Uuid>,

    folders: BTreeMap<FolderId, VaultFolder>,
    // Site reports about the passkeys in this vault. Stored in the vault blob.
    passkey_signals: SignalStore,
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

    // Cached encrypted blobs. The vault blob holds the folders. An entry is
    // dropped when its data changes so that to_encrypted() only re-encrypts
    // what is necessary.
    metadata_blob: Option<EncryptedBlob<VaultMetadata>>,
    item_blobs: BTreeMap<ItemId, EncryptedBlob<VaultItemMetadata>>,
    autofill_blobs: BTreeMap<ItemId, EncryptedBlob<ItemAutofill>>,
    cred_blobs: BTreeMap<CredentialId, EncryptedBlob<VaultCredentialMetadata>>,
}

impl Vault {
    /// New empty vault with a random id and file key. `key` must be a valid
    /// vault key.
    pub fn new(
        name: Option<String>,
        key: String,
        user_encryption_key: ManagedKey,
    ) -> Result<Self, Error> {
        let vault_id = Uuid::new_v4();
        let actual_file_key = Zeroizing::new(Aes256Gcm::generate_key(OsRng));

        // use actual key to create personal vault file key
        let enc_file_key = VaultFileKey::new(
            user_encryption_key
                .encrypt(&actual_file_key)
                .ok_or(Error::VaultFileKeyEncryptionError)?
                .into_bytes(),
        );

        // wrap actual key in VaultCipher to simplify operations
        let cipher = VaultCipher::new_with_bytes(&actual_file_key, vault_id);

        Ok(Self::empty(vault_id, key, name, enc_file_key, cipher))
    }

    fn empty(
        id: Uuid,
        key: String,
        name: Option<String>,
        file_key: VaultFileKey,
        cipher: VaultCipher,
    ) -> Self {
        Self {
            id,
            key,
            name,
            file_key,
            cipher,
            generation: 0,
            replica_id: None,
            folders: BTreeMap::new(),
            passkey_signals: SignalStore::new(),
            items: BTreeMap::new(),
            item_index: BTreeMap::new(),
            item_credential_index: BTreeMap::new(),
            secrets: BTreeMap::new(),
            history: BTreeMap::new(),
            deleted: BTreeMap::new(),
            deleted_items: BTreeMap::new(),
            metadata_blob: None,
            item_blobs: BTreeMap::new(),
            autofill_blobs: BTreeMap::new(),
            cred_blobs: BTreeMap::new(),
        }
    }

    /// New empty vault with key `key` and the file key `file_key`, whose
    /// vault id it takes. Not synced.
    pub(crate) fn with_unlocked_key(key: String, file_key: &UnlockedKey) -> Self {
        Self::empty(
            file_key.vault_id(),
            key,
            None,
            file_key.file_key.clone(),
            file_key.cipher.duplicate(),
        )
    }

    /// An empty vault with key `personal`, a random file key, and no keychain
    /// involvement.
    #[cfg(test)]
    pub(crate) fn new_for_test() -> Self {
        let id = Uuid::new_v4();
        Self::empty(
            id,
            "personal".to_string(),
            None,
            VaultFileKey::new(vec![0u8; 32]),
            VaultCipher::new(id),
        )
    }

    /// An empty vault with the given file key bytes and cipher key, for tests
    /// that read the vault back from its file.
    #[cfg(test)]
    pub(crate) fn new_with_file_key_for_test(
        name: Option<String>,
        key: String,
        file_key: Vec<u8>,
        cipher_key: &[u8],
    ) -> Self {
        let id = Uuid::new_v4();
        Self::empty(
            id,
            key,
            name,
            VaultFileKey::new(file_key),
            VaultCipher::new_with_bytes(cipher_key, id),
        )
    }

    /// Add entries of every kind the vault file holds, for tests. Item `kept`
    /// is in folder `Folder` and has section `Section`. It has credential
    /// `alpha` in that section with value `two` and one previous value, the
    /// passkey credential `passkey` with [`Self::PASSKEY_VALUE_FOR_TEST`], and
    /// the deleted credential `beta`. Its autofill password is `alpha`. The
    /// deleted item `removed` has credential `gamma` and the deleted
    /// credential `delta`, and its autofill password is `gamma`. `beta`,
    /// `gamma`, and `delta` have value `secret` and the previous value `one`.
    /// Each credential has a `value-created` entry before its previous value.
    /// The vault holds one passkey site report,
    /// [`Self::signals_filled_for_test`].
    #[cfg(test)]
    pub(crate) fn fill_for_test(&mut self) {
        self.add_or_update_item("kept", "Kept").unwrap();
        self.add_or_update_item("removed", "Removed").unwrap();
        let values = [
            ("kept", "alpha", "one"),
            ("kept", "alpha", "two"),
            ("kept", "beta", "one"),
            ("kept", "beta", "secret"),
            ("removed", "gamma", "one"),
            ("removed", "gamma", "secret"),
            ("removed", "delta", "one"),
            ("removed", "delta", "secret"),
        ];
        for (item, cred, value) in values {
            self.add_or_update_item_credential(
                item,
                cred,
                cred,
                FieldKind::default(),
                SecretString::from(value.to_string()),
            )
            .unwrap();
        }
        self.add_or_update_item_credential(
            "kept",
            "passkey",
            "Passkey",
            FieldKind::Passkey,
            SecretString::from(Self::PASSKEY_VALUE_FOR_TEST.to_string()),
        )
        .unwrap();

        let folder_id = self.create_folder("Folder").id;
        self.move_item("kept", Some(folder_id)).unwrap();
        let section_id = self.create_item_section("kept", "Section").unwrap().id;
        self.move_item_credential("kept", "alpha", Some(section_id))
            .unwrap();
        for (item, cred) in [("kept", "alpha"), ("removed", "gamma")] {
            let password = self.get_item_credential(item, cred).unwrap().id;
            let autofill = ItemAutofill {
                password: Some(password),
                ..ItemAutofill::default()
            };
            self.set_item_autofill(item, autofill).unwrap();
        }
        self.update_passkey_signals(|signals| *signals = Self::signals_filled_for_test());

        self.delete_item_credential("kept", "beta").unwrap();
        self.delete_item_credential("removed", "delta").unwrap();
        self.delete_item("removed").unwrap();
    }

    /// Value of the passkey credential [`Self::fill_for_test`] adds. Its
    /// fields are not in sorted order, so a value parsed and written again as
    /// JSON would differ.
    #[cfg(test)]
    pub(crate) const PASSKEY_VALUE_FOR_TEST: &str =
        r#"{"rp_id":"example.com","credential_id":"AQID","user_name":"me","private_key":"k"}"#;

    /// Passkey site reports [`Self::fill_for_test`] adds.
    #[cfg(test)]
    pub(crate) fn signals_filled_for_test() -> SignalStore {
        use crate::secrets::vaults::passkey::signals::Report;

        let mut signals = SignalStore::new();
        let report = Report::Unknown {
            rp_id: "example.com".to_string(),
            credential_id: vec![1, 2, 3],
        };
        signals.record(report, 1_700_000_000);
        signals
    }

    /// Check that the vault holds the live entries [`Self::fill_for_test`]
    /// adds, the passkey credential included. Deleted entries are not checked.
    #[cfg(test)]
    pub(crate) fn assert_live_filled_for_test(&self) {
        let value = self.get_item_credential_secret("kept", "alpha").unwrap();
        assert_eq!(value.unwrap().expose_secret(), "two");
        let history = self.list_history("kept", "alpha").unwrap();
        assert_eq!(history.len(), 1);
        let previous = self
            .get_history_value("kept", "alpha", history[0].id)
            .unwrap();
        assert_eq!(previous.expose_secret(), "one");

        let passkey = self.get_item_credential("kept", "passkey").unwrap();
        assert_eq!(passkey.kind, FieldKind::Passkey);
        let value = self.get_item_credential_secret("kept", "passkey").unwrap();
        assert_eq!(value.unwrap().expose_secret(), Self::PASSKEY_VALUE_FOR_TEST);

        let folders = self.list_folders();
        assert_eq!(folders.len(), 1);
        assert_eq!(folders[0].title, "Folder");
        let kept = self.get_item("kept").unwrap();
        assert_eq!(kept.folder, Some(folders[0].id));
        let sections: Vec<&VaultItemSection> = kept.sections.values().collect();
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0].title, "Section");
        let alpha = self.get_item_credential("kept", "alpha").unwrap();
        assert_eq!(alpha.section, Some(sections[0].id));
        assert_eq!(kept.autofill.password, Some(alpha.id));
        assert_eq!(self.passkey_signals(), &Self::signals_filled_for_test());
    }

    /// Check that the vault holds the entries [`Self::fill_for_test`] adds.
    #[cfg(test)]
    pub(crate) fn assert_filled_for_test(&self) {
        self.assert_live_filled_for_test();
        let kept = self.get_item("kept").unwrap();

        let deleted = self.list_deleted("kept").unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].credential.key, "beta");
        let beta = &self.deleted[&deleted[0].credential.id];
        self.assert_deleted_credential_filled_for_test(
            kept.id,
            beta.overview.credential.id,
            &beta.blobs.credential.value,
            &beta.blobs.credential.history,
        );

        let deleted_items = self.list_deleted_items();
        assert_eq!(deleted_items.len(), 1);
        assert_eq!(deleted_items[0].item.key, "removed");
        let removed = &self.deleted_items[&deleted_items[0].item.id].item;
        let gamma = removed
            .overview
            .credentials
            .values()
            .find(|cred| cred.key == "gamma")
            .unwrap();
        assert_eq!(removed.overview.autofill.password, Some(gamma.id));
        let gamma_blobs = &removed.credentials[&gamma.id];
        self.assert_deleted_credential_filled_for_test(
            removed.overview.id,
            gamma.id,
            &gamma_blobs.value,
            &gamma_blobs.history,
        );
        assert_eq!(deleted_items[0].deleted_credentials.len(), 1);
        assert_eq!(deleted_items[0].deleted_credentials[0].key, "delta");
        let delta = removed.deleted.values().next().unwrap();
        self.assert_deleted_credential_filled_for_test(
            removed.overview.id,
            delta.overview.credential.id,
            &delta.blobs.credential.value,
            &delta.blobs.credential.history,
        );
    }

    /// Ids of every folder, item, section, credential, history entry, deleted
    /// item, and deleted credential, each with its kind, for tests.
    #[cfg(test)]
    pub(crate) fn entry_ids_for_test(&self) -> BTreeSet<(&'static str, Uuid)> {
        fn history(ids: &mut BTreeSet<(&'static str, Uuid)>, entries: &[HistoryEntry]) {
            ids.extend(entries.iter().map(|entry| ("history entry", entry.id)));
        }
        fn item(ids: &mut BTreeSet<(&'static str, Uuid)>, overview: &VaultItemOverview) {
            ids.extend(overview.sections.keys().map(|id| ("section", *id)));
            ids.extend(overview.credentials.keys().map(|id| ("credential", *id)));
        }

        let mut ids = BTreeSet::new();
        ids.extend(self.folders.keys().map(|id| ("folder", *id)));
        for overview in self.items.values() {
            ids.insert(("item", overview.id));
            item(&mut ids, overview);
        }
        for entries in self.history.values() {
            history(&mut ids, entries);
        }
        let mut deleted: Vec<&DeletedEntry> = self.deleted.values().collect();
        for entry in self.deleted_items.values() {
            ids.insert(("deleted item", entry.item.overview.id));
            item(&mut ids, &entry.item.overview);
            for cred in entry.item.credentials.values() {
                history(&mut ids, &cred.history);
            }
            deleted.extend(entry.item.deleted.values());
        }
        for entry in deleted {
            ids.insert(("deleted credential", entry.overview.credential.id));
            history(&mut ids, &entry.blobs.credential.history);
        }
        ids
    }

    /// Replace the autofill data of an item without any check, as a vault
    /// file written by an older build can hold it.
    #[cfg(test)]
    pub(crate) fn set_item_autofill_unchecked_for_test(
        &mut self,
        item_key: &str,
        autofill: ItemAutofill,
    ) {
        let item_id = self.item_index[item_key];
        if let Some(item) = self.items.get_mut(&item_id) {
            item.autofill = autofill;
        }
        self.autofill_blobs.remove(&item_id);
    }

    /// Reverse the stored list of previous values of a live credential.
    #[cfg(test)]
    pub(crate) fn reverse_history_for_test(&mut self, cred_id: CredentialId) {
        if let Some(history) = self.history.get_mut(&cred_id) {
            history.reverse();
        }
    }

    /// Check that a credential of a deleted entry has value `secret`, one
    /// `value-created` entry, and one replaced value `one`.
    #[cfg(test)]
    fn assert_deleted_credential_filled_for_test(
        &self,
        item_id: ItemId,
        cred_id: CredentialId,
        value: &EncryptedBlob<String>,
        history: &[HistoryEntry],
    ) {
        let value = self.cipher.decrypt_cred_value(item_id, cred_id, value);
        assert_eq!(value.unwrap().expose_secret(), "secret");
        let entries: Vec<DecryptedHistoryEntry> = history
            .iter()
            .map(|entry| self.cipher.decrypt_history_entry(item_id, cred_id, entry))
            .collect::<Result<_, _>>()
            .unwrap();
        let kinds: Vec<&HistoryKind> = entries.iter().map(|e| &e.metadata.kind).collect();
        assert_eq!(
            kinds,
            [&HistoryKind::ValueCreated, &HistoryKind::ValueUpdated]
        );
        let previous = entries[1].value.as_ref().unwrap();
        assert_eq!(previous.expose_secret(), "one");
    }

    /// Decrypt a verified vault file with the vault encryption key. Only a
    /// [`VerifiedVault`] is accepted, so the signature is checked first:
    ///
    /// ```compile_fail
    /// use axo_pass_core::secrets::keychain::managed_key::ManagedKey;
    /// use axo_pass_core::secrets::vaults::format::encrypted_vault::EncryptedVault;
    /// use axo_pass_core::secrets::vaults::model::Vault;
    ///
    /// fn open(key: ManagedKey, vault: EncryptedVault) {
    ///     let _ = Vault::from_encrypted(key, vault);
    /// }
    /// ```
    pub fn from_encrypted(
        user_encryption_key: ManagedKey,
        enc_vault: VerifiedVault,
    ) -> Result<Self, Error> {
        let vault_cipher = enc_vault.decrypt_file_key(&user_encryption_key)?;
        Self::decrypt(vault_cipher, enc_vault.into_inner())
    }

    /// Decrypt a verified vault file with a file key unwrapped earlier,
    /// without the keychain. Fails with `VaultFileKeyChanged` if the wrapped
    /// file key in `enc_vault` differs from the one `key` was unwrapped from.
    pub(crate) fn from_unlocked_key(
        key: &UnlockedKey,
        enc_vault: VerifiedVault,
    ) -> Result<Self, Error> {
        if enc_vault.file_key != key.file_key || enc_vault.id != key.cipher.vault_id() {
            return Err(Error::VaultFileKeyChanged);
        }
        Self::decrypt(key.cipher.duplicate(), enc_vault.into_inner())
    }

    /// File key of this vault, for decrypting a reloaded copy.
    pub(crate) fn unlocked_key(&self) -> UnlockedKey {
        UnlockedKey {
            file_key: self.file_key.clone(),
            cipher: self.cipher.duplicate(),
        }
    }

    /// Decrypt a bundle vault under its raw file key in `cipher`. The vault
    /// takes the id of `cipher`, holds no wrapped file key and no deleted
    /// entries, and is not synced. It cannot be unwrapped if saved, so import
    /// re-keys it first.
    pub(crate) fn from_bundled(
        cipher: VaultCipher,
        key: String,
        name: Option<String>,
        metadata: Option<EncryptedBlob<VaultMetadata>>,
        items: BTreeMap<Uuid, EncryptedVaultItem>,
    ) -> Result<Self, Error> {
        let enc_vault = EncryptedVault {
            id: cipher.vault_id(),
            key,
            name,
            generation: 0,
            replica_id: None,
            file_key: VaultFileKey::new(Vec::new()),
            metadata,
            items,
            deleted: BTreeMap::new(),
        };
        Self::decrypt(cipher, enc_vault)
    }

    /// Decrypt a vault built in memory, without a signature check.
    #[cfg(test)]
    pub(crate) fn from_encrypted_with_cipher(
        cipher: VaultCipher,
        enc_vault: EncryptedVault,
    ) -> Result<Self, Error> {
        Self::decrypt(cipher, enc_vault)
    }

    /// Copy of this vault, encrypted and decrypted again under its own file
    /// key. Secrets stay encrypted, as in any decrypted vault. A copy of a
    /// vault as loaded saves to the same file contents.
    pub(crate) fn duplicate(&self) -> Result<Self, Error> {
        Self::decrypt(self.cipher.duplicate(), self.to_encrypted(true)?)
    }

    /// Decrypt `enc_vault` under `cipher`. Callers outside this module pass
    /// a [`VerifiedVault`] or the parts of a bundle vault.
    fn decrypt(cipher: VaultCipher, enc_vault: EncryptedVault) -> Result<Self, Error> {
        let mut vault = Self::empty(
            enc_vault.id,
            enc_vault.key,
            enc_vault.name,
            enc_vault.file_key,
            cipher,
        );
        vault.generation = enc_vault.generation;
        vault.replica_id = enc_vault.replica_id;

        if let Some(blob) = enc_vault.metadata {
            let metadata = vault.cipher.decrypt_vault_metadata(&blob)?;
            for folder in &metadata.expose_secret().folders {
                vault
                    .folders
                    .insert(folder.id, VaultFolder::from_metadata(folder));
            }
            vault.passkey_signals = metadata.expose_secret().passkey_signals.clone();
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
    /// credentials, and check the info of every previous value. Secret values
    /// stay encrypted.
    fn decrypt_item(
        cipher: &VaultCipher,
        folders: &BTreeMap<FolderId, VaultFolder>,
        item_id: ItemId,
        encrypted_item: EncryptedVaultItem,
    ) -> Result<DecryptedItem, Error> {
        let metadata = cipher.decrypt_item_metadata(item_id, &encrypted_item.metadata)?;
        let mut overview = VaultItemOverview::from_metadata(item_id, metadata.expose_secret());

        // An item filed in a folder that no longer exists is unfiled. Its
        // metadata blob is not current, so the next save persists that. The
        // same holds for metadata of a 0.2.0 vault, which has no creation time.
        // MIGRATE_V1
        let mut metadata_current = !metadata.expose_secret().lacks_created_at();
        if overview.folder.is_some_and(|f| !folders.contains_key(&f)) {
            overview.folder = None;
            metadata_current = false;
        }

        if let Some(blob) = &encrypted_item.autofill {
            overview.autofill = cipher
                .decrypt_item_autofill(item_id, blob)?
                .expose_secret()
                .clone();
        }

        let mut credentials = BTreeMap::new();
        for (cred_id, encrypted_cred) in encrypted_item.credentials {
            let cred_metadata =
                cipher.decrypt_cred_metadata(item_id, cred_id, &encrypted_cred.metadata)?;
            let mut cred_overview =
                VaultItemCredentialOverview::from_metadata(cred_id, cred_metadata.expose_secret());
            cipher.check_history_metadata(item_id, cred_id, &encrypted_cred.history)?;

            // Same as above, for a credential in a missing section.
            // MIGRATE_V1
            let mut cred_metadata_current = !cred_metadata.expose_secret().lacks_created_at();
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
            cipher.check_history_metadata(
                item_id,
                cred_id,
                &encrypted_deleted.credential.history,
            )?;
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
            autofill: encrypted_item.autofill,
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
            autofill,
            credentials,
            deleted,
        } = item;
        let item_id = overview.id;

        if metadata_current {
            self.item_blobs.insert(item_id, metadata);
        }
        if let Some(blob) = autofill {
            self.autofill_blobs.insert(item_id, blob);
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
        let autofill = match &item.autofill {
            Some(blob) => Some(blob.clone()),
            None if item.overview.autofill.is_empty() => None,
            None => Some(
                self.cipher
                    .encrypt_item_autofill(item_id, &item.overview.autofill)?,
            ),
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
            autofill,
            credentials,
            deleted,
        })
    }

    /// Convert to the on disk form. Deleted items and credentials are written
    /// only if `include_deleted` is set.
    pub fn to_encrypted(&self, include_deleted: bool) -> Result<EncryptedVault, Error> {
        let mut vault = EncryptedVault {
            id: self.id,
            key: self.key.clone(),
            name: self.name.clone(),
            generation: self.generation,
            replica_id: self.replica_id,
            file_key: self.file_key.clone(),
            metadata: None,
            items: BTreeMap::new(),
            deleted: BTreeMap::new(),
        };

        vault.set_metadata(
            &self.cipher,
            self.metadata_blob.as_ref(),
            &self.vault_metadata(),
        )?;

        for item_overview in self.items.values() {
            let existing_metadata = self.item_blobs.get(&item_overview.id);
            let existing_autofill = self.autofill_blobs.get(&item_overview.id);
            vault.add_item(
                &self.cipher,
                existing_metadata,
                existing_autofill,
                item_overview,
            )?;

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

    /// Plaintext of the vault metadata blob.
    fn vault_metadata(&self) -> VaultMetadata {
        VaultMetadata {
            folders: self
                .folders
                .values()
                .map(VaultFolder::to_metadata)
                .collect(),
            passkey_signals: self.passkey_signals.clone(),
        }
    }

    /// Copy of this vault with every blob encrypted again under a new random
    /// file key. Deleted items and deleted credentials are included. This
    /// vault is unchanged.
    ///
    /// If `new_id` is set, the copy takes that vault id, and every blob is
    /// bound to it. The copy is then a new vault that is not synced, so it has
    /// generation 0 and no replica id. Otherwise the id, generation, and
    /// replica id are kept. The vault key, name, and every item, credential,
    /// history entry, folder, and section id are kept in both cases.
    ///
    /// `wrap` receives the raw new file key and returns the form the vault
    /// file stores. The raw key is zeroized once the copy cipher is built. The
    /// cipher holds its own copy of the key in a `SecretBox`.
    ///
    /// Metadata blobs are encrypted from the decrypted overviews, so fields
    /// this build does not read are dropped. Values, previous values, and
    /// deleted info and history metadata are decrypted under the old key and
    /// encrypted again. A blob that fails to decrypt fails the call.
    pub fn rekeyed(
        &self,
        new_id: Option<Uuid>,
        wrap: impl FnOnce(&[u8]) -> Result<VaultFileKey, Error>,
    ) -> Result<Self, Error> {
        self.rekeyed_in(RekeyScope::All, new_id, wrap)
    }

    /// Copy of this vault as [`Self::rekeyed`] builds it, holding only the
    /// entries in `scope`. Entries outside `scope` are not decrypted.
    fn rekeyed_in(
        &self,
        scope: RekeyScope,
        new_id: Option<Uuid>,
        wrap: impl FnOnce(&[u8]) -> Result<VaultFileKey, Error>,
    ) -> Result<Self, Error> {
        let id = new_id.unwrap_or(self.id);
        let raw_key = Zeroizing::new(Aes256Gcm::generate_key(OsRng));
        let file_key = wrap(&raw_key)?;
        let cipher = VaultCipher::new_with_bytes(&raw_key, id);
        drop(raw_key);

        let mut vault = Self::empty(id, self.key.clone(), self.name.clone(), file_key, cipher);
        if new_id.is_none() {
            vault.generation = self.generation;
            vault.replica_id = self.replica_id;
        }
        let (from, to) = (&self.cipher, &vault.cipher);

        let mut items = self.items.clone();
        let mut item_credential_index = self.item_credential_index.clone();
        if matches!(scope, RekeyScope::Live { passkeys: false }) {
            for item in items.values_mut() {
                item.credentials
                    .retain(|_, cred| !matches!(cred.kind, FieldKind::Passkey));
            }
            item_credential_index
                .retain(|_, (item_id, cred_id)| items[item_id].credentials.contains_key(cred_id));
        }

        // Every cache is rebuilt under the new key, so no old blob is kept.
        let metadata = self.vault_metadata();
        let metadata_blob = if metadata.is_empty() {
            None
        } else {
            Some(to.encrypt_vault_metadata(&metadata)?)
        };
        let mut item_blobs = BTreeMap::new();
        let mut autofill_blobs = BTreeMap::new();
        let mut cred_blobs = BTreeMap::new();
        let mut secrets = BTreeMap::new();
        let mut history = BTreeMap::new();
        for (item_id, item) in &items {
            item_blobs.insert(
                *item_id,
                to.encrypt_item_metadata(*item_id, &item.to_metadata())?,
            );
            if !item.autofill.is_empty() {
                autofill_blobs.insert(
                    *item_id,
                    to.encrypt_item_autofill(*item_id, &item.autofill)?,
                );
            }
            for (cred_id, cred) in &item.credentials {
                cred_blobs.insert(
                    *cred_id,
                    to.encrypt_cred_metadata(*item_id, *cred_id, &cred.to_metadata())?,
                );
                if let Some(value) = self.secrets.get(cred_id) {
                    secrets.insert(
                        *cred_id,
                        from.rekey_cred_value(to, *item_id, *cred_id, value)?,
                    );
                }
                if let Some(entries) = self.history.get(cred_id) {
                    history.insert(
                        *cred_id,
                        from.rekey_history(to, *item_id, *cred_id, entries)?,
                    );
                }
            }
        }
        let (deleted, deleted_items) = match scope {
            RekeyScope::All => (
                self.deleted
                    .iter()
                    .map(|(cred_id, entry)| Ok((*cred_id, entry.rekeyed(from, to)?)))
                    .collect::<Result<_, Error>>()?,
                self.deleted_items
                    .iter()
                    .map(|(item_id, entry)| Ok((*item_id, entry.rekeyed(from, to)?)))
                    .collect::<Result<_, Error>>()?,
            ),
            RekeyScope::Live { .. } => (BTreeMap::new(), BTreeMap::new()),
        };

        vault.folders = self.folders.clone();
        vault.passkey_signals = self.passkey_signals.clone();
        vault.items = items;
        vault.item_index = self.item_index.clone();
        vault.item_credential_index = item_credential_index;
        vault.secrets = secrets;
        vault.history = history;
        vault.deleted = deleted;
        vault.deleted_items = deleted_items;
        vault.metadata_blob = metadata_blob;
        vault.item_blobs = item_blobs;
        vault.autofill_blobs = autofill_blobs;
        vault.cred_blobs = cred_blobs;
        Ok(vault)
    }

    /// Build a [`BundledVault`] for export. `key` is the preferred import key,
    /// `bundle_cipher` wraps the raw file key. Passkey credentials are left out
    /// unless `include_passkeys` is set.
    ///
    /// Deleted items and credentials are not exported.
    ///
    /// Each export encrypts every exported blob again under a new random file
    /// key, so the bundle never holds the file key of this vault. The vault id
    /// is kept. Entries left out are not decrypted, so a deleted entry or a
    /// left out passkey whose blob fails to decrypt does not fail the export.
    /// This vault is unchanged.
    ///
    /// The bundled vault holds no file blobs. Records name their blobs, which
    /// [`Self::to_bundled_vault_with_blobs`] lists.
    pub fn to_bundled_vault(
        &self,
        key: Option<String>,
        bundle_id: Uuid,
        bundle_cipher: &Aes256Gcm,
        include_passkeys: bool,
    ) -> Result<BundledVault, Error> {
        self.to_bundled_vault_with_blobs(key, bundle_id, bundle_cipher, include_passkeys)
            .map(|(bundled, _)| bundled)
    }

    /// Same as [`Self::to_bundled_vault`], with the blobs that the exported
    /// records name. Trashed files are not exported, so their blobs are not
    /// listed. The caller adds the blob bytes to `blobs` of the result.
    pub(crate) fn to_bundled_vault_with_blobs(
        &self,
        key: Option<String>,
        bundle_id: Uuid,
        bundle_cipher: &Aes256Gcm,
        include_passkeys: bool,
    ) -> Result<(BundledVault, BTreeSet<FileHash>), Error> {
        // A bundle holds no wrapped file key, so the copy gets an empty one.
        // The copy is dropped at return and is never saved.
        let scope = RekeyScope::Live {
            passkeys: include_passkeys,
        };
        let copy = self.rekeyed_in(scope, None, |_| Ok(VaultFileKey::new(Vec::new())))?;
        let encrypted_vault = copy.to_encrypted(false)?;
        let wrapped_file_key = copy.cipher.wrap_raw_key(
            bundle_cipher,
            ExportedBundle::file_key_aad(bundle_id, copy.id),
        )?;
        let blobs = copy.file_blobs()?;
        let bundled = BundledVault {
            id: encrypted_vault.id,
            name: encrypted_vault.name,
            default_key: key,
            wrapped_file_key,
            metadata: encrypted_vault.metadata,
            items: encrypted_vault.items,
            blobs: BTreeMap::new(),
        };
        Ok((bundled, blobs))
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Vault key, as stored in the vault file.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Set the vault key. The caller validates it.
    pub(crate) fn set_key(&mut self, key: String) {
        self.key = key;
    }

    /// Sync generation `v` the vault was saved with. 0 if the vault is not
    /// synced.
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    /// Replica id of this copy of the vault. `None` if the vault is not
    /// synced.
    pub(crate) fn replica_id(&self) -> Option<Uuid> {
        self.replica_id
    }

    /// Set the sync generation and the replica id written to the vault file.
    pub(crate) fn set_sync(&mut self, generation: u64, replica_id: Option<Uuid>) {
        self.generation = generation;
        self.replica_id = replica_id;
    }

    pub fn list_folders(&self) -> Vec<&VaultFolder> {
        self.folders.values().collect()
    }

    pub fn get_folder(&self, folder_id: FolderId) -> Result<&VaultFolder, Error> {
        self.folders
            .get(&folder_id)
            .ok_or_else(|| Error::InvalidFolder(folder_id.to_string()))
    }

    /// Site reports about the passkeys in this vault.
    pub fn passkey_signals(&self) -> &SignalStore {
        &self.passkey_signals
    }

    /// Decrypted entries of this vault, live and trashed, for the sync diff.
    ///
    /// Every credential value and previous value is decrypted. A credential
    /// with no value reads as empty.
    pub(crate) fn sync_entries(&self) -> Result<SyncEntries<'_>, Error> {
        let Self {
            // Local to this Mac. Vault ids and keys are not synced.
            id: _,
            key: _,
            name,
            // Wrapped file key of this file. Each Mac has its own.
            file_key: _,
            // Decrypts the values below. Not mapped.
            cipher,
            // Sync fields of the vault file, written by the transaction.
            generation: _,
            replica_id: _,
            folders,
            passkey_signals,
            items,
            // Indexes by key, derived from `items`.
            item_index: _,
            item_credential_index: _,
            secrets,
            history,
            deleted,
            deleted_items,
            // Caches of encrypted blobs, derived from the fields above.
            metadata_blob: _,
            item_blobs: _,
            autofill_blobs: _,
            cred_blobs: _,
        } = self;

        let mut entries = SyncEntries {
            name: name.as_deref(),
            folders,
            passkey_signals,
            items: Vec::new(),
            credentials: Vec::new(),
        };
        for item in items.values() {
            entries.items.push(SyncItemEntry {
                overview: item,
                trashed: None,
            });
            for cred in item.credentials.values() {
                let history = history.get(&cred.id).map_or(&[][..], Vec::as_slice);
                entries.credentials.push(Self::sync_credential_entry(
                    cipher,
                    item.id,
                    cred,
                    secrets.get(&cred.id),
                    history,
                    None,
                )?);
            }
        }
        for entry in deleted.values() {
            entries
                .credentials
                .push(Self::sync_trashed_credential_entry(cipher, entry)?);
        }
        for entry in deleted_items.values() {
            let DeletedItemEntry {
                item,
                info,
                // Copy of the time in `info`.
                deleted_at: _,
            } = entry;
            let DecryptedItem {
                overview,
                // Blobs of the decrypted overview.
                metadata: _,
                metadata_current: _,
                autofill: _,
                credentials,
                deleted,
            } = item;
            let info = cipher.decrypt_deleted_item_info(overview.id, info)?;
            entries.items.push(SyncItemEntry {
                overview,
                trashed: Some(DeletedInfo {
                    deleted_at: info.expose_secret().deleted_at,
                    role: info.expose_secret().role,
                }),
            });
            for cred in overview.credentials.values() {
                let blobs = credentials.get(&cred.id);
                entries.credentials.push(Self::sync_credential_entry(
                    cipher,
                    overview.id,
                    cred,
                    blobs.map(|blobs| &blobs.value),
                    blobs.map_or(&[][..], |blobs| &blobs.history),
                    None,
                )?);
            }
            for entry in deleted.values() {
                entries
                    .credentials
                    .push(Self::sync_trashed_credential_entry(cipher, entry)?);
            }
        }
        Ok(entries)
    }

    /// Sync entry of a trashed credential.
    fn sync_trashed_credential_entry<'a>(
        cipher: &VaultCipher,
        entry: &'a DeletedEntry,
    ) -> Result<SyncCredentialEntry<'a>, Error> {
        let DeletedEntry { blobs, overview } = entry;
        let info =
            cipher.decrypt_deleted_info(overview.item_id, overview.credential.id, &blobs.info)?;
        Self::sync_credential_entry(
            cipher,
            overview.item_id,
            &overview.credential,
            Some(&blobs.credential.value),
            &blobs.credential.history,
            Some(DeletedInfo {
                deleted_at: info.expose_secret().deleted_at,
                role: info.expose_secret().role,
            }),
        )
    }

    /// Sync entry of a credential of item `item_id`, with its value and
    /// previous values decrypted. No `value` reads as empty.
    fn sync_credential_entry<'a>(
        cipher: &VaultCipher,
        item_id: ItemId,
        cred: &'a VaultItemCredentialOverview,
        value: Option<&EncryptedBlob<String>>,
        history: &[HistoryEntry],
        trashed: Option<DeletedInfo>,
    ) -> Result<SyncCredentialEntry<'a>, Error> {
        let value = match value {
            Some(blob) => cipher.decrypt_cred_value(item_id, cred.id, blob)?,
            None => SecretBox::new(Box::default()),
        };
        let history = history
            .iter()
            .map(|entry| cipher.decrypt_history_entry(item_id, cred.id, entry))
            .collect::<Result<_, Error>>()?;
        Ok(SyncCredentialEntry {
            item: item_id,
            overview: cred,
            trashed,
            value,
            history,
        })
    }

    /// Change the site reports stored in this vault.
    pub fn update_passkey_signals<R>(&mut self, change: impl FnOnce(&mut SignalStore) -> R) -> R {
        self.metadata_blob = None;
        change(&mut self.passkey_signals)
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

    /// Add an item with the id `id`, which is for an item that has an id
    /// outside the vault. Fails with `DuplicateItemKey` if the key is taken,
    /// and with `InvalidItemKey` if a live or deleted item has the id.
    pub fn add_item_with_id(
        &mut self,
        id: ItemId,
        item_key: &str,
        item_title: &str,
    ) -> Result<&VaultItemOverview, Error> {
        if self.items.contains_key(&id) || self.deleted_items.contains_key(&id) {
            return Err(Error::InvalidItemKey(format!("item {id} exists")));
        }
        let mut overview = VaultItemOverview::try_new(item_title, item_key)?;
        if self.item_index.contains_key(&overview.key) {
            return Err(Error::DuplicateItemKey(overview.key));
        }
        overview.id = id;
        self.item_index.insert(overview.key.clone(), id);
        self.item_blobs.remove(&id);
        Ok(self.items.entry(id).or_insert(overview))
    }

    /// Change the key of an item. Its credentials keep their keys. Fails with
    /// `DuplicateItemKey` if `new_key` belongs to another item.
    pub fn change_item_key(
        &mut self,
        item_key: &str,
        new_key: &str,
    ) -> Result<&VaultItemOverview, Error> {
        let item_id = *self.get_item_id(item_key)?;
        let new_key =
            normalized_key(new_key).ok_or_else(|| Error::InvalidItemKey(new_key.to_string()))?;
        if new_key != item_key {
            if self.item_index.contains_key(&new_key) {
                return Err(Error::DuplicateItemKey(new_key));
            }
            let item = self
                .items
                .get_mut(&item_id)
                .ok_or_else(|| Error::InvalidItemKey(item_key.to_string()))?;
            item.key = new_key.clone();
            for cred in item.credentials.values() {
                let id = self
                    .item_credential_index
                    .remove(&(item_key.to_string(), cred.key.clone()));
                if let Some(id) = id {
                    self.item_credential_index
                        .insert((new_key.clone(), cred.key.clone()), id);
                }
            }
            self.item_index.remove(item_key);
            self.item_index.insert(new_key, item_id);
            self.item_blobs.remove(&item_id);
        }
        self.get_item_by_id(item_id)
    }

    /// Plaintext copy of a live item for [`Self::import_item`] on another
    /// vault. It holds the credential values and previous values. The item's
    /// deleted credentials are not copied. An item with a file credential
    /// fails with `FileMoveRefused`, since its blobs belong to this vault.
    pub fn export_item(&self, item_key: &str) -> Result<ItemTransfer, Error> {
        let overview = self.get_item(item_key)?.clone();
        if overview
            .credentials
            .values()
            .any(|cred| matches!(cred.kind, FieldKind::File))
        {
            return Err(Error::FileMoveRefused(item_key.to_string()));
        }
        let item_id = overview.id;
        let mut values = BTreeMap::new();
        let mut history = BTreeMap::new();
        for cred_id in overview.credentials.keys() {
            if let Some(blob) = self.secrets.get(cred_id) {
                values.insert(
                    *cred_id,
                    self.cipher.decrypt_cred_value(item_id, *cred_id, blob)?,
                );
            }
            let mut entries = Vec::new();
            for entry in self.history.get(cred_id).into_iter().flatten() {
                entries.push(
                    self.cipher
                        .decrypt_history_entry(item_id, *cred_id, entry)?,
                );
            }
            if !entries.is_empty() {
                history.insert(*cred_id, entries);
            }
        }
        Ok(ItemTransfer {
            overview,
            values,
            history,
        })
    }

    /// Add an item exported from another vault. The item keeps its id, its
    /// credential ids, and its previous values. It is unfiled, since folders
    /// belong to a vault. It gets `new_key` if given. Fails with
    /// `DuplicateItemKey` if the resulting key is taken.
    pub fn import_item(
        &mut self,
        transfer: ItemTransfer,
        new_key: Option<&str>,
    ) -> Result<&VaultItemOverview, Error> {
        let ItemTransfer {
            mut overview,
            values,
            history,
        } = transfer;
        let item_id = overview.id;
        let key = match new_key {
            Some(key) => {
                normalized_key(key).ok_or_else(|| Error::InvalidItemKey(key.to_string()))?
            },
            None => overview.key.clone(),
        };
        if self.item_index.contains_key(&key) {
            return Err(Error::DuplicateItemKey(key));
        }
        if self.items.contains_key(&item_id) {
            return Err(Error::InvalidItemKey(format!(
                "item {item_id} is already in this vault"
            )));
        }
        overview.key = key;
        overview.folder = None;

        // Encrypt everything for this vault before changing anything.
        let mut secrets = BTreeMap::new();
        let mut histories = BTreeMap::new();
        for cred_id in overview.credentials.keys() {
            if let Some(value) = values.get(cred_id) {
                secrets.insert(
                    *cred_id,
                    self.cipher
                        .encrypt_cred_value(item_id, *cred_id, value.expose_secret())?,
                );
            }
            let mut entries = Vec::new();
            for entry in history.get(cred_id).into_iter().flatten() {
                entries.push(
                    self.cipher
                        .encrypt_history_entry(item_id, *cred_id, entry)?,
                );
            }
            if !entries.is_empty() {
                histories.insert(*cred_id, entries);
            }
        }

        for cred in overview.credentials.values() {
            self.item_credential_index
                .insert((overview.key.clone(), cred.key.clone()), (item_id, cred.id));
        }
        self.secrets.extend(secrets);
        self.history.extend(histories);
        self.item_index.insert(overview.key.clone(), item_id);
        self.items.insert(item_id, overview);
        self.items
            .get(&item_id)
            .ok_or_else(|| Error::InvalidItemKey(item_id.to_string()))
    }

    /// Set the display category of an item, such as `login`.
    pub fn set_item_category(
        &mut self,
        item_key: &str,
        category: Option<String>,
    ) -> Result<(), Error> {
        self.edit_item(item_key, |item| {
            item.category = category;
            Ok(())
        })
    }

    /// Set the creation time of an item, in Unix seconds.
    pub fn set_item_created_at(&mut self, item_key: &str, at: i64) -> Result<(), Error> {
        self.edit_item(item_key, |item| {
            item.created_at = at;
            Ok(())
        })
    }

    /// Set the creation time of a credential, in Unix seconds.
    pub fn set_item_credential_created_at(
        &mut self,
        item_key: &str,
        cred_key: &str,
        at: i64,
    ) -> Result<(), Error> {
        let (item_id, cred_id) = self.get_credential_ids(item_key, cred_key)?;
        let cred = self
            .items
            .get_mut(&item_id)
            .and_then(|item| item.credentials.get_mut(&cred_id))
            .ok_or_else(|| Error::InvalidCredentialKey(format!("{item_key}/{cred_key}")))?;
        cred.created_at = at;
        self.cred_blobs.remove(&cred_id);
        Ok(())
    }

    /// Replace an item's autofill data. Rejects a role slot that points at a
    /// credential outside the item, one credential in both slots, and two
    /// websites with one URL.
    pub fn set_item_autofill(
        &mut self,
        item_key: &str,
        autofill: ItemAutofill,
    ) -> Result<(), Error> {
        let item_id = *self.get_item_id(item_key)?;
        let item = self
            .items
            .get_mut(&item_id)
            .ok_or_else(|| Error::InvalidItemKey(item_key.to_string()))?;
        if autofill.has_shared_slot() {
            return Err(Error::InvalidAutofill(
                "one credential cannot be both the username and the password".to_string(),
            ));
        }
        let mut urls = BTreeSet::new();
        if let Some(website) = autofill
            .websites
            .iter()
            .find(|website| !urls.insert(website.url.as_str()))
        {
            return Err(Error::InvalidAutofill(format!(
                "two websites have the URL {}",
                website.url
            )));
        }
        for slot in [autofill.username, autofill.password, autofill.totp]
            .into_iter()
            .flatten()
        {
            if !item.credentials.contains_key(&slot) {
                return Err(Error::InvalidAutofill(format!(
                    "credential {slot} is not in item {item_key}"
                )));
            }
        }
        item.autofill = autofill;
        self.autofill_blobs.remove(&item_id);
        Ok(())
    }

    /// Remove each later website of an item with two websites of one URL.
    /// The first website of each URL by order stays. Live and trashed items
    /// are changed. Returns the ids of the changed items, in id order.
    pub(crate) fn remove_duplicate_websites(&mut self) -> Vec<ItemId> {
        let mut changed = Vec::new();
        for item in self.items.values_mut() {
            if item.autofill.remove_duplicate_websites() {
                self.autofill_blobs.remove(&item.id);
                changed.push(item.id);
            }
        }
        for entry in self.deleted_items.values_mut() {
            let item = &mut entry.item;
            if item.overview.autofill.remove_duplicate_websites() {
                item.autofill = None;
                changed.push(item.overview.id);
            }
        }
        changed.sort();
        changed
    }

    pub fn get_item_by_id(&self, item_id: Uuid) -> Result<&VaultItemOverview, Error> {
        self.items
            .get(&item_id)
            .ok_or_else(|| Error::InvalidItemKey(item_id.to_string()))
    }

    pub fn get_item_credential_by_id(
        &self,
        item_id: Uuid,
        cred_id: Uuid,
    ) -> Result<&VaultItemCredentialOverview, Error> {
        self.get_item_by_id(item_id)?
            .credentials
            .get(&cred_id)
            .ok_or_else(|| Error::InvalidCredentialKey(format!("{item_id}/{cred_id}")))
    }

    pub fn get_item_credential_secret_by_id(
        &self,
        item_id: Uuid,
        cred_id: Uuid,
    ) -> Result<Option<SecretBox<String>>, Error> {
        self.get_item_credential_by_id(item_id, cred_id)?;
        let Some(encrypted_secret) = self.secrets.get(&cred_id) else {
            return Ok(None);
        };
        let plaintext = self
            .cipher
            .decrypt_cred_value(item_id, cred_id, encrypted_secret)?;
        Ok(Some(plaintext))
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
        let autofill = self.autofill_blobs.get(&item_id).cloned();
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
        let info = self.cipher.encrypt_deleted_item_info(
            item_id,
            &DeletedInfo {
                deleted_at,
                role: None,
            },
        )?;

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
        self.autofill_blobs.remove(&item_id);

        self.deleted_items.insert(
            item_id,
            DeletedItemEntry {
                item: DecryptedItem {
                    overview,
                    metadata,
                    metadata_current: true,
                    autofill,
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

    /// History entry for writing `new_value` over the current value of a
    /// credential. A non-empty value over no value or an empty value is
    /// `value-created`. A different value over a non-empty value is
    /// `value-updated`, holding the replaced value. Any other write has no
    /// entry.
    fn value_history_entry(
        &self,
        item_id: ItemId,
        cred_id: CredentialId,
        new_value: &str,
    ) -> Result<Option<HistoryEntry>, Error> {
        let current = match self.secrets.get(&cred_id) {
            Some(blob) => Some(self.cipher.decrypt_cred_value(item_id, cred_id, blob)?),
            None => None,
        };
        let current = current.filter(|value| !value.expose_secret().is_empty());
        let (kind, value) = match current {
            None if new_value.is_empty() => return Ok(None),
            None => (HistoryKind::ValueCreated, None),
            Some(current) if current.expose_secret() == new_value => return Ok(None),
            Some(current) => (HistoryKind::ValueUpdated, Some(current)),
        };
        let entry = DecryptedHistoryEntry {
            id: Uuid::new_v4(),
            metadata: HistoryMetadata {
                at: OffsetDateTime::now_utc().unix_timestamp(),
                kind,
            },
            value,
        };
        Ok(Some(
            self.cipher
                .encrypt_history_entry(item_id, cred_id, &entry)?,
        ))
    }

    /// Add `value-updated` history entries to a credential. `entries` are
    /// replaced values with the Unix seconds of the replacement, oldest first.
    /// The entries are placed before the stored entries, so the stored order
    /// stays oldest first if the stored entries are newer. The current value
    /// is not changed.
    pub(crate) fn add_history_values(
        &mut self,
        item_key: &str,
        cred_key: &str,
        entries: &[(i64, SecretString)],
    ) -> Result<(), Error> {
        let (item_id, cred_id) = self.get_credential_ids(item_key, cred_key)?;
        let encrypted = entries
            .iter()
            .map(|(at, value)| {
                let entry = DecryptedHistoryEntry {
                    id: Uuid::new_v4(),
                    metadata: HistoryMetadata {
                        at: *at,
                        kind: HistoryKind::ValueUpdated,
                    },
                    value: Some(SecretBox::new(Box::new(value.expose_secret().to_string()))),
                };
                self.cipher.encrypt_history_entry(item_id, cred_id, &entry)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if !encrypted.is_empty() {
            self.history
                .entry(cred_id)
                .or_default()
                .splice(0..0, encrypted);
        }
        Ok(())
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
        self.put_item_credential(item_key, cred_key, cred_title, cred_kind, cred_value, true)
    }

    /// Replace the title, kind, and value of an existing credential. The value
    /// change is not recorded in history. Fails with
    /// `InvalidCredentialKey` if the item has no credential with this key.
    pub fn replace_item_credential(
        &mut self,
        item_key: &str,
        cred_key: &str,
        cred_title: &str,
        cred_kind: FieldKind,
        cred_value: SecretString,
    ) -> Result<&VaultItemCredentialOverview, Error> {
        self.get_item_credential(item_key, cred_key)?;
        self.put_item_credential(item_key, cred_key, cred_title, cred_kind, cred_value, false)
    }

    /// Add a credential, or update the title, kind, and value of an existing
    /// one. The value change is recorded in history if `keep_replaced` is set.
    fn put_item_credential(
        &mut self,
        item_key: &str,
        cred_key: &str,
        cred_title: &str,
        cred_kind: FieldKind,
        cred_value: SecretString,
        keep_replaced: bool,
    ) -> Result<&VaultItemCredentialOverview, Error> {
        // get existing cred by key or create new one
        let cred_overview = match self.get_item_credential(item_key, cred_key) {
            Ok(existing) => {
                files::check_kind_change(&existing.key, &existing.kind, &cred_kind)?;
                fields::check_ssh_key_kind_change(&existing.key, &existing.kind, &cred_kind)?;
                VaultItemCredentialOverview {
                    title: cred_title.to_string(),
                    kind: cred_kind,
                    ..existing.clone()
                }
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
        let replaced = if keep_replaced {
            self.value_history_entry(item_id, cred_id, secret)?
        } else {
            None
        };
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

        if let Some(kind) = &update.kind {
            files::check_kind_change(&cred.key, &cred.kind, kind)?;
            fields::check_ssh_key_kind_change(&cred.key, &cred.kind, kind)?;
        }
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

    /// Record a use of a credential at `at`. Writes only if no use is stored,
    /// or if the stored use falls on an earlier date in `zone`. Only the
    /// credential metadata blob is re-encrypted. The value and its history are
    /// unchanged. Returns whether the time was written.
    pub fn mark_credential_used(
        &mut self,
        item_key: &str,
        cred_key: &str,
        at: i64,
        zone: &TimeZone,
    ) -> Result<bool, Error> {
        let (item_id, cred_id) = self.get_credential_ids(item_key, cred_key)?;
        let cred = self
            .items
            .get_mut(&item_id)
            .and_then(|item| item.credentials.get_mut(&cred_id))
            .ok_or_else(|| Error::InvalidCredentialKey(format!("{item_key}/{cred_key}")))?;
        if !last_used::is_later_day(cred.last_used_day_at, at, zone) {
            return Ok(false);
        }
        cred.last_used_day_at = Some(at);
        self.cred_blobs.remove(&cred_id);
        Ok(true)
    }

    /// Mark a credential as deleted. Its key is free for reuse. The
    /// encrypted value is kept unchanged.
    pub fn delete_item_credential(&mut self, item_key: &str, cred_key: &str) -> Result<(), Error> {
        let (item_id, cred_id) = self.get_credential_ids(item_key, cred_key)?;
        let credential = self.get_item_credential(item_key, cred_key)?.clone();

        // Build the deleted entry before changing anything.
        let credential_blobs = self.live_credential_blobs(item_id, &credential)?;
        let deleted_at = OffsetDateTime::now_utc().unix_timestamp();
        let role = self
            .items
            .get(&item_id)
            .and_then(|item| item.autofill.role_of(cred_id));
        let info = self.cipher.encrypt_deleted_info(
            item_id,
            cred_id,
            &DeletedInfo { deleted_at, role },
        )?;

        // remove from item
        let item = self
            .items
            .get_mut(&item_id)
            .ok_or_else(|| Error::InvalidItemKey(item_key.to_string()))?;
        item.credentials.remove(&cred_id);

        // Clear the role slot pointing at the deleted credential. The role is
        // kept in the deleted info for a restore.
        if role.is_some() {
            item.autofill.clear_credential(cred_id);
            self.autofill_blobs.remove(&item_id);
        }

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

        let role = match self.deleted.get(&cred_id) {
            Some(entry) => {
                self.cipher
                    .decrypt_deleted_info(item_id, cred_id, &entry.blobs.info)?
                    .expose_secret()
                    .role
            },
            None => None,
        };
        let entry = self
            .deleted
            .remove(&cred_id)
            .ok_or_else(|| Error::InvalidCredentialKey(format!("{item_key}/{cred_id}")))?;
        let DeletedCredential {
            credential: blobs, ..
        } = entry.blobs;
        // Give the role back unless another credential took it meanwhile.
        if let Some(role) = role
            && item.autofill.fill_empty_slot(role, cred_id)
        {
            self.autofill_blobs.remove(&item_id);
        }
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

    /// Previous values of a credential, most recently replaced first. These
    /// are the `value-updated` entries of its history. Entries whose metadata
    /// fails to decrypt are skipped and logged.
    pub fn list_history(
        &self,
        item_key: &str,
        cred_key: &str,
    ) -> Result<Vec<HistoryOverview>, Error> {
        let (item_id, cred_id) = self.get_credential_ids(item_key, cred_key)?;
        Ok(self
            .history_overviews(item_id, cred_id, self.history.get(&cred_id))
            .into_iter()
            .filter(|entry| entry.kind == HistoryKind::ValueUpdated)
            .rev()
            .collect())
    }

    /// History of a live item, newest first. Covers the item creation, the
    /// history entries of its live and deleted credentials, and the deletion
    /// of its deleted credentials. Entries whose metadata fails to decrypt are
    /// skipped and logged.
    pub fn item_history(&self, item_key: &str) -> Result<Vec<ItemHistoryEvent<'_>>, Error> {
        let item = self.get_item(item_key)?;
        let mut events = vec![ItemHistoryEvent {
            at: item.created_at,
            change: ItemChange::ItemCreated,
            credential: None,
            credential_deleted: false,
        }];
        for cred in item.credentials.values() {
            let history = self.history.get(&cred.id);
            events.extend(self.credential_history_events(item.id, cred, history, false));
        }
        let deleted: Vec<&DeletedEntry> = self
            .deleted
            .values()
            .filter(|entry| entry.overview.item_id == item.id)
            .collect();
        for entry in &deleted {
            let cred = &entry.overview.credential;
            let history = Some(&entry.blobs.credential.history);
            events.extend(self.credential_history_events(item.id, cred, history, true));
        }
        for entry in deleted {
            events.push(ItemHistoryEvent {
                at: entry.overview.deleted_at,
                change: ItemChange::CredentialDeleted,
                credential: Some(&entry.overview.credential),
                credential_deleted: true,
            });
        }
        // Stable sort, so events with the same time stay in the order added,
        // and appear reversed after the reverse.
        events.sort_by_key(|event| event.at);
        events.reverse();
        Ok(events)
    }

    /// Item history events of the history entries of credential `cred`.
    fn credential_history_events<'a>(
        &self,
        item_id: ItemId,
        cred: &'a VaultItemCredentialOverview,
        history: Option<&Vec<HistoryEntry>>,
        credential_deleted: bool,
    ) -> Vec<ItemHistoryEvent<'a>> {
        self.history_overviews(item_id, cred.id, history)
            .into_iter()
            .map(|entry| ItemHistoryEvent {
                at: entry.at,
                change: ItemChange::History {
                    id: entry.id,
                    kind: entry.kind,
                },
                credential: Some(cred),
                credential_deleted,
            })
            .collect()
    }

    /// History entries of a credential, oldest first, without values. Entries
    /// whose metadata fails to decrypt are skipped and logged.
    fn history_overviews(
        &self,
        item_id: ItemId,
        cred_id: CredentialId,
        history: Option<&Vec<HistoryEntry>>,
    ) -> Vec<HistoryOverview> {
        let mut entries = Vec::new();
        for entry in history.into_iter().flatten() {
            let metadata = match self.cipher.decrypt_history_metadata(
                item_id,
                cred_id,
                entry.id,
                &entry.metadata,
            ) {
                Ok(metadata) => metadata,
                Err(e) => {
                    let id = entry.id;
                    log::warn!("Skipping history entry {id} of credential {cred_id}: {e}");
                    continue;
                },
            };
            let metadata = metadata.expose_secret();
            entries.push(HistoryOverview {
                id: entry.id,
                at: metadata.at,
                kind: metadata.kind.clone(),
            });
        }
        entries
    }

    /// Value held by a history entry of a credential. Fails with
    /// `InvalidHistoryEntry` if the entry holds no value.
    pub fn get_history_value(
        &self,
        item_key: &str,
        cred_key: &str,
        history_id: Uuid,
    ) -> Result<SecretBox<String>, Error> {
        let (item_id, cred_id) = self.get_credential_ids(item_key, cred_key)?;
        let entry = self.history_entry(cred_id, history_id)?;
        let blob = entry
            .value
            .as_ref()
            .ok_or_else(|| Error::InvalidHistoryEntry(history_id.to_string()))?;
        self.cipher
            .decrypt_history_value(item_id, cred_id, history_id, blob)
    }

    /// Make a previous value the current value. The entry is removed from the
    /// history, and the value change is recorded in it.
    pub fn restore_history_value(
        &mut self,
        item_key: &str,
        cred_key: &str,
        history_id: Uuid,
    ) -> Result<(), Error> {
        let (item_id, cred_id) = self.get_credential_ids(item_key, cred_key)?;
        let value = self.get_history_value(item_key, cred_key, history_id)?;
        let replaced = self.value_history_entry(item_id, cred_id, value.expose_secret())?;
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

    /// Move a credential to another item, with its value and previous values.
    /// The credential keeps its id. It gets `new_key` and goes in `section_id`
    /// of the destination, after the credentials there that have a position.
    /// The value and history are encrypted again, since their blobs are bound
    /// to the item. A role slot of the source item that points at the
    /// credential is cleared. Fails with `DuplicateCredentialKey` if the
    /// destination already has `new_key`.
    pub fn transfer_item_credential(
        &mut self,
        item_key: &str,
        cred_key: &str,
        dest_item_key: &str,
        new_key: &str,
        section_id: Option<SectionId>,
    ) -> Result<&VaultItemCredentialOverview, Error> {
        let (item_id, cred_id) = self.get_credential_ids(item_key, cred_key)?;
        let dest_item_id = *self.get_item_id(dest_item_key)?;
        if dest_item_id == item_id {
            return Err(Error::InvalidItemKey(format!(
                "cannot move {item_key}/{cred_key} into its own item"
            )));
        }
        let new_key = normalized_key(new_key)
            .ok_or_else(|| Error::InvalidCredentialKey(new_key.to_string()))?;
        if self
            .item_credential_index
            .contains_key(&(dest_item_key.to_string(), new_key.clone()))
        {
            return Err(Error::DuplicateCredentialKey(new_key));
        }
        let dest = self
            .items
            .get(&dest_item_id)
            .ok_or_else(|| Error::InvalidItemKey(dest_item_key.to_string()))?;
        if let Some(section_id) = section_id
            && !dest.sections.contains_key(&section_id)
        {
            return Err(Error::InvalidSection(section_id.to_string()));
        }

        // Encrypt everything for the destination before changing anything.
        let value = match self.secrets.get(&cred_id) {
            Some(blob) => {
                let plain = self.cipher.decrypt_cred_value(item_id, cred_id, blob)?;
                Some(self.cipher.encrypt_cred_value(
                    dest_item_id,
                    cred_id,
                    plain.expose_secret(),
                )?)
            },
            None => None,
        };
        let mut history = Vec::new();
        for entry in self.history.get(&cred_id).into_iter().flatten() {
            let decrypted = self.cipher.decrypt_history_entry(item_id, cred_id, entry)?;
            history.push(
                self.cipher
                    .encrypt_history_entry(dest_item_id, cred_id, &decrypted)?,
            );
        }

        // Remove from the source item.
        let source = self
            .items
            .get_mut(&item_id)
            .ok_or_else(|| Error::InvalidItemKey(item_key.to_string()))?;
        let mut credential = source
            .credentials
            .remove(&cred_id)
            .ok_or_else(|| Error::InvalidCredentialKey(format!("{item_key}/{cred_key}")))?;
        if source.autofill.role_of(cred_id).is_some() {
            source.autofill.clear_credential(cred_id);
            self.autofill_blobs.remove(&item_id);
        }
        self.item_credential_index
            .remove(&(item_key.to_string(), cred_key.to_string()));
        self.cred_blobs.remove(&cred_id);
        self.secrets.remove(&cred_id);
        self.history.remove(&cred_id);

        // Add to the destination item.
        credential.key = new_key.clone();
        credential.section = section_id;
        credential.position = None;
        if let Some(value) = value {
            self.secrets.insert(cred_id, value);
        }
        if !history.is_empty() {
            self.history.insert(cred_id, history);
        }
        self.item_credential_index.insert(
            (dest_item_key.to_string(), new_key),
            (dest_item_id, cred_id),
        );
        let dest = self
            .items
            .get_mut(&dest_item_id)
            .ok_or_else(|| Error::InvalidItemKey(dest_item_key.to_string()))?;
        dest.credentials.insert(cred_id, credential);
        Ok(dest.credentials.get(&cred_id).expect("just inserted"))
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

/// Entries a re-key carries into the copy.
#[derive(Clone, Copy)]
enum RekeyScope {
    /// Every entry, deleted items and deleted credentials included.
    All,
    /// Live entries only. Passkey credentials are left out unless `passkeys`
    /// is set.
    Live { passkeys: bool },
}

struct DeletedEntry {
    blobs: DeletedCredential,
    overview: DeletedCredentialOverview,
}

struct DeletedItemEntry {
    item: DecryptedItem,
    info: EncryptedBlob<DeletedInfo>,
    deleted_at: i64,
}

/// Plaintext copy of an item, as it is held while moving between vaults.
pub struct ItemTransfer {
    overview: VaultItemOverview,
    values: BTreeMap<CredentialId, SecretBox<String>>,
    history: BTreeMap<CredentialId, Vec<DecryptedHistoryEntry>>,
}

impl ItemTransfer {
    /// Id of the item.
    pub fn item_id(&self) -> Uuid {
        self.overview.id
    }
}

/// Decrypted history entry of a credential.
pub(crate) struct DecryptedHistoryEntry {
    pub(crate) id: Uuid,
    pub(crate) metadata: HistoryMetadata,
    /// Value the entry holds, as its kind states.
    pub(crate) value: Option<SecretBox<String>>,
}

/// An item with decrypted metadata and encrypted secrets, as it is held while
/// moving between live and deleted.
struct DecryptedItem {
    overview: VaultItemOverview,
    metadata: EncryptedBlob<VaultItemMetadata>,
    /// Whether `metadata` matches `overview`.
    metadata_current: bool,
    /// Autofill blob matching `overview`. `None` if absent or not current.
    autofill: Option<EncryptedBlob<ItemAutofill>>,
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

impl DeletedEntry {
    /// Entry with every blob encrypted again from `from` to `to`. The
    /// credential metadata is encrypted from the overview.
    fn rekeyed(&self, from: &VaultCipher, to: &VaultCipher) -> Result<Self, Error> {
        let item_id = self.overview.item_id;
        let credential = &self.overview.credential;
        let blobs = &self.blobs.credential;
        Ok(Self {
            blobs: DeletedCredential {
                credential: EncryptedVaultItemCredential {
                    metadata: to.encrypt_cred_metadata(
                        item_id,
                        credential.id,
                        &credential.to_metadata(),
                    )?,
                    value: from.rekey_cred_value(to, item_id, credential.id, &blobs.value)?,
                    history: from.rekey_history(to, item_id, credential.id, &blobs.history)?,
                },
                info: from.rekey_deleted_info(to, item_id, credential.id, &self.blobs.info)?,
            },
            overview: self.overview.clone(),
        })
    }
}

impl DeletedItemEntry {
    /// Entry with every blob encrypted again from `from` to `to`.
    fn rekeyed(&self, from: &VaultCipher, to: &VaultCipher) -> Result<Self, Error> {
        let item_id = self.item.overview.id;
        Ok(Self {
            item: self.item.rekeyed(from, to)?,
            info: from.rekey_deleted_item_info(to, item_id, &self.info)?,
            deleted_at: self.deleted_at,
        })
    }
}

impl DecryptedItem {
    /// Item with every blob encrypted again from `from` to `to`. Metadata
    /// and autofill blobs are encrypted from the overview and are current.
    fn rekeyed(&self, from: &VaultCipher, to: &VaultCipher) -> Result<Self, Error> {
        let item_id = self.overview.id;
        let autofill = if self.overview.autofill.is_empty() {
            None
        } else {
            Some(to.encrypt_item_autofill(item_id, &self.overview.autofill)?)
        };
        let mut credentials = BTreeMap::new();
        for (cred_id, cred) in &self.credentials {
            let overview = self
                .overview
                .credentials
                .get(cred_id)
                .ok_or_else(|| Error::InvalidCredentialKey(format!("{item_id}/{cred_id}")))?;
            credentials.insert(
                *cred_id,
                DecryptedCredential {
                    metadata: to.encrypt_cred_metadata(
                        item_id,
                        *cred_id,
                        &overview.to_metadata(),
                    )?,
                    metadata_current: true,
                    value: from.rekey_cred_value(to, item_id, *cred_id, &cred.value)?,
                    history: from.rekey_history(to, item_id, *cred_id, &cred.history)?,
                },
            );
        }
        let deleted = self
            .deleted
            .iter()
            .map(|(cred_id, entry)| Ok((*cred_id, entry.rekeyed(from, to)?)))
            .collect::<Result<_, Error>>()?;
        Ok(Self {
            overview: self.overview.clone(),
            metadata: to.encrypt_item_metadata(item_id, &self.overview.to_metadata())?,
            metadata_current: true,
            autofill,
            credentials,
            deleted,
        })
    }
}

/// Decrypted entries of a vault, live and trashed, from
/// [`Vault::sync_entries`].
pub(crate) struct SyncEntries<'a> {
    pub(crate) name: Option<&'a str>,
    pub(crate) folders: &'a BTreeMap<FolderId, VaultFolder>,
    /// Site reports as stored. Reports held in memory are not included.
    pub(crate) passkey_signals: &'a SignalStore,
    /// Live and trashed items.
    pub(crate) items: Vec<SyncItemEntry<'a>>,
    /// Live and trashed credentials of live and trashed items.
    pub(crate) credentials: Vec<SyncCredentialEntry<'a>>,
}

pub(crate) struct SyncItemEntry<'a> {
    /// Its `credentials` holds only the credentials that are not trashed.
    pub(crate) overview: &'a VaultItemOverview,
    /// `None` for a live item.
    pub(crate) trashed: Option<DeletedInfo>,
}

pub(crate) struct SyncCredentialEntry<'a> {
    pub(crate) item: ItemId,
    pub(crate) overview: &'a VaultItemCredentialOverview,
    /// `None` for a credential that is not trashed. A credential of a trashed
    /// item is not trashed unless it was trashed itself.
    pub(crate) trashed: Option<DeletedInfo>,
    /// Empty if the credential has no value.
    pub(crate) value: SecretBox<String>,
    /// In stored order, oldest first.
    pub(crate) history: Vec<DecryptedHistoryEntry>,
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

#[cfg(test)]
mod tests;
