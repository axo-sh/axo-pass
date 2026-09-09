pub mod encrypted_blob;
pub mod encrypted_vault;
pub mod vault_cipher;

use std::collections::BTreeMap;

use aes_gcm::aead::OsRng;
use aes_gcm::{Aes256Gcm, KeyInit};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::fields::FieldKind;
use crate::secrets::vaults::vault::encrypted_blob::EncryptedBlob;
use crate::secrets::vaults::vault::encrypted_vault::{EncryptedVault, VaultFileKey};
use crate::secrets::vaults::vault::vault_cipher::VaultCipher;
use crate::secrets::vaults::vault_export::exported_bundle::{BundledVault, ExportedBundle};
use crate::secrets::vaults::vault_wrapper::normalized_key;

type ItemId = Uuid;
type CredentialId = Uuid;

/// Vault contains decrypted metadata for all items and credentials in a
/// vault, as well as the encrypted secrets for each credential. It is used to
/// display the vault contents without decrypting secrets, and to look up
/// credentials by their item and credential keys.
pub struct Vault {
    id: Uuid,
    pub name: Option<String>,
    file_key: VaultFileKey,
    cipher: VaultCipher,

    items: BTreeMap<ItemId, VaultItemOverview>,
    item_index: BTreeMap<String, ItemId>,
    item_credential_index: BTreeMap<(String, String), (ItemId, CredentialId)>,
    secrets: BTreeMap<CredentialId, EncryptedBlob<String>>,

    // Cached encrypted metadata blobs (keyed by item or cred UUID, which are
    // globally unique). Dropped when metadata changes so that to_encrypted()
    // only re-encrypts what is necessary.
    metadata_blobs: BTreeMap<Uuid, EncryptedBlob<VaultFieldMetadata>>,
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

        Ok(Self {
            id: vault_id,
            name,
            file_key: enc_file_key,
            cipher,
            items: BTreeMap::new(),
            item_index: BTreeMap::new(),
            item_credential_index: BTreeMap::new(),
            secrets: BTreeMap::new(),
            metadata_blobs: BTreeMap::new(),
        })
    }

    // This converts an EncryptedVault into a Vault by decrypting all
    // metadata and organizing data into the appropriate fields.
    pub fn from_encrypted(
        user_encryption_key: ManagedKey,
        enc_vault: EncryptedVault,
    ) -> Result<Self, Error> {
        let vault_cipher = enc_vault.decrypt_file_key(&user_encryption_key)?;
        let mut vault = Vault {
            id: enc_vault.id,
            name: enc_vault.name.clone(),
            file_key: enc_vault.file_key.clone(),
            cipher: vault_cipher,
            items: BTreeMap::new(),
            item_index: BTreeMap::new(),
            item_credential_index: BTreeMap::new(),
            secrets: BTreeMap::new(),
            metadata_blobs: BTreeMap::new(),
        };

        for (item_id, encrypted_item) in enc_vault.items {
            let (item_title, item_key) = vault
                .cipher
                .decrypt_item_metadata(item_id, &encrypted_item.metadata)
                .map(|m| {
                    let metadata = m.expose_secret();
                    (metadata.title.clone(), metadata.key.clone())
                })?;

            vault
                .metadata_blobs
                .insert(item_id, encrypted_item.metadata);

            let mut item_overview = VaultItemOverview {
                id: item_id,
                title: item_title,
                key: item_key.clone(),
                credentials: BTreeMap::new(),
            };

            for (cred_id, encrypted_cred) in encrypted_item.credentials {
                let (cred_title, cred_key, cred_kind, cred_position) = vault
                    .cipher
                    .decrypt_cred_metadata(item_id, cred_id, &encrypted_cred.metadata)
                    .map(|m| {
                        let metadata = m.expose_secret();
                        (
                            metadata.title.clone(),
                            metadata.key.clone(),
                            metadata.kind.clone(),
                            metadata.position,
                        )
                    })?;

                vault
                    .metadata_blobs
                    .insert(cred_id, encrypted_cred.metadata);

                item_overview.credentials.insert(
                    cred_id,
                    VaultItemCredentialOverview {
                        id: cred_id,
                        title: cred_title,
                        key: cred_key.clone(),
                        kind: cred_kind,
                        position: cred_position,
                    },
                );

                // update (item_key, cred_key) index
                vault
                    .item_credential_index
                    .insert((item_key.clone(), cred_key.clone()), (item_id, cred_id));

                vault.secrets.insert(cred_id, encrypted_cred.value);
            }

            vault.item_index.insert(item_key, item_id);
            vault.items.insert(item_id, item_overview);
        }

        Ok(vault)
    }

    pub fn to_encrypted(&self) -> Result<EncryptedVault, Error> {
        let mut vault = EncryptedVault {
            id: self.id,
            name: self.name.clone(),
            file_key: self.file_key.clone(),
            items: BTreeMap::new(),
        };

        for item_overview in self.items.values() {
            let existing_metadata = self.metadata_blobs.get(&item_overview.id);
            vault.add_item(&self.cipher, existing_metadata, item_overview)?;

            for (cred_id, cred_overview) in &item_overview.credentials {
                let existing_metadata = self.metadata_blobs.get(cred_id);
                vault.add_credential(
                    &self.cipher,
                    existing_metadata,
                    item_overview.id,
                    cred_overview,
                    self.secrets
                        .get(cred_id)
                        .ok_or_else(|| Error::InvalidCredentialKey(cred_id.to_string()))?
                        .clone(),
                )?;
            }
        }

        Ok(vault)
    }

    /// Build a [`BundledVault`] for export. `key` is the preferred import key,
    /// `bundle_cipher` wraps the raw file key.
    ///
    /// The exported vault carries this vault's own file key. An imported copy
    /// shares that key with the source; export does not re-key.
    pub fn to_bundled_vault(
        &self,
        key: Option<String>,
        bundle_id: Uuid,
        bundle_cipher: &Aes256Gcm,
    ) -> Result<BundledVault, Error> {
        let encrypted_vault = self.to_encrypted()?;
        let wrapped_file_key = self.cipher.wrap_raw_key(
            bundle_cipher,
            ExportedBundle::file_key_aad(bundle_id, self.id),
        )?;
        Ok(BundledVault {
            id: encrypted_vault.id,
            name: encrypted_vault.name,
            default_key: key,
            wrapped_file_key,
            items: encrypted_vault.items,
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
        self.metadata_blobs.remove(&item_id); // for simplicity, always attempt this

        // get a reference to return
        let item_overview_ref = self.items.get(&item_id).expect("just inserted");
        Ok(item_overview_ref)
    }

    pub fn delete_item(&mut self, item_key: &str) -> Result<(), Error> {
        let item_id = *self.get_item_id(item_key)?;

        // remove credentials from indices and secrets map
        if let Some(item) = self.items.get(&item_id) {
            for cred in item.credentials.values() {
                let composite_key = (item_key.to_string(), cred.key.clone());
                self.item_credential_index.remove(&composite_key);
                self.secrets.remove(&cred.id);
            }
        }

        // remove from indices and items map
        self.item_index.remove(item_key);
        self.items.remove(&item_id);
        self.metadata_blobs.remove(&item_id); // for simplicity, always attempt this

        Ok(())
    }

    pub fn get_item_credential(
        &self,
        item_key: &str,
        cred_key: &str,
    ) -> Result<&VaultItemCredentialOverview, Error> {
        let composite_key = (item_key.to_string(), cred_key.to_string());
        let (item_id, cred_id) = self
            .item_credential_index
            .get(&composite_key)
            .ok_or_else(|| Error::InvalidCredentialKey(format!("{item_key}/{cred_key}")))?;
        let item = self
            .items
            .get(item_id)
            .ok_or_else(|| Error::InvalidItemKey(item_key.to_string()))?;
        item.credentials
            .get(cred_id)
            .ok_or_else(|| Error::InvalidCredentialKey(cred_key.to_string()))
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
        let item = self
            .items
            .get_mut(&item_id)
            .ok_or_else(|| Error::InvalidItemKey(item_key.to_string()))?;

        // update secret if secret is non-empty
        let secret = cred_value.expose_secret();
        if !secret.is_empty() {
            let encrypted_secret = self.cipher.encrypt_cred_value(item_id, cred_id, secret)?;
            self.secrets.insert(cred_id, encrypted_secret);
        } else if !self.secrets.contains_key(&cred_id) {
            // if secret is empty and credential doesn't already exist, throw error (to
            // prevent creating credentials with empty secrets by mistake)
            return Err(Error::InvalidEmptyCredentialValue);
        }

        // add or update credential in item.credentials
        item.credentials.insert(cred_id, cred_overview);

        // update indices. note: if credential already exists, the following should just
        // overwrite the existing keys.
        self.item_credential_index
            .insert((item_key.to_string(), cred_key), (item_id, cred_id));
        self.metadata_blobs.remove(&cred_id); // for simplicity, always attempt this

        // get a reference to return
        let cred_overview_ref = item.credentials.get(&cred_id).expect("just inserted");
        Ok(cred_overview_ref)
    }

    pub fn delete_item_credential(&mut self, item_key: &str, cred_key: &str) -> Result<(), Error> {
        let composite_key = (item_key.to_string(), cred_key.to_string());
        let (item_id, cred_id) = *self
            .item_credential_index
            .get(&composite_key)
            .ok_or_else(|| Error::InvalidCredentialKey(format!("{item_key}/{cred_key}")))?;

        // remove from item
        let item = self
            .items
            .get_mut(&item_id)
            .ok_or_else(|| Error::InvalidItemKey(item_key.to_string()))?;
        item.credentials.remove(&cred_id);

        // remove from indices and secrets map
        self.item_credential_index.remove(&composite_key);
        self.secrets.remove(&cred_id);
        self.metadata_blobs.remove(&cred_id); // for simplicity, always attempt this

        Ok(())
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

    /// Set the display order of an item's credentials. `ordered_cred_keys` must
    /// list exactly the item's credential keys, once each. Each credential's
    /// `position` is set to its index and its metadata blob is invalidated so
    /// the next save re-encrypts it.
    pub fn reorder_item_credentials(
        &mut self,
        item_key: &str,
        ordered_cred_keys: &[String],
    ) -> Result<(), Error> {
        let item_id = *self.get_item_id(item_key)?;

        // Resolve every requested key to a credential id in this item.
        let mut ordered_ids = Vec::with_capacity(ordered_cred_keys.len());
        for cred_key in ordered_cred_keys {
            let composite_key = (item_key.to_string(), cred_key.clone());
            let (found_item_id, cred_id) = self
                .item_credential_index
                .get(&composite_key)
                .copied()
                .ok_or_else(|| {
                    Error::InvalidCredentialKey(format!("{item_key}/{cred_key}"))
                })?;
            if found_item_id != item_id {
                return Err(Error::InvalidCredentialKey(format!("{item_key}/{cred_key}")));
            }
            ordered_ids.push(cred_id);
        }

        let item = self
            .items
            .get_mut(&item_id)
            .ok_or_else(|| Error::InvalidItemKey(item_key.to_string()))?;

        // Require a full permutation of the item's credentials.
        let mut unique: Vec<Uuid> = ordered_ids.clone();
        unique.sort();
        unique.dedup();
        if unique.len() != ordered_ids.len() || ordered_ids.len() != item.credentials.len() {
            return Err(Error::InvalidCredentialOrder(item_key.to_string()));
        }

        for (idx, cred_id) in ordered_ids.iter().enumerate() {
            // Every id resolved through the index above, so a miss here means
            // the index and the item's credentials have diverged.
            let cred = item
                .credentials
                .get_mut(cred_id)
                .ok_or_else(|| Error::InvalidCredentialOrder(item_key.to_string()))?;
            cred.position = Some(idx as u32);
        }

        // Invalidate the cached metadata blobs so the next save re-encrypts
        // them with the new positions.
        for cred_id in &ordered_ids {
            self.metadata_blobs.remove(cred_id);
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct VaultItemOverview {
    pub id: Uuid,
    pub title: String,
    pub key: String,
    pub credentials: BTreeMap<Uuid, VaultItemCredentialOverview>,
}

impl VaultItemOverview {
    pub fn try_new(title: &str, key: &str) -> Result<Self, Error> {
        let item_key = normalized_key(key).ok_or_else(|| Error::InvalidItemKey(key.to_string()))?;
        Ok(Self {
            id: Uuid::new_v4(),
            title: title.to_string(),
            key: item_key,
            credentials: BTreeMap::new(),
        })
    }
}

#[derive(Clone)]
pub struct VaultItemCredentialOverview {
    pub id: Uuid,
    pub title: String,
    pub key: String,
    pub kind: FieldKind,
    /// User-defined order within the item. `None` until the item is reordered.
    pub position: Option<u32>,
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
        })
    }
}

#[derive(Serialize, Deserialize, Zeroize)]
pub struct VaultFieldMetadata {
    pub title: String,
    pub key: String,
    #[serde(default, skip_serializing_if = "FieldKind::is_default")]
    pub kind: FieldKind,
    /// User-defined order of a credential within its item. Absent on legacy
    /// vaults and until the first reorder; unset credentials sort after set
    /// ones, by title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub position: Option<u32>,
}

impl VaultFieldMetadata {
    pub fn try_new(title: &str, key: &str, kind: FieldKind) -> Result<Self, Error> {
        let cred_key = normalized_key(key).ok_or_else(|| Error::InvalidItemKey(key.to_string()))?;
        Ok(Self {
            title: title.to_string(),
            key: cred_key,
            kind,
            position: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::vaults::fields::TextField;

    fn test_vault() -> Vault {
        let id = Uuid::new_v4();
        Vault {
            id,
            name: Some("test vault".to_string()),
            file_key: VaultFileKey::Personal(vec![0u8; 32]),
            cipher: VaultCipher::new(id),
            items: BTreeMap::new(),
            item_index: BTreeMap::new(),
            item_credential_index: BTreeMap::new(),
            secrets: BTreeMap::new(),
            metadata_blobs: BTreeMap::new(),
        }
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

    fn positions(vault: &Vault, item_key: &str, cred_keys: &[&str]) -> Vec<Option<u32>> {
        cred_keys
            .iter()
            .map(|k| vault.get_item_credential(item_key, k).unwrap().position)
            .collect()
    }

    #[test]
    fn reorder_assigns_positions_in_the_given_order() {
        let keys = ["alpha", "beta", "gamma"];
        let mut vault = vault_with_credentials("item", &keys);
        assert_eq!(positions(&vault, "item", &keys), vec![None, None, None]);

        vault
            .reorder_item_credentials(
                "item",
                &["gamma".to_string(), "alpha".to_string(), "beta".to_string()],
            )
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

        // Populate the metadata cache the way a load/save cycle would.
        let encrypted = vault.to_encrypted().unwrap();
        let item_id = *vault.get_item_id("item").unwrap();
        for (cred_id, cred) in &encrypted.items.get(&item_id).unwrap().credentials {
            vault.metadata_blobs.insert(*cred_id, cred.metadata.clone());
        }

        vault
            .reorder_item_credentials("item", &["beta".to_string(), "alpha".to_string()])
            .unwrap();

        let encrypted = vault.to_encrypted().unwrap();
        let mut persisted: Vec<(String, Option<u32>)> = encrypted
            .items
            .get(&item_id)
            .unwrap()
            .credentials
            .iter()
            .map(|(cred_id, cred)| {
                let meta = vault
                    .cipher
                    .decrypt_cred_metadata(item_id, *cred_id, &cred.metadata)
                    .unwrap();
                let meta = meta.expose_secret();
                (meta.key.clone(), meta.position)
            })
            .collect();
        persisted.sort();
        assert_eq!(
            persisted,
            vec![
                ("alpha".to_string(), Some(1)),
                ("beta".to_string(), Some(0))
            ]
        );
    }

    #[test]
    fn reorder_rejects_a_partial_list() {
        let mut vault = vault_with_credentials("item", &["alpha", "beta", "gamma"]);
        let err = vault
            .reorder_item_credentials("item", &["beta".to_string(), "alpha".to_string()])
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
            .reorder_item_credentials("item", &["alpha".to_string(), "alpha".to_string()])
            .unwrap_err();
        assert!(matches!(err, Error::InvalidCredentialOrder(_)));
    }

    #[test]
    fn reorder_rejects_an_unknown_key() {
        let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
        let err = vault
            .reorder_item_credentials("item", &["alpha".to_string(), "nope".to_string()])
            .unwrap_err();
        assert!(matches!(err, Error::InvalidCredentialKey(_)));
    }

    #[test]
    fn reorder_rejects_a_key_from_another_item() {
        let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
        let err = vault
            .reorder_item_credentials("item", &["alpha".to_string(), "elsewhere".to_string()])
            .unwrap_err();
        assert!(matches!(err, Error::InvalidCredentialKey(_)));
    }

    #[test]
    fn reorder_rejects_an_unknown_item() {
        let mut vault = vault_with_credentials("item", &["alpha"]);
        let err = vault
            .reorder_item_credentials("nope", &["alpha".to_string()])
            .unwrap_err();
        assert!(matches!(err, Error::InvalidItemKey(_)));
    }

    #[test]
    fn reordered_positions_survive_a_save_and_load() {
        let keys = ["alpha", "beta", "gamma"];
        let mut vault = vault_with_credentials("item", &keys);
        vault
            .reorder_item_credentials(
                "item",
                &["gamma".to_string(), "beta".to_string(), "alpha".to_string()],
            )
            .unwrap();

        let encrypted = vault.to_encrypted().unwrap();
        let item_id = *vault.get_item_id("item").unwrap();

        // Decrypt the persisted metadata with the vault's own cipher, since
        // from_encrypted needs a keychain-backed key.
        let mut loaded: Vec<(String, Option<u32>)> = encrypted
            .items
            .get(&item_id)
            .unwrap()
            .credentials
            .iter()
            .map(|(cred_id, cred)| {
                let meta = vault
                    .cipher
                    .decrypt_cred_metadata(item_id, *cred_id, &cred.metadata)
                    .unwrap();
                let meta = meta.expose_secret();
                (meta.key.clone(), meta.position)
            })
            .collect();
        loaded.sort_by_key(|(_, position)| *position);
        assert_eq!(
            loaded.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
            vec!["gamma", "beta", "alpha"]
        );
    }

    #[test]
    fn default_kind_is_omitted_from_json() {
        let meta =
            VaultFieldMetadata::try_new("Password", "password", FieldKind::default()).unwrap();
        let json = serde_json::to_value(&meta).unwrap();
        assert!(json.get("kind").is_none());
    }

    #[test]
    fn legacy_metadata_without_kind_loads_as_default() {
        let meta: VaultFieldMetadata =
            serde_json::from_str(r#"{"title":"Password","key":"password"}"#).unwrap();
        assert_eq!(meta.kind, FieldKind::default());
    }

    #[test]
    fn position_is_omitted_when_unset_and_roundtrips_when_set() {
        let meta =
            VaultFieldMetadata::try_new("Password", "password", FieldKind::default()).unwrap();
        let json = serde_json::to_value(&meta).unwrap();
        assert!(json.get("position").is_none());

        let mut meta = meta;
        meta.position = Some(2);
        let json = serde_json::to_value(&meta).unwrap();
        assert_eq!(json.get("position").and_then(|v| v.as_u64()), Some(2));
        let back: VaultFieldMetadata = serde_json::from_value(json).unwrap();
        assert_eq!(back.position, Some(2));
    }

    #[test]
    fn legacy_metadata_without_position_loads_as_none() {
        let meta: VaultFieldMetadata =
            serde_json::from_str(r#"{"title":"Password","key":"password"}"#).unwrap();
        assert_eq!(meta.position, None);
    }

    #[test]
    fn non_default_kind_roundtrips_through_metadata() {
        let meta = VaultFieldMetadata::try_new(
            "Notes",
            "notes",
            FieldKind::Text(TextField {
                multiline: Some(true),
            }),
        )
        .unwrap();
        let json = serde_json::to_value(&meta).unwrap();
        let back: VaultFieldMetadata = serde_json::from_value(json).unwrap();
        assert_eq!(back.kind, meta.kind);
    }
}
