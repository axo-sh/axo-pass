pub mod encrypted_blob;
pub mod encrypted_vault;
pub mod vault_cipher;

use std::collections::BTreeMap;

use aes_gcm::aead::OsRng;
use aes_gcm::{Aes256Gcm, KeyInit};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::vault::encrypted_blob::EncryptedBlob;
use crate::secrets::vaults::vault::encrypted_vault::{EncryptedVault, VaultFileKey};
use crate::secrets::vaults::vault::vault_cipher::VaultCipher;
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
    // globally unique). Dropped when metadata changes so that into_encrypted()
    // only re-encrypts what is necessary.
    metadata_blobs: BTreeMap<Uuid, EncryptedBlob<VaultFieldMetadata>>,
}

impl Vault {
    pub fn new(name: Option<String>, user_encryption_key: ManagedKey) -> Result<Self, Error> {
        let vault_id = Uuid::new_v4();
        let actual_file_key = Aes256Gcm::generate_key(OsRng);

        // use actual key to create personal vault file key
        let enc_file_key = VaultFileKey::Personal(
            user_encryption_key
                .encrypt(&actual_file_key)
                .ok_or(Error::VaultFileKeyEncryptionError)?
                .into_bytes(),
        );

        // wrap actual key in VaultCipher to simplify operations
        let cipher = VaultCipher::new(Aes256Gcm::new(&actual_file_key), vault_id);

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
                let (cred_title, cred_key) = vault
                    .cipher
                    .decrypt_cred_metadata(item_id, cred_id, &encrypted_cred.metadata)
                    .map(|m| {
                        let metadata = m.expose_secret();
                        (metadata.title.clone(), metadata.key.clone())
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

    pub fn into_encrypted(&self) -> Result<EncryptedVault, Error> {
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
        cred_value: SecretString,
    ) -> Result<&VaultItemCredentialOverview, Error> {
        // get existing cred by key or create new one
        let cred_overview = match self.get_item_credential(item_key, cred_key) {
            Ok(existing) => VaultItemCredentialOverview {
                title: cred_title.to_string(),
                ..existing.clone()
            },
            Err(Error::InvalidCredentialKey(_)) => {
                VaultItemCredentialOverview::try_new(cred_title, cred_key)?
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

        let encrypted_secret =
            self.cipher
                .encrypt_cred_value(item_id, cred_id, cred_value.expose_secret())?;

        // add or update credential in item.credentials
        item.credentials.insert(cred_id, cred_overview);

        // update indices. note: if credential already exists, the following should just
        // overwrite the existing keys.
        self.item_credential_index
            .insert((item_key.to_string(), cred_key), (item_id, cred_id));
        self.secrets.insert(cred_id, encrypted_secret);
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
        let item_id = self.get_item(item_key)?.id;
        let cred_overview = self.get_item_credential(item_key, cred_key)?;
        let cred_id = cred_overview.id;
        let Some(encrypted_secret) = self.secrets.get(&cred_overview.id) else {
            return Ok(None);
        };
        let plaintext = self
            .cipher
            .decrypt_cred_value(item_id, cred_id, encrypted_secret)?;
        Ok(Some(plaintext))
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
}

impl VaultItemCredentialOverview {
    pub fn try_new(title: &str, key: &str) -> Result<Self, Error> {
        let cred_key =
            normalized_key(key).ok_or_else(|| Error::InvalidCredentialKey(key.to_string()))?;
        Ok(Self {
            id: Uuid::new_v4(),
            title: title.to_string(),
            key: cred_key,
        })
    }
}

#[derive(Serialize, Deserialize, Zeroize)]
pub struct VaultFieldMetadata {
    pub title: String,
    pub key: String,
}

impl VaultFieldMetadata {
    pub fn try_new(title: &str, key: &str) -> Result<Self, Error> {
        let cred_key = normalized_key(key).ok_or_else(|| Error::InvalidItemKey(key.to_string()))?;
        Ok(Self {
            title: title.to_string(),
            key: cred_key,
        })
    }
}
