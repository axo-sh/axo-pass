use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::{fs, io};

use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use uuid::Uuid;

use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::vaults::autofill::item::ItemAutofill;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::encrypted_blob::EncryptedBlob;
use crate::secrets::vaults::format::vault_cipher::VaultCipher;
use crate::secrets::vaults::model::{
    DeletedInfo, HistoryInfo, VaultCredentialMetadata, VaultItemCredentialOverview,
    VaultItemMetadata, VaultItemOverview, VaultMetadata,
};

// EncryptedVault is the on disk representation of a vault, with metadata and
// secrets encrypted. We don't persist this in memory; see Vault
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct EncryptedVault {
    pub id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub file_key: VaultFileKey,
    /// Vault-level metadata such as folders. Absent for a vault with none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<EncryptedBlob<VaultMetadata>>,
    pub items: BTreeMap<Uuid, EncryptedVaultItem>,
    /// Deleted items that can still be restored. Absent if empty.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub deleted: BTreeMap<Uuid, DeletedItem>,
}

/// Struct to read just the id and name of a vault file, without decrypting the
/// vault itself Used for the locked vault list and the transaction registry.
/// Other fields are ignored.
#[derive(Deserialize)]
pub struct VaultHeader {
    pub id: Uuid,
    pub name: Option<String>,
}

impl VaultHeader {
    pub fn peek(vault_path: &Path) -> Result<Self, Error> {
        let vault_data = EncryptedVault::read_file(vault_path)?;
        serde_json::from_str(&vault_data).map_err(Error::VaultDeserializationError)
    }
}

impl EncryptedVault {
    /// Read a vault file as text. A missing file is `VaultNotFound`.
    pub(crate) fn read_file(vault_path: &Path) -> Result<String, Error> {
        fs::read_to_string(vault_path).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                Error::VaultNotFound(format!("Vault file not found: {}", vault_path.display()))
            } else {
                Error::VaultReadError(e)
            }
        })
    }

    pub fn load(vault_path: &Path) -> Result<Self, Error> {
        log::debug!("Reading vault from file: {}", vault_path.display());
        Self::parse(&Self::read_file(vault_path)?)
    }

    pub(crate) fn parse(vault_data: &str) -> Result<Self, Error> {
        serde_json::from_str(vault_data).map_err(Error::VaultDeserializationError)
    }

    pub fn decrypt_file_key(&self, user_encryption_key: &ManagedKey) -> Result<VaultCipher, Error> {
        let candidate_keys = match &self.file_key {
            VaultFileKey::Personal(file_key_bytes) => vec![file_key_bytes],
            VaultFileKey::Members(members) => {
                members.iter().map(|member| &member.wrapped_key).collect()
            },
            VaultFileKey::MembersFile { .. } => {
                todo!()
            },
        };

        // try all candidate keys
        for file_key_bytes in candidate_keys {
            if let Some(decrypted_key) = user_encryption_key.decrypt(file_key_bytes) {
                let cipher = VaultCipher::new_with_bytes(&decrypted_key, self.id);
                return Ok(cipher);
            }
        }
        Err(Error::VaultFileKeyDecryptionError)
    }

    /// Set the vault metadata. If `value` is empty, the field is left as none.
    /// A decrypted the vault cipher is required.
    pub fn set_metadata(
        &mut self,
        vault_cipher: &VaultCipher,
        existing: Option<&EncryptedBlob<VaultMetadata>>,
        value: &VaultMetadata,
    ) -> Result<(), Error> {
        self.metadata = if value.is_empty() {
            None
        } else {
            Some(match existing {
                Some(blob) => blob.clone(),
                None => vault_cipher.encrypt_vault_metadata(value)?,
            })
        };
        Ok(())
    }

    /// Add an item to the vault and return a reference to the newly added item.
    /// The caller must have already decrypted the vault's file key and is
    /// responsible for passing in the cipher for encryption.
    pub fn add_item(
        &mut self,
        vault_cipher: &VaultCipher,
        metadata: Option<&EncryptedBlob<VaultItemMetadata>>,
        autofill: Option<&EncryptedBlob<ItemAutofill>>,
        item: &VaultItemOverview,
    ) -> Result<&EncryptedVaultItem, Error> {
        let encrypted_item = EncryptedVaultItem {
            metadata: match metadata {
                Some(existing) => existing.clone(),
                None => vault_cipher.encrypt_item_metadata(item.id, &item.to_metadata())?,
            },
            autofill: match autofill {
                Some(existing) => Some(existing.clone()),
                None if item.autofill.is_empty() => None,
                None => Some(vault_cipher.encrypt_item_autofill(item.id, &item.autofill)?),
            },
            credentials: BTreeMap::new(),
            deleted: BTreeMap::new(),
        };
        self.items.insert(item.id, encrypted_item);
        Ok(self.items.get(&item.id).expect("just inserted"))
    }

    /// Add a credential to an item and return a reference to the newly added
    /// credential. The caller must have already decrypted the vault's file
    /// key and is responsible for passing in the cipher for encryption.
    pub fn add_credential(
        &mut self,
        vault_cipher: &VaultCipher,
        metadata: Option<&EncryptedBlob<VaultCredentialMetadata>>,
        item_id: Uuid,
        cred: &VaultItemCredentialOverview,
        secret: EncryptedBlob<String>,
        history: Vec<HistoryEntry>,
    ) -> Result<&EncryptedVaultItemCredential, Error> {
        let item = self
            .items
            .get_mut(&item_id)
            .ok_or_else(|| Error::InvalidItemKey(item_id.to_string()))?;
        let encrypted_cred = EncryptedVaultItemCredential {
            metadata: match metadata {
                Some(existing) => existing.clone(),
                None => {
                    vault_cipher.encrypt_cred_metadata(item_id, cred.id, &cred.to_metadata())?
                },
            },
            value: secret,
            history,
        };
        item.credentials.insert(cred.id, encrypted_cred);
        Ok(item.credentials.get(&cred.id).expect("just inserted"))
    }

    /// Add a deleted credential to an item. The blobs are stored unchanged.
    pub fn add_deleted_credential(
        &mut self,
        item_id: Uuid,
        cred_id: Uuid,
        deleted: DeletedCredential,
    ) -> Result<(), Error> {
        let item = self
            .items
            .get_mut(&item_id)
            .ok_or_else(|| Error::InvalidItemKey(item_id.to_string()))?;
        item.deleted.insert(cred_id, deleted);
        Ok(())
    }

    /// Add a deleted item. The blobs are stored unchanged.
    pub fn add_deleted_item(&mut self, item_id: Uuid, deleted: DeletedItem) {
        self.deleted.insert(item_id, deleted);
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum VaultFileKey {
    Personal(#[serde_as(as = "Base64")] Vec<u8>),
    Members(Vec<VaultMember>),
    MembersFile { path: PathBuf },
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct VaultMember {
    pub public_key: String,
    pub wrapped_key: Vec<u8>, // file_key encrypted with this member's public key
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedVaultItem {
    pub metadata: EncryptedBlob<VaultItemMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autofill: Option<EncryptedBlob<ItemAutofill>>,
    pub credentials: BTreeMap<Uuid, EncryptedVaultItemCredential>,
    /// Deleted credentials that can still be restored. Absent if empty.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub deleted: BTreeMap<Uuid, DeletedCredential>,
}

/// A deleted item. The item blobs are the same as when it was live, including
/// its credentials and its own deleted credentials, so moving it to or from
/// deleted needs no re-encryption.
#[derive(Serialize, Deserialize)]
pub struct DeletedItem {
    #[serde(flatten)]
    pub item: EncryptedVaultItem,
    pub info: EncryptedBlob<DeletedInfo>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EncryptedVaultItemCredential {
    pub metadata: EncryptedBlob<VaultCredentialMetadata>,
    pub value: EncryptedBlob<String>,
    /// Previous values, oldest first. Absent if empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<HistoryEntry>,
}

/// A previous value of a credential. The value is encrypted under the entry id
/// as well as the credential, so it cannot be swapped into the live value's
/// place.
#[derive(Serialize, Deserialize, Clone)]
pub struct HistoryEntry {
    pub id: Uuid,
    pub value: EncryptedBlob<String>,
    pub info: EncryptedBlob<HistoryInfo>,
}

/// A deleted credential. The credential blobs are the same as when it was
/// live, so moving it to or from deleted needs no re-encryption.
#[derive(Serialize, Deserialize, Clone)]
pub struct DeletedCredential {
    #[serde(flatten)]
    pub credential: EncryptedVaultItemCredential,
    pub info: EncryptedBlob<DeletedInfo>,
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;
    use crate::secrets::vaults::model::VaultFolder;
    use crate::secrets::vaults::model::fields::FieldKind;

    fn make_vault() -> EncryptedVault {
        EncryptedVault {
            id: Uuid::new_v4(),
            name: Some("test vault".to_string()),
            file_key: VaultFileKey::Personal(vec![0u8; 32]),
            metadata: None,
            items: BTreeMap::new(),
            deleted: BTreeMap::new(),
        }
    }

    #[test]
    fn test_add_multiple_items() {
        let mut vault = make_vault();
        let cipher = VaultCipher::new(vault.id);
        let item_a = VaultItemOverview::try_new("Item A", "item-a").unwrap();
        let item_b = VaultItemOverview::try_new("Item B", "item-b").unwrap();
        vault.add_item(&cipher, None, None, &item_a).unwrap();
        vault.add_item(&cipher, None, None, &item_b).unwrap();

        assert_eq!(vault.items.len(), 2);
        assert!(vault.items.contains_key(&item_a.id));
        assert!(vault.items.contains_key(&item_b.id));

        // Each item should have encrypted metadata and no credentials yet
        let enc_a = vault.items.get(&item_a.id).unwrap();
        assert!(enc_a.credentials.is_empty());
        let enc_b = vault.items.get(&item_b.id).unwrap();
        assert!(enc_b.credentials.is_empty());

        // Verify the metadata decrypts to the expected values
        let meta_a = cipher
            .decrypt_item_metadata(item_a.id, &enc_a.metadata)
            .unwrap();
        let meta_a = meta_a.expose_secret();
        assert_eq!(meta_a.title, "Item A");
        assert_eq!(meta_a.key, "item-a");

        let meta_b = cipher
            .decrypt_item_metadata(item_b.id, &enc_b.metadata)
            .unwrap();
        let meta_b = meta_b.expose_secret();
        assert_eq!(meta_b.title, "Item B");
        assert_eq!(meta_b.key, "item-b");
    }

    #[test]
    fn test_add_and_get_credential() {
        let mut vault = make_vault();
        let cipher = VaultCipher::new(vault.id);
        let item = VaultItemOverview::try_new("My Item", "my-item").unwrap();
        vault.add_item(&cipher, None, None, &item).unwrap();

        let cred =
            VaultItemCredentialOverview::try_new("Password", "password", FieldKind::default())
                .unwrap();
        let secret = cipher
            .encrypt_cred_value(item.id, cred.id, "secret123")
            .unwrap();

        vault
            .add_credential(&cipher, None, item.id, &cred, secret, Vec::new())
            .unwrap();

        // Verify the vault has exactly one item with exactly one credential
        assert_eq!(vault.items.len(), 1);
        let enc_item = vault.items.get(&item.id).unwrap();
        assert_eq!(enc_item.credentials.len(), 1);

        let enc_cred = enc_item.credentials.get(&cred.id).unwrap();

        // Verify credential metadata decrypts to the expected values
        let meta = cipher
            .decrypt_cred_metadata(item.id, cred.id, &enc_cred.metadata)
            .unwrap();
        let meta = meta.expose_secret();
        assert_eq!(meta.title, "Password");
        assert_eq!(meta.key, "password");

        // Verify the secret value decrypts correctly
        let secret_value = cipher
            .decrypt_cred_value(item.id, cred.id, &enc_cred.value)
            .unwrap();
        assert_eq!(secret_value.expose_secret(), "secret123");
    }

    #[test]
    fn credential_position_is_persisted_in_metadata() {
        let mut vault = make_vault();
        let cipher = VaultCipher::new(vault.id);
        let item = VaultItemOverview::try_new("My Item", "my-item").unwrap();
        vault.add_item(&cipher, None, None, &item).unwrap();

        let mut cred =
            VaultItemCredentialOverview::try_new("Password", "password", FieldKind::default())
                .unwrap();
        cred.position = Some(3);
        let secret = cipher
            .encrypt_cred_value(item.id, cred.id, "secret123")
            .unwrap();
        vault
            .add_credential(&cipher, None, item.id, &cred, secret, Vec::new())
            .unwrap();

        let enc_cred = vault
            .items
            .get(&item.id)
            .unwrap()
            .credentials
            .get(&cred.id)
            .unwrap();
        let meta = cipher
            .decrypt_cred_metadata(item.id, cred.id, &enc_cred.metadata)
            .unwrap();
        assert_eq!(meta.expose_secret().position, Some(3));
    }

    #[test]
    fn vault_metadata_is_encrypted_and_bound_to_its_vault() {
        let mut vault = make_vault();
        let cipher = VaultCipher::new(vault.id);
        let metadata = VaultMetadata {
            folders: vec![VaultFolder::new("Work").to_metadata()],
            ..Default::default()
        };
        vault.set_metadata(&cipher, None, &metadata).unwrap();

        let blob = vault.metadata.as_ref().unwrap();
        let back = cipher.decrypt_vault_metadata(blob).unwrap();
        assert_eq!(back.expose_secret().folders[0].title, "Work");

        // The AAD binds the blob to its vault id.
        let other = VaultCipher::new(Uuid::new_v4());
        assert!(other.decrypt_vault_metadata(blob).is_err());
    }

    #[test]
    fn vault_without_metadata_omits_the_field() {
        let mut vault = make_vault();
        let cipher = VaultCipher::new(vault.id);
        vault
            .set_metadata(&cipher, None, &VaultMetadata::default())
            .unwrap();
        let json = serde_json::to_value(&vault).unwrap();
        assert!(json.get("metadata").is_none());

        let back: EncryptedVault = serde_json::from_value(json).unwrap();
        assert!(back.metadata.is_none());
    }

    #[test]
    fn test_add_credential_to_nonexistent_item_returns_error() {
        let mut vault = make_vault();
        let cipher = VaultCipher::new(vault.id);
        let cred =
            VaultItemCredentialOverview::try_new("Token", "token", FieldKind::default()).unwrap();
        let secret = cipher
            .encrypt_cred_value(Uuid::new_v4(), Uuid::new_v4(), "tok")
            .unwrap();

        let result = vault.add_credential(&cipher, None, Uuid::new_v4(), &cred, secret, Vec::new());
        assert!(matches!(result, Err(Error::InvalidItemKey(_))));
    }
}
