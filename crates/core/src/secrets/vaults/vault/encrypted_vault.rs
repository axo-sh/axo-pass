use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::{fs, io};

use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use uuid::Uuid;

use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::vault::encrypted_blob::EncryptedBlob;
use crate::secrets::vaults::vault::vault_cipher::VaultCipher;
use crate::secrets::vaults::vault::{
    VaultFieldMetadata, VaultItemCredentialOverview, VaultItemOverview,
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
    pub items: BTreeMap<Uuid, EncryptedVaultItem>,
}

impl EncryptedVault {
    pub fn load(vault_path: &Path) -> Result<Self, Error> {
        log::debug!("Reading vault from file: {}", vault_path.display());
        let vault_data = fs::read_to_string(vault_path).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                Error::VaultNotFound(format!("Vault file not found: {}", vault_path.display()))
            } else {
                Error::VaultReadError(e)
            }
        })?;
        serde_json::from_str(&vault_data).map_err(Error::VaultDeserializationError)
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

    /// Add an item to the vault and return a reference to the newly added item.
    /// The caller must have already decrypted the vault's file key and is
    /// responsible for passing in the cipher for encryption.
    pub fn add_item(
        &mut self,
        vault_cipher: &VaultCipher,
        metadata: Option<&EncryptedBlob<VaultFieldMetadata>>,
        item: &VaultItemOverview,
    ) -> Result<&EncryptedVaultItem, Error> {
        let encrypted_item = EncryptedVaultItem {
            metadata: match metadata {
                Some(existing) => existing.clone(),
                None => {
                    let metadata = VaultFieldMetadata::try_new(&item.title, &item.key)?;
                    vault_cipher.encrypt_item_metadata(item.id, &metadata)?
                },
            },
            credentials: BTreeMap::new(),
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
        metadata: Option<&EncryptedBlob<VaultFieldMetadata>>,
        item_id: Uuid,
        cred: &VaultItemCredentialOverview,
        secret: EncryptedBlob<String>,
    ) -> Result<&EncryptedVaultItemCredential, Error> {
        let item = self
            .items
            .get_mut(&item_id)
            .ok_or_else(|| Error::InvalidItemKey(item_id.to_string()))?;
        let encrypted_cred = EncryptedVaultItemCredential {
            metadata: match metadata {
                Some(existing) => existing.clone(),
                None => {
                    let metadata = VaultFieldMetadata::try_new(&cred.title, &cred.key)?;
                    vault_cipher.encrypt_cred_metadata(item_id, cred.id, &metadata)?
                },
            },
            value: secret,
        };
        item.credentials.insert(cred.id, encrypted_cred);
        Ok(item.credentials.get(&cred.id).expect("just inserted"))
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum VaultFileKey {
    Personal(#[serde_as(as = "Base64")] Vec<u8>),
    Members(Vec<VaultMember>),
    MembersFile { path: PathBuf },
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VaultMember {
    pub public_key: String,
    pub wrapped_key: Vec<u8>, // file_key encrypted with this member's public key
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedVaultItem {
    pub metadata: EncryptedBlob<VaultFieldMetadata>,
    pub credentials: BTreeMap<Uuid, EncryptedVaultItemCredential>,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedVaultItemCredential {
    pub metadata: EncryptedBlob<VaultFieldMetadata>,
    pub value: EncryptedBlob<String>,
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    fn make_vault() -> EncryptedVault {
        EncryptedVault {
            id: Uuid::new_v4(),
            name: Some("test vault".to_string()),
            file_key: VaultFileKey::Personal(vec![0u8; 32]),
            items: BTreeMap::new(),
        }
    }

    #[test]
    fn test_add_multiple_items() {
        let mut vault = make_vault();
        let cipher = VaultCipher::new(vault.id);
        let item_a = VaultItemOverview::try_new("Item A", "item-a").unwrap();
        let item_b = VaultItemOverview::try_new("Item B", "item-b").unwrap();
        vault.add_item(&cipher, None, &item_a).unwrap();
        vault.add_item(&cipher, None, &item_b).unwrap();

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
        vault.add_item(&cipher, None, &item).unwrap();

        let cred = VaultItemCredentialOverview::try_new("Password", "password").unwrap();
        let secret = cipher
            .encrypt_cred_value(item.id, cred.id, "secret123")
            .unwrap();

        vault
            .add_credential(&cipher, None, item.id, &cred, secret)
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
    fn test_add_credential_to_nonexistent_item_returns_error() {
        let mut vault = make_vault();
        let cipher = VaultCipher::new(vault.id);
        let cred = VaultItemCredentialOverview::try_new("Token", "token").unwrap();
        let secret = cipher
            .encrypt_cred_value(Uuid::new_v4(), Uuid::new_v4(), "tok")
            .unwrap();

        let result = vault.add_credential(&cipher, None, Uuid::new_v4(), &cred, secret);
        assert!(matches!(result, Err(Error::InvalidItemKey(_))));
    }
}
