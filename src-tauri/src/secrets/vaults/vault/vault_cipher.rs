use aes_gcm::Aes256Gcm;
use secrecy::SecretBox;
use uuid::Uuid;

use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::vault::VaultFieldMetadata;
use crate::secrets::vaults::vault::encrypted_blob::EncryptedBlob;

pub struct VaultCipher {
    cipher: Aes256Gcm,
    vault_id: Uuid,
}

impl VaultCipher {
    pub fn new(cipher: Aes256Gcm, vault_id: Uuid) -> Self {
        Self { cipher, vault_id }
    }

    pub fn encrypt_item_metadata(
        &self,
        item_id: Uuid,
        value: &VaultFieldMetadata,
    ) -> Result<EncryptedBlob<VaultFieldMetadata>, Error> {
        EncryptedBlob::encrypt(
            value,
            &self.cipher,
            vec![
                self.vault_id.to_string(),
                item_id.to_string(),
                "metadata".to_string(),
            ],
        )
    }

    pub fn decrypt_item_metadata(
        &self,
        item_id: Uuid,
        blob: &EncryptedBlob<VaultFieldMetadata>,
    ) -> Result<SecretBox<VaultFieldMetadata>, Error> {
        blob.decrypt(
            &self.cipher,
            vec![
                self.vault_id.to_string(),
                item_id.to_string(),
                "metadata".to_string(),
            ],
        )
    }

    pub fn encrypt_cred_metadata(
        &self,
        item_id: Uuid,
        cred_id: Uuid,
        value: &VaultFieldMetadata,
    ) -> Result<EncryptedBlob<VaultFieldMetadata>, Error> {
        EncryptedBlob::encrypt(
            value,
            &self.cipher,
            vec![
                self.vault_id.to_string(),
                item_id.to_string(),
                cred_id.to_string(),
                "metadata".to_string(),
            ],
        )
    }

    pub fn decrypt_cred_metadata(
        &self,
        item_id: Uuid,
        cred_id: Uuid,
        blob: &EncryptedBlob<VaultFieldMetadata>,
    ) -> Result<SecretBox<VaultFieldMetadata>, Error> {
        blob.decrypt(
            &self.cipher,
            vec![
                self.vault_id.to_string(),
                item_id.to_string(),
                cred_id.to_string(),
                "metadata".to_string(),
            ],
        )
    }

    pub fn encrypt_cred_value(
        &self,
        item_id: Uuid,
        cred_id: Uuid,
        value: &str,
    ) -> Result<EncryptedBlob<String>, Error> {
        EncryptedBlob::encrypt(
            &value.to_string(),
            &self.cipher,
            vec![
                self.vault_id.to_string(),
                item_id.to_string(),
                cred_id.to_string(),
                "value".to_string(),
            ],
        )
    }

    pub fn decrypt_cred_value(
        &self,
        item_id: Uuid,
        cred_id: Uuid,
        blob: &EncryptedBlob<String>,
    ) -> Result<SecretBox<String>, Error> {
        blob.decrypt(
            &self.cipher,
            vec![
                self.vault_id.to_string(),
                item_id.to_string(),
                cred_id.to_string(),
                "value".to_string(),
            ],
        )
    }
}
