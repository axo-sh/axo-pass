use aes_gcm::{Aes256Gcm, KeyInit};
use secrecy::{ExposeSecret, SecretBox};
use uuid::Uuid;

use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::vault::VaultFieldMetadata;
use crate::secrets::vaults::vault::encrypted_blob::EncryptedBlob;
use crate::secrets::vaults::vault_export::ExportMode;

pub struct VaultCipher {
    cipher: Aes256Gcm,
    cipher_bytes: SecretBox<Vec<u8>>,
    vault_id: Uuid,
}

impl VaultCipher {
    #[cfg(test)]
    pub fn new(vault_id: Uuid) -> Self {
        use aes_gcm::aead::OsRng;

        Self::new_with_bytes(&Aes256Gcm::generate_key(OsRng), vault_id)
    }

    pub fn new_with_bytes(cipher_key: &[u8], vault_id: Uuid) -> Self {
        let cipher = Aes256Gcm::new(cipher_key.into());
        let cipher_bytes = SecretBox::new(Box::new(cipher_key.to_vec()));
        Self {
            cipher,
            cipher_bytes,
            vault_id,
        }
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

    pub fn wrap_file_key_for_export(&self, export_mode: ExportMode) -> Result<String, Error> {
        export_mode.wrap_file_key(self.cipher_bytes.expose_secret())
    }
}
