use aes_gcm::{Aes256Gcm, KeyInit};
use secrecy::{ExposeSecret, SecretBox};
use uuid::Uuid;

use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::vault::encrypted_blob::EncryptedBlob;
use crate::secrets::vaults::vault::{
    VaultCredentialMetadata, VaultFolderMetadata, VaultItemMetadata,
};
use crate::secrets::vaults::vault_export::exported_bundle::RawFileKey;

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

    // AAD binding each blob to its location in the vault. Changing any of
    // these makes existing vaults undecryptable.

    fn folder_metadata_aad(&self, folder_id: Uuid) -> Vec<String> {
        vec![
            self.vault_id.to_string(),
            "folder".to_string(),
            folder_id.to_string(),
            "metadata".to_string(),
        ]
    }

    fn item_metadata_aad(&self, item_id: Uuid) -> Vec<String> {
        vec![
            self.vault_id.to_string(),
            item_id.to_string(),
            "metadata".to_string(),
        ]
    }

    /// `part` is `"metadata"` or `"value"`.
    fn cred_aad(&self, item_id: Uuid, cred_id: Uuid, part: &str) -> Vec<String> {
        vec![
            self.vault_id.to_string(),
            item_id.to_string(),
            cred_id.to_string(),
            part.to_string(),
        ]
    }

    pub fn encrypt_folder_metadata(
        &self,
        folder_id: Uuid,
        value: &VaultFolderMetadata,
    ) -> Result<EncryptedBlob<VaultFolderMetadata>, Error> {
        EncryptedBlob::encrypt(value, &self.cipher, self.folder_metadata_aad(folder_id))
    }

    pub fn decrypt_folder_metadata(
        &self,
        folder_id: Uuid,
        blob: &EncryptedBlob<VaultFolderMetadata>,
    ) -> Result<SecretBox<VaultFolderMetadata>, Error> {
        blob.decrypt(&self.cipher, self.folder_metadata_aad(folder_id))
    }

    pub fn encrypt_item_metadata(
        &self,
        item_id: Uuid,
        value: &VaultItemMetadata,
    ) -> Result<EncryptedBlob<VaultItemMetadata>, Error> {
        EncryptedBlob::encrypt(value, &self.cipher, self.item_metadata_aad(item_id))
    }

    pub fn decrypt_item_metadata(
        &self,
        item_id: Uuid,
        blob: &EncryptedBlob<VaultItemMetadata>,
    ) -> Result<SecretBox<VaultItemMetadata>, Error> {
        blob.decrypt(&self.cipher, self.item_metadata_aad(item_id))
    }

    pub fn encrypt_cred_metadata(
        &self,
        item_id: Uuid,
        cred_id: Uuid,
        value: &VaultCredentialMetadata,
    ) -> Result<EncryptedBlob<VaultCredentialMetadata>, Error> {
        EncryptedBlob::encrypt(
            value,
            &self.cipher,
            self.cred_aad(item_id, cred_id, "metadata"),
        )
    }

    pub fn decrypt_cred_metadata(
        &self,
        item_id: Uuid,
        cred_id: Uuid,
        blob: &EncryptedBlob<VaultCredentialMetadata>,
    ) -> Result<SecretBox<VaultCredentialMetadata>, Error> {
        blob.decrypt(&self.cipher, self.cred_aad(item_id, cred_id, "metadata"))
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
            self.cred_aad(item_id, cred_id, "value"),
        )
    }

    pub fn decrypt_cred_value(
        &self,
        item_id: Uuid,
        cred_id: Uuid,
        blob: &EncryptedBlob<String>,
    ) -> Result<SecretBox<String>, Error> {
        blob.decrypt(&self.cipher, self.cred_aad(item_id, cred_id, "value"))
    }

    /// Encrypt this vault's raw file key with the bundle cipher for export.
    pub fn wrap_raw_key(
        &self,
        bundle_cipher: &Aes256Gcm,
        aad: Vec<String>,
    ) -> Result<EncryptedBlob<RawFileKey>, Error> {
        let raw = RawFileKey(self.cipher_bytes.expose_secret().clone());
        EncryptedBlob::encrypt(&raw, bundle_cipher, aad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aad_layout_is_unchanged() {
        let vault_id = Uuid::new_v4();
        let item_id = Uuid::new_v4();
        let cred_id = Uuid::new_v4();
        let cipher = VaultCipher::new(vault_id);

        assert_eq!(
            cipher.item_metadata_aad(item_id),
            vec![
                vault_id.to_string(),
                item_id.to_string(),
                "metadata".to_string()
            ]
        );
        assert_eq!(
            cipher.cred_aad(item_id, cred_id, "value"),
            vec![
                vault_id.to_string(),
                item_id.to_string(),
                cred_id.to_string(),
                "value".to_string()
            ]
        );
    }
}
