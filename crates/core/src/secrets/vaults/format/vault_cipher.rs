use aes_gcm::{Aes256Gcm, KeyInit};
use secrecy::{ExposeSecret, SecretBox};
use uuid::Uuid;

use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::encrypted_blob::EncryptedBlob;
use crate::secrets::vaults::item_autofill::ItemAutofill;
use crate::secrets::vaults::vault::{
    DeletedInfo, HistoryInfo, VaultCredentialMetadata, VaultItemMetadata, VaultMetadata,
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

    /// A second cipher with the same key, for a reloaded copy of the vault.
    pub(crate) fn duplicate(&self) -> Self {
        Self::new_with_bytes(self.cipher_bytes.expose_secret(), self.vault_id)
    }

    pub(crate) fn vault_id(&self) -> Uuid {
        self.vault_id
    }

    // AAD binding each blob to its location in the vault. Changing any of
    // these makes existing vaults undecryptable.

    fn vault_metadata_aad(&self) -> Vec<String> {
        vec![self.vault_id.to_string(), "metadata".to_string()]
    }

    fn item_metadata_aad(&self, item_id: Uuid) -> Vec<String> {
        vec![
            self.vault_id.to_string(),
            item_id.to_string(),
            "metadata".to_string(),
        ]
    }

    fn deleted_item_info_aad(&self, item_id: Uuid) -> Vec<String> {
        vec![
            self.vault_id.to_string(),
            item_id.to_string(),
            "deleted".to_string(),
        ]
    }

    /// `part` is `"metadata"`, `"value"`, `"deleted"`, `"history:<id>"`, or
    /// `"history-info:<id>"`.
    fn cred_aad(&self, item_id: Uuid, cred_id: Uuid, part: &str) -> Vec<String> {
        vec![
            self.vault_id.to_string(),
            item_id.to_string(),
            cred_id.to_string(),
            part.to_string(),
        ]
    }

    pub fn encrypt_vault_metadata(
        &self,
        value: &VaultMetadata,
    ) -> Result<EncryptedBlob<VaultMetadata>, Error> {
        EncryptedBlob::encrypt(value, &self.cipher, self.vault_metadata_aad())
    }

    pub fn decrypt_vault_metadata(
        &self,
        blob: &EncryptedBlob<VaultMetadata>,
    ) -> Result<SecretBox<VaultMetadata>, Error> {
        blob.decrypt(&self.cipher, self.vault_metadata_aad())
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

    pub fn encrypt_item_autofill(
        &self,
        item_id: Uuid,
        value: &ItemAutofill,
    ) -> Result<EncryptedBlob<ItemAutofill>, Error> {
        EncryptedBlob::encrypt(
            value,
            &self.cipher,
            vec![
                self.vault_id.to_string(),
                item_id.to_string(),
                "autofill".to_string(),
            ],
        )
    }

    pub fn decrypt_item_autofill(
        &self,
        item_id: Uuid,
        blob: &EncryptedBlob<ItemAutofill>,
    ) -> Result<SecretBox<ItemAutofill>, Error> {
        blob.decrypt(
            &self.cipher,
            vec![
                self.vault_id.to_string(),
                item_id.to_string(),
                "autofill".to_string(),
            ],
        )
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

    pub fn encrypt_deleted_info(
        &self,
        item_id: Uuid,
        cred_id: Uuid,
        value: &DeletedInfo,
    ) -> Result<EncryptedBlob<DeletedInfo>, Error> {
        EncryptedBlob::encrypt(
            value,
            &self.cipher,
            self.cred_aad(item_id, cred_id, "deleted"),
        )
    }

    pub fn decrypt_deleted_info(
        &self,
        item_id: Uuid,
        cred_id: Uuid,
        blob: &EncryptedBlob<DeletedInfo>,
    ) -> Result<SecretBox<DeletedInfo>, Error> {
        blob.decrypt(&self.cipher, self.cred_aad(item_id, cred_id, "deleted"))
    }

    fn history_value_aad(&self, item_id: Uuid, cred_id: Uuid, entry_id: Uuid) -> Vec<String> {
        self.cred_aad(item_id, cred_id, &format!("history:{entry_id}"))
    }

    fn history_info_aad(&self, item_id: Uuid, cred_id: Uuid, entry_id: Uuid) -> Vec<String> {
        self.cred_aad(item_id, cred_id, &format!("history-info:{entry_id}"))
    }

    pub fn encrypt_history_value(
        &self,
        item_id: Uuid,
        cred_id: Uuid,
        entry_id: Uuid,
        value: &str,
    ) -> Result<EncryptedBlob<String>, Error> {
        EncryptedBlob::encrypt(
            &value.to_string(),
            &self.cipher,
            self.history_value_aad(item_id, cred_id, entry_id),
        )
    }

    pub fn decrypt_history_value(
        &self,
        item_id: Uuid,
        cred_id: Uuid,
        entry_id: Uuid,
        blob: &EncryptedBlob<String>,
    ) -> Result<SecretBox<String>, Error> {
        blob.decrypt(
            &self.cipher,
            self.history_value_aad(item_id, cred_id, entry_id),
        )
    }

    pub fn encrypt_history_info(
        &self,
        item_id: Uuid,
        cred_id: Uuid,
        entry_id: Uuid,
        value: &HistoryInfo,
    ) -> Result<EncryptedBlob<HistoryInfo>, Error> {
        EncryptedBlob::encrypt(
            value,
            &self.cipher,
            self.history_info_aad(item_id, cred_id, entry_id),
        )
    }

    pub fn decrypt_history_info(
        &self,
        item_id: Uuid,
        cred_id: Uuid,
        entry_id: Uuid,
        blob: &EncryptedBlob<HistoryInfo>,
    ) -> Result<SecretBox<HistoryInfo>, Error> {
        blob.decrypt(
            &self.cipher,
            self.history_info_aad(item_id, cred_id, entry_id),
        )
    }

    pub fn encrypt_deleted_item_info(
        &self,
        item_id: Uuid,
        value: &DeletedInfo,
    ) -> Result<EncryptedBlob<DeletedInfo>, Error> {
        EncryptedBlob::encrypt(value, &self.cipher, self.deleted_item_info_aad(item_id))
    }

    pub fn decrypt_deleted_item_info(
        &self,
        item_id: Uuid,
        blob: &EncryptedBlob<DeletedInfo>,
    ) -> Result<SecretBox<DeletedInfo>, Error> {
        blob.decrypt(&self.cipher, self.deleted_item_info_aad(item_id))
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
            cipher.vault_metadata_aad(),
            vec![vault_id.to_string(), "metadata".to_string()]
        );
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
        assert_eq!(
            cipher.cred_aad(item_id, cred_id, "deleted"),
            vec![
                vault_id.to_string(),
                item_id.to_string(),
                cred_id.to_string(),
                "deleted".to_string()
            ]
        );
        let entry_id = Uuid::new_v4();
        assert_eq!(
            cipher.history_value_aad(item_id, cred_id, entry_id),
            vec![
                vault_id.to_string(),
                item_id.to_string(),
                cred_id.to_string(),
                format!("history:{entry_id}")
            ]
        );
        assert_eq!(
            cipher.history_info_aad(item_id, cred_id, entry_id),
            vec![
                vault_id.to_string(),
                item_id.to_string(),
                cred_id.to_string(),
                format!("history-info:{entry_id}")
            ]
        );
        assert_eq!(
            cipher.deleted_item_info_aad(item_id),
            vec![
                vault_id.to_string(),
                item_id.to_string(),
                "deleted".to_string()
            ]
        );
    }
}
