use aes_gcm::{Aes256Gcm, KeyInit};
use secrecy::{ExposeSecret, SecretBox};
use uuid::Uuid;

use crate::secrets::vaults::autofill::item::ItemAutofill;
use crate::secrets::vaults::bundle::exported_bundle::RawFileKey;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::encrypted_blob::EncryptedBlob;
#[cfg(test)]
use crate::secrets::vaults::format::encrypted_vault::EncryptedVault;
use crate::secrets::vaults::format::encrypted_vault::HistoryEntry;
use crate::secrets::vaults::model::{
    DeletedInfo, HistoryInfo, VaultCredentialMetadata, VaultItemMetadata, VaultMetadata,
};

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
    // these makes existing vaults undecryptable. Ids are in the hyphenated
    // UUID form, not the short form of the vault file.

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

    fn item_autofill_aad(&self, item_id: Uuid) -> Vec<String> {
        vec![
            self.vault_id.to_string(),
            item_id.to_string(),
            "autofill".to_string(),
        ]
    }

    pub fn encrypt_item_autofill(
        &self,
        item_id: Uuid,
        value: &ItemAutofill,
    ) -> Result<EncryptedBlob<ItemAutofill>, Error> {
        EncryptedBlob::encrypt(value, &self.cipher, self.item_autofill_aad(item_id))
    }

    pub fn decrypt_item_autofill(
        &self,
        item_id: Uuid,
        blob: &EncryptedBlob<ItemAutofill>,
    ) -> Result<SecretBox<ItemAutofill>, Error> {
        blob.decrypt(&self.cipher, self.item_autofill_aad(item_id))
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

    /// Credential value decrypted with this cipher and encrypted with `to`.
    pub(crate) fn rekey_cred_value(
        &self,
        to: &VaultCipher,
        item_id: Uuid,
        cred_id: Uuid,
        blob: &EncryptedBlob<String>,
    ) -> Result<EncryptedBlob<String>, Error> {
        let value = self.decrypt_cred_value(item_id, cred_id, blob)?;
        to.encrypt_cred_value(item_id, cred_id, value.expose_secret())
    }

    /// Check that the info of each previous value of a credential decrypts
    /// and parses. The values are not decrypted.
    pub(crate) fn check_history_info(
        &self,
        item_id: Uuid,
        cred_id: Uuid,
        history: &[HistoryEntry],
    ) -> Result<(), Error> {
        for entry in history {
            self.decrypt_history_info(item_id, cred_id, entry.id, &entry.info)?;
        }
        Ok(())
    }

    /// Previous values of a credential decrypted with this cipher and
    /// encrypted with `to`. Entry ids and order are kept.
    pub(crate) fn rekey_history(
        &self,
        to: &VaultCipher,
        item_id: Uuid,
        cred_id: Uuid,
        history: &[HistoryEntry],
    ) -> Result<Vec<HistoryEntry>, Error> {
        history
            .iter()
            .map(|entry| {
                let value = self.decrypt_history_value(item_id, cred_id, entry.id, &entry.value)?;
                let info = self.decrypt_history_info(item_id, cred_id, entry.id, &entry.info)?;
                Ok(HistoryEntry {
                    id: entry.id,
                    value: to.encrypt_history_value(
                        item_id,
                        cred_id,
                        entry.id,
                        value.expose_secret(),
                    )?,
                    info: to.encrypt_history_info(
                        item_id,
                        cred_id,
                        entry.id,
                        info.expose_secret(),
                    )?,
                })
            })
            .collect()
    }

    /// Deleted credential info decrypted with this cipher and encrypted with
    /// `to`.
    pub(crate) fn rekey_deleted_info(
        &self,
        to: &VaultCipher,
        item_id: Uuid,
        cred_id: Uuid,
        blob: &EncryptedBlob<DeletedInfo>,
    ) -> Result<EncryptedBlob<DeletedInfo>, Error> {
        let info = self.decrypt_deleted_info(item_id, cred_id, blob)?;
        to.encrypt_deleted_info(item_id, cred_id, info.expose_secret())
    }

    /// Deleted item info decrypted with this cipher and encrypted with `to`.
    pub(crate) fn rekey_deleted_item_info(
        &self,
        to: &VaultCipher,
        item_id: Uuid,
        blob: &EncryptedBlob<DeletedInfo>,
    ) -> Result<EncryptedBlob<DeletedInfo>, Error> {
        let info = self.decrypt_deleted_item_info(item_id, blob)?;
        to.encrypt_deleted_item_info(item_id, info.expose_secret())
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

    /// Raw file key, for tests.
    #[cfg(test)]
    pub(crate) fn key_bytes_for_test(&self) -> Vec<u8> {
        self.cipher_bytes.expose_secret().clone()
    }

    /// Cipher with the same key and another vault id, for tests.
    #[cfg(test)]
    pub(crate) fn with_vault_id_for_test(&self, vault_id: Uuid) -> Self {
        Self::new_with_bytes(self.cipher_bytes.expose_secret(), vault_id)
    }

    /// Credential metadata blob whose plaintext is `value`, for tests that
    /// store fields `VaultCredentialMetadata` does not hold.
    #[cfg(test)]
    pub(crate) fn encrypt_cred_metadata_as_for_test<T>(
        &self,
        item_id: Uuid,
        cred_id: Uuid,
        value: &T,
    ) -> EncryptedBlob<VaultCredentialMetadata>
    where
        T: serde::Serialize + serde::de::DeserializeOwned + zeroize::Zeroize,
    {
        let blob = EncryptedBlob::encrypt(
            value,
            &self.cipher,
            self.cred_aad(item_id, cred_id, "metadata"),
        )
        .unwrap();
        serde_json::from_value(serde_json::to_value(&blob).unwrap()).unwrap()
    }

    /// Plaintext of a credential metadata blob read as `T`, for tests.
    #[cfg(test)]
    pub(crate) fn decrypt_cred_metadata_as_for_test<T>(
        &self,
        item_id: Uuid,
        cred_id: Uuid,
        blob: &EncryptedBlob<VaultCredentialMetadata>,
    ) -> SecretBox<T>
    where
        T: serde::Serialize + serde::de::DeserializeOwned + zeroize::Zeroize,
    {
        let blob: EncryptedBlob<T> =
            serde_json::from_value(serde_json::to_value(blob).unwrap()).unwrap();
        blob.decrypt(&self.cipher, self.cred_aad(item_id, cred_id, "metadata"))
            .unwrap()
    }

    /// Add the field `unknown_field` to the plaintext object of the blob
    /// number `n` in `vault`, for tests. Only blobs whose plaintext is a
    /// struct are counted, in a fixed order. Returns the place and kind of the
    /// blob as [`Self::blob_results_for_test`] names them, or `None` if the
    /// vault has `n` or fewer such blobs.
    #[cfg(test)]
    pub(crate) fn add_unknown_field_for_test(
        &self,
        vault: &mut EncryptedVault,
        n: usize,
    ) -> Option<String> {
        use crate::secrets::vaults::format::encrypted_vault::{
            EncryptedVaultItem, EncryptedVaultItemCredential,
        };

        /// Blob plaintext read as any JSON value.
        #[derive(serde::Serialize, serde::Deserialize, zeroize::Zeroize)]
        #[serde(transparent)]
        struct LoosePlaintext(#[zeroize(skip)] serde_json::Value);

        struct Walk<'a> {
            cipher: &'a VaultCipher,
            target: usize,
            seen: usize,
            found: Option<String>,
        }

        impl Walk<'_> {
            fn visit<T>(
                &mut self,
                place: &str,
                kind: &str,
                blob: &mut EncryptedBlob<T>,
                aad: Vec<String>,
            ) {
                if self.seen == self.target {
                    let loose: EncryptedBlob<LoosePlaintext> =
                        serde_json::from_value(serde_json::to_value(&*blob).unwrap()).unwrap();
                    let plaintext = loose.decrypt(&self.cipher.cipher, aad.clone()).unwrap();
                    let mut value = plaintext.expose_secret().0.clone();
                    let object = value.as_object_mut().unwrap();
                    object.insert("unknown_field".to_string(), serde_json::Value::from(1));
                    let edited =
                        EncryptedBlob::encrypt(&LoosePlaintext(value), &self.cipher.cipher, aad)
                            .unwrap();
                    *blob = serde_json::from_value(serde_json::to_value(&edited).unwrap()).unwrap();
                    self.found = Some(format!("{place}: {kind}"));
                }
                self.seen += 1;
            }

            fn credential(
                &mut self,
                place: &str,
                item_id: Uuid,
                cred_id: Uuid,
                cred: &mut EncryptedVaultItemCredential,
            ) {
                let aad = self.cipher.cred_aad(item_id, cred_id, "metadata");
                self.visit(place, "credential metadata", &mut cred.metadata, aad);
                for entry in &mut cred.history {
                    let aad = self.cipher.history_info_aad(item_id, cred_id, entry.id);
                    self.visit(place, "history info", &mut entry.info, aad);
                }
            }

            fn item(&mut self, place: &str, item_id: Uuid, item: &mut EncryptedVaultItem) {
                let aad = self.cipher.item_metadata_aad(item_id);
                self.visit(place, "item metadata", &mut item.metadata, aad);
                if let Some(blob) = &mut item.autofill {
                    let aad = self.cipher.item_autofill_aad(item_id);
                    self.visit(place, "item autofill", blob, aad);
                }
                for (cred_id, cred) in &mut item.credentials {
                    self.credential(place, item_id, *cred_id, cred);
                }
                let deleted_place = format!("{place} deleted credential");
                for (cred_id, deleted) in &mut item.deleted {
                    self.credential(&deleted_place, item_id, *cred_id, &mut deleted.credential);
                    let aad = self.cipher.cred_aad(item_id, *cred_id, "deleted");
                    self.visit(&deleted_place, "deleted info", &mut deleted.info, aad);
                }
            }
        }

        let mut walk = Walk {
            cipher: self,
            target: n,
            seen: 0,
            found: None,
        };
        if let Some(blob) = &mut vault.metadata {
            walk.visit("live", "vault metadata", blob, self.vault_metadata_aad());
        }
        for (item_id, item) in &mut vault.items {
            walk.item("live", *item_id, item);
        }
        for (item_id, deleted) in &mut vault.deleted {
            let aad = self.deleted_item_info_aad(*item_id);
            walk.visit("deleted item", "deleted item info", &mut deleted.info, aad);
            walk.item("deleted item", *item_id, &mut deleted.item);
        }
        walk.found
    }

    /// Whether each blob in `vault` decrypts under this cipher, by place and
    /// blob kind. Keys are `"{place}: {kind}"`. Places are `live`,
    /// `live deleted credential`, `deleted item`, and
    /// `deleted item deleted credential`.
    #[cfg(test)]
    pub(crate) fn blob_results_for_test(
        &self,
        vault: &EncryptedVault,
    ) -> std::collections::BTreeMap<String, Vec<bool>> {
        use std::collections::BTreeMap;

        use crate::secrets::vaults::format::encrypted_vault::{
            EncryptedVaultItem, EncryptedVaultItemCredential,
        };

        type Results = BTreeMap<String, Vec<bool>>;

        fn record(results: &mut Results, place: &str, kind: &str, ok: bool) {
            results
                .entry(format!("{place}: {kind}"))
                .or_default()
                .push(ok);
        }

        fn credential(
            cipher: &VaultCipher,
            results: &mut Results,
            place: &str,
            item_id: Uuid,
            cred_id: Uuid,
            cred: &EncryptedVaultItemCredential,
        ) {
            let metadata = cipher.decrypt_cred_metadata(item_id, cred_id, &cred.metadata);
            record(results, place, "credential metadata", metadata.is_ok());
            let value = cipher.decrypt_cred_value(item_id, cred_id, &cred.value);
            record(results, place, "value", value.is_ok());
            for entry in &cred.history {
                let value = cipher.decrypt_history_value(item_id, cred_id, entry.id, &entry.value);
                record(results, place, "history value", value.is_ok());
                let info = cipher.decrypt_history_info(item_id, cred_id, entry.id, &entry.info);
                record(results, place, "history info", info.is_ok());
            }
        }

        fn item(
            cipher: &VaultCipher,
            results: &mut Results,
            place: &str,
            item_id: Uuid,
            item: &EncryptedVaultItem,
        ) {
            let metadata = cipher.decrypt_item_metadata(item_id, &item.metadata);
            record(results, place, "item metadata", metadata.is_ok());
            if let Some(blob) = &item.autofill {
                let autofill = cipher.decrypt_item_autofill(item_id, blob);
                record(results, place, "item autofill", autofill.is_ok());
            }
            for (cred_id, cred) in &item.credentials {
                credential(cipher, results, place, item_id, *cred_id, cred);
            }
            let deleted_place = format!("{place} deleted credential");
            for (cred_id, deleted) in &item.deleted {
                credential(
                    cipher,
                    results,
                    &deleted_place,
                    item_id,
                    *cred_id,
                    &deleted.credential,
                );
                let info = cipher.decrypt_deleted_info(item_id, *cred_id, &deleted.info);
                record(results, &deleted_place, "deleted info", info.is_ok());
            }
        }

        let mut results = Results::new();
        if let Some(blob) = &vault.metadata {
            let metadata = self.decrypt_vault_metadata(blob);
            record(&mut results, "live", "vault metadata", metadata.is_ok());
        }
        for (item_id, encrypted) in &vault.items {
            item(self, &mut results, "live", *item_id, encrypted);
        }
        for (item_id, deleted) in &vault.deleted {
            let info = self.decrypt_deleted_item_info(*item_id, &deleted.info);
            record(
                &mut results,
                "deleted item",
                "deleted item info",
                info.is_ok(),
            );
            item(self, &mut results, "deleted item", *item_id, &deleted.item);
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::vaults::format::short_id::ShortId;

    #[test]
    fn blob_under_hyphenated_aad_decrypts() {
        let vault_id = Uuid::parse_str("5355e6aa-868d-43ce-824e-7b7002baddd2").unwrap();
        let item_id = Uuid::parse_str("f81d4fae-7dec-11d0-a765-00a0c91e6bf6").unwrap();
        let cred_id = Uuid::parse_str("00000001-0000-4000-8000-000000000000").unwrap();
        let cipher = VaultCipher::new(vault_id);
        let aad = vec![
            "5355e6aa-868d-43ce-824e-7b7002baddd2".to_string(),
            "f81d4fae-7dec-11d0-a765-00a0c91e6bf6".to_string(),
            "00000001-0000-4000-8000-000000000000".to_string(),
            "value".to_string(),
        ];
        let blob = EncryptedBlob::encrypt(&"secret".to_string(), &cipher.cipher, aad).unwrap();

        let value = cipher.decrypt_cred_value(item_id, cred_id, &blob).unwrap();
        assert_eq!(value.expose_secret(), "secret");

        // The short form is not the AAD.
        let short_aad = vec![
            ShortId::encode_uuid(vault_id),
            ShortId::encode_uuid(item_id),
            ShortId::encode_uuid(cred_id),
            "value".to_string(),
        ];
        assert!(blob.decrypt(&cipher.cipher, short_aad).is_err());
    }

    #[test]
    fn aad_layout_unchanged() {
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
