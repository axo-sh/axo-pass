use std::collections::BTreeMap;
use std::ops::Deref;
use std::path::Path;
use std::{fs, io};

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_with::base64::Base64;
use serde_with::serde_as;
use uuid::Uuid;

use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::vaults::autofill::item::ItemAutofill;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::encrypted_blob::EncryptedBlob;
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::format::signing::{self, VaultSigner};
use crate::secrets::vaults::format::vault_cipher::VaultCipher;
use crate::secrets::vaults::model::{
    DeletedInfo, HistoryMetadata, VaultCredentialMetadata, VaultItemCredentialOverview,
    VaultItemMetadata, VaultItemOverview, VaultMetadata,
};
use crate::secrets::vaults::storage::handle::validate_key;

/// Vault file format written and read by this build.
pub const VAULT_FORMAT: u32 = 2;

/// Format of a vault file without a `format` field. Format 1 is not read.
const FORMAT_WITHOUT_ENVELOPE: u32 = 1;

/// Outer object of a vault file.
#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultEnvelope<'a> {
    format: u32,
    /// DER signature by `device-signing-key` over
    /// [`VaultEnvelope::signed_message`], written as base64. Read as optional
    /// so the header of an unsigned file can be read. Load refuses an
    /// unsigned file.
    #[serde_as(as = "Option<Base64>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<Vec<u8>>,
    #[serde(borrow)]
    vault: &'a RawValue,
}

impl<'a> VaultEnvelope<'a> {
    /// Envelope of the vault file `data`. Any format other than
    /// [`VAULT_FORMAT`] fails with `UnsupportedVaultFormat` before the rest
    /// of the envelope is checked. A file without a `format` field is format
    /// 1. The signature is not checked.
    fn read(data: &'a str) -> Result<Self, Error> {
        let fields: BTreeMap<String, &RawValue> =
            serde_json::from_str(data).map_err(Error::VaultDeserializationError)?;
        let format = match fields.get("format") {
            Some(format) => {
                serde_json::from_str(format.get()).map_err(Error::VaultDeserializationError)?
            },
            None => FORMAT_WITHOUT_ENVELOPE,
        };
        if format != VAULT_FORMAT {
            return Err(Error::UnsupportedVaultFormat(format));
        }
        serde_json::from_str(data).map_err(Error::VaultDeserializationError)
    }

    /// Message signed for the raw vault bytes `vault_json` in a file of format
    /// `format`. The prefix names the format.
    fn signed_message(format: u32, vault_json: &str) -> Vec<u8> {
        let mut message = format!("ap-vault-v{format}:").into_bytes();
        message.extend_from_slice(vault_json.as_bytes());
        message
    }

    /// Raw vault bytes, after their signature is checked under the key of
    /// `signer`. An unsigned file fails with `VaultSignatureMissing`, and any
    /// other failure with `VaultSignatureInvalid`.
    fn verified_vault_json(&self, signer: &dyn VaultSigner) -> Result<&'a str, Error> {
        let signature = self
            .signature
            .as_deref()
            .ok_or(Error::VaultSignatureMissing)?;
        let message = Self::signed_message(self.format, self.vault.get());
        signing::verify(&signer.verifying_key()?, &message, signature)?;
        Ok(self.vault.get())
    }

    /// Contents of a vault file of format [`VAULT_FORMAT`] holding the raw
    /// vault bytes `vault_json` unchanged, signed by `signer`.
    fn sign(vault_json: String, signer: &dyn VaultSigner) -> Result<String, Error> {
        let signature = signer.sign(&Self::signed_message(VAULT_FORMAT, &vault_json))?;
        let vault = RawValue::from_string(vault_json).map_err(Error::VaultSerializationError)?;
        let envelope = VaultEnvelope {
            format: VAULT_FORMAT,
            signature: Some(signature),
            vault: &vault,
        };
        serde_json::to_string_pretty(&envelope).map_err(Error::VaultSerializationError)
    }
}

/// Vault object of a vault file whose signature verified. Only
/// [`EncryptedVault::load`] and [`EncryptedVault::parse`] build one, so a
/// vault decrypted from a file was verified first.
///
/// The field is private, so code outside this module cannot wrap an
/// unverified vault:
///
/// ```compile_fail
/// use axo_pass_core::secrets::vaults::format::encrypted_vault::{EncryptedVault, VerifiedVault};
///
/// fn wrap(vault: EncryptedVault) -> VerifiedVault {
///     VerifiedVault(vault)
/// }
/// ```
pub struct VerifiedVault(EncryptedVault);

impl VerifiedVault {
    /// Unwrap the file key of this vault with the vault encryption key. Only a
    /// verified vault is unwrapped, so a planted `file_key` never reaches the
    /// keychain:
    ///
    /// ```compile_fail
    /// use axo_pass_core::secrets::keychain::managed_key::ManagedKey;
    /// use axo_pass_core::secrets::vaults::format::encrypted_vault::EncryptedVault;
    ///
    /// fn unwrap(key: &ManagedKey, vault: &EncryptedVault) {
    ///     let _ = vault.decrypt_file_key(key);
    /// }
    /// ```
    pub fn decrypt_file_key(&self, user_encryption_key: &ManagedKey) -> Result<VaultCipher, Error> {
        let decrypted_key = user_encryption_key
            .decrypt(self.0.file_key.as_bytes())
            .ok_or(Error::VaultFileKeyDecryptionError)?;
        Ok(VaultCipher::new_with_bytes(&decrypted_key, self.0.id))
    }

    /// Verified vault, to decrypt.
    pub(crate) fn into_inner(self) -> EncryptedVault {
        self.0
    }
}

impl Deref for VerifiedVault {
    type Target = EncryptedVault;

    fn deref(&self) -> &EncryptedVault {
        &self.0
    }
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

// EncryptedVault is the on disk representation of a vault, with metadata and
// secrets encrypted. We don't persist this in memory; see Vault. Ids are
// written as short ids and read in any form ShortId accepts. A parsed
// EncryptedVault that was not verified can be read but not unwrapped or
// decrypted. See VerifiedVault.
#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedVault {
    #[serde_as(as = "ShortId")]
    pub id: Uuid,
    /// Vault key, unique among the vault files on this Mac. Required.
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Save counter for sync. Absent if 0.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub generation: u64,
    /// Sync replica id of this copy of the vault. Absent if the vault is not
    /// synced.
    #[serde_as(as = "Option<ShortId>")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replica_id: Option<Uuid>,
    pub file_key: VaultFileKey,
    /// Vault-level metadata such as folders. Absent for a vault with none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<EncryptedBlob<VaultMetadata>>,
    #[serde_as(as = "BTreeMap<ShortId, _>")]
    pub items: BTreeMap<Uuid, EncryptedVaultItem>,
    /// Deleted items that can still be restored. Absent if empty.
    #[serde_as(as = "BTreeMap<ShortId, _>")]
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub deleted: BTreeMap<Uuid, DeletedItem>,
}

/// Struct to read just the id, key, and name of a vault file, without
/// decrypting the vault itself. Used for the locked vault list and the
/// transaction registry. Other fields are ignored.
#[serde_as]
#[derive(Deserialize)]
pub struct VaultHeader {
    #[serde_as(as = "ShortId")]
    pub id: Uuid,
    pub key: String,
    pub name: Option<String>,
}

impl VaultHeader {
    pub fn peek(vault_path: &Path) -> Result<Self, Error> {
        Self::parse(&EncryptedVault::read_file(vault_path)?)
    }

    /// Parse the header of a vault file without checking its signature. A
    /// missing key fails with `VaultDeserializationError`, and an invalid key
    /// with `InvalidVaultKey`.
    pub(crate) fn parse(vault_data: &str) -> Result<Self, Error> {
        let envelope = VaultEnvelope::read(vault_data)?;
        let header: Self =
            serde_json::from_str(envelope.vault.get()).map_err(Error::VaultDeserializationError)?;
        EncryptedVault::check_key(&header.key)?;
        Ok(header)
    }

    /// Replica id of the vault file at `vault_path`, read without checking
    /// its signature. `None` if the vault is not synced. It only picks a
    /// vault whose sync is disabled before a delete, and the disable
    /// verifies the file.
    pub(crate) fn peek_replica_id(vault_path: &Path) -> Result<Option<Uuid>, Error> {
        #[serde_as]
        #[derive(Deserialize)]
        struct Synced {
            #[serde_as(as = "Option<ShortId>")]
            #[serde(default)]
            replica_id: Option<Uuid>,
        }
        let contents = EncryptedVault::read_file(vault_path)?;
        let envelope = VaultEnvelope::read(&contents)?;
        let synced: Synced =
            serde_json::from_str(envelope.vault.get()).map_err(Error::VaultDeserializationError)?;
        Ok(synced.replica_id)
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

    /// Read the vault file at `vault_path` and verify it under the key of
    /// `signer`. See [`Self::parse`].
    pub fn load(vault_path: &Path, signer: &dyn VaultSigner) -> Result<VerifiedVault, Error> {
        log::debug!("Reading vault from file: {}", vault_path.display());
        Self::parse(&Self::read_file(vault_path)?, signer)
    }

    /// Verify the contents of a vault file under the key of `signer`, then
    /// parse the vault object. The signature is checked over the raw vault
    /// bytes before they are parsed. An unsigned file fails with
    /// `VaultSignatureMissing`, a signature that does not verify with
    /// `VaultSignatureInvalid`, and an invalid key with `InvalidVaultKey`.
    pub(crate) fn parse(
        vault_data: &str,
        signer: &dyn VaultSigner,
    ) -> Result<VerifiedVault, Error> {
        let envelope = VaultEnvelope::read(vault_data)?;
        let vault_json = envelope.verified_vault_json(signer)?;
        let vault: Self =
            serde_json::from_str(vault_json).map_err(Error::VaultDeserializationError)?;
        Self::check_key(&vault.key)?;
        Ok(VerifiedVault(vault))
    }

    /// Raw vault bytes of the vault file `vault_data`, without checking the
    /// signature. Used only to compare a file with the vault about to be
    /// saved over it.
    pub(crate) fn raw_vault_json(vault_data: &str) -> Result<&str, Error> {
        Ok(VaultEnvelope::read(vault_data)?.vault.get())
    }

    /// Fail if a key read from a vault file is not a valid vault key. Keys are
    /// written normalized, so a key with an upper case letter is refused.
    fn check_key(key: &str) -> Result<(), Error> {
        if !validate_key(key) {
            return Err(Error::InvalidVaultKey(key.to_string()));
        }
        Ok(())
    }

    /// Raw vault bytes of this vault, as a vault file of format
    /// [`VAULT_FORMAT`] holds them and signs them.
    pub(crate) fn to_vault_json(&self) -> Result<String, Error> {
        // Indent the vault JSON to its depth in the envelope. JSON strings
        // hold no raw newlines, so only line breaks between tokens change.
        Ok(serde_json::to_string_pretty(self)
            .map_err(Error::VaultSerializationError)?
            .replace('\n', "\n  "))
    }

    /// Contents of a vault file of format [`VAULT_FORMAT`] holding the raw
    /// vault bytes `vault_json`, signed by `signer`.
    pub(crate) fn sign_vault_json(
        vault_json: String,
        signer: &dyn VaultSigner,
    ) -> Result<String, Error> {
        VaultEnvelope::sign(vault_json, signer)
    }

    /// Contents of the vault file `vault_data` of vault `id`, signed again by
    /// `signer`, for the confirmed re-sign after signing key loss. The old
    /// signature is not checked. The raw vault bytes are unchanged. They must
    /// parse as a vault of id `id` with a valid key, or the file is refused
    /// with the error of the parse, or `VaultNotFound` for another id.
    pub(crate) fn sign_again(
        vault_data: &str,
        id: Uuid,
        signer: &dyn VaultSigner,
    ) -> Result<String, Error> {
        let vault_json = Self::raw_vault_json(vault_data)?;
        let vault: Self =
            serde_json::from_str(vault_json).map_err(Error::VaultDeserializationError)?;
        Self::check_key(&vault.key)?;
        if vault.id != id {
            return Err(Error::VaultNotFound(ShortId::encode_uuid(id)));
        }
        Self::sign_vault_json(vault_json.to_string(), signer)
    }

    /// Contents of a vault file of format [`VAULT_FORMAT`] for this vault,
    /// signed by `signer`. Saves sign through [`Self::sign_vault_json`], so
    /// they can compare the raw vault bytes first.
    #[cfg(test)]
    pub(crate) fn to_file_contents(&self, signer: &dyn VaultSigner) -> Result<String, Error> {
        Self::sign_vault_json(self.to_vault_json()?, signer)
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

    /// Check that every id in the vault file `contents` is a short id. Returns
    /// the number of ids checked.
    #[cfg(test)]
    pub(crate) fn assert_short_ids_for_test(contents: &str) -> usize {
        use serde_json::Value;

        use crate::secrets::vaults::format::short_id::SHORT_ID_LEN;

        fn check(id: &str, at: &str, count: &mut usize) {
            assert_eq!(id.len(), SHORT_ID_LEN, "{at}: {id}");
            assert!(ShortId::decode(id).is_ok(), "{at}: {id}");
            *count += 1;
        }

        fn check_item(item: &Value, at: &str, count: &mut usize) {
            let credentials = item["credentials"].as_object().unwrap();
            let deleted = item.get("deleted").and_then(Value::as_object);
            for (id, credential) in credentials {
                check(id, &format!("{at}/credentials"), count);
                check_credential(credential, at, count);
            }
            for (id, deleted) in deleted.into_iter().flatten() {
                check(id, &format!("{at}/deleted"), count);
                check_credential(&deleted["credential"], at, count);
            }
        }

        fn check_credential(credential: &Value, at: &str, count: &mut usize) {
            let history = credential.get("history").and_then(Value::as_array);
            for entry in history.into_iter().flatten() {
                check(
                    entry["id"].as_str().unwrap(),
                    &format!("{at}/history"),
                    count,
                );
            }
        }

        let file: Value = serde_json::from_str(contents).unwrap();
        let vault = &file["vault"];
        let mut count = 0;
        check(vault["id"].as_str().unwrap(), "id", &mut count);
        if let Some(replica_id) = vault.get("replica_id") {
            check(replica_id.as_str().unwrap(), "replica_id", &mut count);
        }
        for (id, item) in vault["items"].as_object().unwrap() {
            check(id, "items", &mut count);
            check_item(item, &format!("items/{id}"), &mut count);
        }
        let deleted = vault.get("deleted").and_then(Value::as_object);
        for (id, deleted) in deleted.into_iter().flatten() {
            check(id, "deleted", &mut count);
            check_item(&deleted["item"], &format!("deleted/{id}"), &mut count);
        }
        count
    }

    /// Contents of the vault file `file`, edited as JSON, with its `vault`
    /// object signed again by `signer` under the [`VAULT_FORMAT`] prefix. The
    /// other top-level fields of `file` are kept, and `signature` is
    /// replaced.
    #[cfg(test)]
    pub(crate) fn sign_file_for_test(file: &serde_json::Value, signer: &dyn VaultSigner) -> String {
        let vault_json = serde_json::to_string_pretty(&file["vault"])
            .unwrap()
            .replace('\n', "\n  ");
        let signed = VaultEnvelope::sign(vault_json, signer).unwrap();
        let mut fields: BTreeMap<String, Box<RawValue>> = serde_json::from_str(&signed).unwrap();
        for (key, value) in file.as_object().unwrap() {
            if key != "signature" && key != "vault" {
                fields.insert(
                    key.clone(),
                    RawValue::from_string(value.to_string()).unwrap(),
                );
            }
        }
        serde_json::to_string_pretty(&fields).unwrap()
    }

    /// Vault file `contents` with every short id in the vault object written
    /// in the hyphenated form, as files were before short ids, and signed
    /// again by `signer`. Map keys and `id` and `replica_id` values are
    /// rewritten. Blob plaintext is not.
    #[cfg(test)]
    pub(crate) fn hyphenate_ids_for_test(contents: &str, signer: &dyn VaultSigner) -> String {
        use serde_json::Value;

        use crate::secrets::vaults::format::short_id::SHORT_ID_LEN;

        fn hyphenated(text: &str) -> Option<String> {
            (text.len() == SHORT_ID_LEN)
                .then(|| ShortId::parse_uuid(text).ok())
                .flatten()
                .map(|id| id.hyphenated().to_string())
        }

        fn rewrite(value: &mut Value) {
            match value {
                Value::Object(map) => {
                    let entries = std::mem::take(map);
                    for (key, mut entry) in entries {
                        let is_id = key == "id" || key == "replica_id";
                        match (&entry, is_id) {
                            (Value::String(text), true) => {
                                entry = Value::String(hyphenated(text).unwrap());
                            },
                            _ => rewrite(&mut entry),
                        }
                        map.insert(hyphenated(&key).unwrap_or(key), entry);
                    }
                },
                Value::Array(values) => values.iter_mut().for_each(rewrite),
                _ => {},
            }
        }

        let mut file: Value = serde_json::from_str(contents).unwrap();
        rewrite(&mut file["vault"]);
        Self::sign_file_for_test(&file, signer)
    }
}

/// Vault file key wrapped by `vault-encryption-key`. Written as a base64
/// string. Any other JSON shape is refused.
#[serde_as]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(transparent)]
pub struct VaultFileKey(#[serde_as(as = "Base64")] Vec<u8>);

impl VaultFileKey {
    pub fn new(wrapped: Vec<u8>) -> Self {
        Self(wrapped)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedVaultItem {
    pub metadata: EncryptedBlob<VaultItemMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autofill: Option<EncryptedBlob<ItemAutofill>>,
    #[serde_as(as = "BTreeMap<ShortId, _>")]
    pub credentials: BTreeMap<Uuid, EncryptedVaultItemCredential>,
    /// Deleted credentials that can still be restored. Absent if empty.
    #[serde_as(as = "BTreeMap<ShortId, _>")]
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub deleted: BTreeMap<Uuid, DeletedCredential>,
}

/// A deleted item. The item blobs are the same as when it was live, including
/// its credentials and its own deleted credentials, so moving it to or from
/// deleted needs no re-encryption.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeletedItem {
    pub item: EncryptedVaultItem,
    pub info: EncryptedBlob<DeletedInfo>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct EncryptedVaultItemCredential {
    pub metadata: EncryptedBlob<VaultCredentialMetadata>,
    pub value: EncryptedBlob<String>,
    /// History entries, oldest first. Absent if empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<HistoryEntry>,
}

/// A history entry of a credential. Blobs are encrypted under the entry id as
/// well as the credential, so a replaced value cannot be swapped into the live
/// value's place.
#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct HistoryEntry {
    #[serde_as(as = "ShortId")]
    pub id: Uuid,
    pub metadata: EncryptedBlob<HistoryMetadata>,
    /// Value the entry holds, as its kind states. Absent if none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<EncryptedBlob<String>>,
}

/// A deleted credential. The credential blobs are the same as when it was
/// live, so moving it to or from deleted needs no re-encryption.
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DeletedCredential {
    pub credential: EncryptedVaultItemCredential,
    pub info: EncryptedBlob<DeletedInfo>,
}

#[cfg(test)]
mod schema_tests;

#[cfg(test)]
mod tests;
