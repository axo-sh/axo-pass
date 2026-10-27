use std::collections::BTreeMap;
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
use crate::secrets::vaults::format::vault_cipher::VaultCipher;
use crate::secrets::vaults::model::{
    DeletedInfo, HistoryInfo, VaultCredentialMetadata, VaultItemCredentialOverview,
    VaultItemMetadata, VaultItemOverview, VaultMetadata,
};
use crate::secrets::vaults::storage::handle::validate_key;

/// Vault file format written and read by this build.
pub const VAULT_FORMAT: u32 = 2;

/// Format of a vault file without a `format` field. Format 1 is not read.
const FORMAT_WITHOUT_ENVELOPE: u32 = 1;

/// Outer object of a vault file.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultEnvelope<'a> {
    format: u32,
    #[serde(borrow)]
    vault: &'a RawValue,
}

impl<'a> VaultEnvelope<'a> {
    /// `vault` field of the vault file `data`. Any format other than
    /// [`VAULT_FORMAT`] fails with `UnsupportedVaultFormat` before the rest
    /// of the envelope is checked. A file without a `format` field is format
    /// 1.
    fn vault_json(data: &'a str) -> Result<&'a RawValue, Error> {
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
        let envelope: Self =
            serde_json::from_str(data).map_err(Error::VaultDeserializationError)?;
        Ok(envelope.vault)
    }
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

// EncryptedVault is the on disk representation of a vault, with metadata and
// secrets encrypted. We don't persist this in memory; see Vault. Ids are
// written as short ids and read in any form ShortId accepts.
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
    /// Save counter for sync. Absent if 0. Not read yet.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub generation: u64,
    /// Sync replica id of this copy of the vault. Absent if the vault is not
    /// synced. Not read yet.
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

    /// Parse the header of a vault file. A missing key fails with
    /// `VaultDeserializationError`, and an invalid key with
    /// `InvalidVaultKey`.
    pub(crate) fn parse(vault_data: &str) -> Result<Self, Error> {
        let vault = VaultEnvelope::vault_json(vault_data)?;
        let header: Self =
            serde_json::from_str(vault.get()).map_err(Error::VaultDeserializationError)?;
        EncryptedVault::check_key(&header.key)?;
        Ok(header)
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

    /// Parse the contents of a vault file. An invalid key fails with
    /// `InvalidVaultKey`.
    pub(crate) fn parse(vault_data: &str) -> Result<Self, Error> {
        let vault = VaultEnvelope::vault_json(vault_data)?;
        let vault: Self =
            serde_json::from_str(vault.get()).map_err(Error::VaultDeserializationError)?;
        Self::check_key(&vault.key)?;
        Ok(vault)
    }

    /// Fail if a key read from a vault file is not a valid vault key. Keys are
    /// written normalized, so a key with an upper case letter is refused.
    fn check_key(key: &str) -> Result<(), Error> {
        if !validate_key(key) {
            return Err(Error::InvalidVaultKey(key.to_string()));
        }
        Ok(())
    }

    /// Contents of a vault file of format [`VAULT_FORMAT`] for this vault.
    pub(crate) fn to_file_contents(&self) -> Result<String, Error> {
        // Indent the vault JSON to its depth in the envelope. JSON strings
        // hold no raw newlines, so only line breaks between tokens change.
        let vault = serde_json::to_string_pretty(self)
            .map_err(Error::VaultSerializationError)?
            .replace('\n', "\n  ");
        let vault = RawValue::from_string(vault).map_err(Error::VaultSerializationError)?;
        let envelope = VaultEnvelope {
            format: VAULT_FORMAT,
            vault: &vault,
        };
        serde_json::to_string_pretty(&envelope).map_err(Error::VaultSerializationError)
    }

    pub fn decrypt_file_key(&self, user_encryption_key: &ManagedKey) -> Result<VaultCipher, Error> {
        let decrypted_key = user_encryption_key
            .decrypt(self.file_key.as_bytes())
            .ok_or(Error::VaultFileKeyDecryptionError)?;
        Ok(VaultCipher::new_with_bytes(&decrypted_key, self.id))
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

    /// Vault file `contents` with every short id in the vault object written
    /// in the hyphenated form, as files were before short ids. Map keys and
    /// `id` and `replica_id` values are rewritten. Blob plaintext is not.
    #[cfg(test)]
    pub(crate) fn hyphenate_ids_for_test(contents: &str) -> String {
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
        serde_json::to_string_pretty(&file).unwrap()
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
    /// Previous values, oldest first. Absent if empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<HistoryEntry>,
}

/// A previous value of a credential. The value is encrypted under the entry id
/// as well as the credential, so it cannot be swapped into the live value's
/// place.
#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct HistoryEntry {
    #[serde_as(as = "ShortId")]
    pub id: Uuid,
    pub value: EncryptedBlob<String>,
    pub info: EncryptedBlob<HistoryInfo>,
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
mod tests {
    use secrecy::ExposeSecret;
    use serde_json::{Value, json};

    use super::*;
    use crate::secrets::vaults::model::fields::FieldKind;
    use crate::secrets::vaults::model::{Vault, VaultFolder};

    fn make_vault() -> EncryptedVault {
        EncryptedVault {
            id: Uuid::new_v4(),
            key: "test-vault".to_string(),
            name: Some("test vault".to_string()),
            generation: 0,
            replica_id: None,
            file_key: VaultFileKey::new(vec![0u8; 32]),
            metadata: None,
            items: BTreeMap::new(),
            deleted: BTreeMap::new(),
        }
    }

    /// Vault named "Filled" with entries of every kind the vault file holds.
    fn filled_vault() -> EncryptedVault {
        let mut vault = Vault::new_for_test();
        vault.name = Some("Filled".to_string());
        vault.fill_for_test();
        vault.to_encrypted(true).unwrap()
    }

    /// Format 2 file of [`filled_vault`], as JSON.
    fn filled_file() -> Value {
        let contents = filled_vault().to_file_contents().unwrap();
        serde_json::from_str(&contents).unwrap()
    }

    /// Pointer to the one entry of the map at `pointer` in `file`.
    fn only_entry(file: &Value, pointer: &str) -> String {
        let map = file.pointer(pointer).unwrap().as_object().unwrap();
        assert_eq!(map.len(), 1, "{pointer}");
        let key = map.keys().next().unwrap();
        format!("{pointer}/{key}")
    }

    /// Parse `file` after adding an unknown field to the object at `pointer`.
    fn parse_with_unknown_field(file: &Value, pointer: &str) -> Result<EncryptedVault, Error> {
        let mut file = file.clone();
        let object = file.pointer_mut(pointer).unwrap().as_object_mut().unwrap();
        object.insert("unknown".to_string(), json!(1));
        EncryptedVault::parse(&file.to_string())
    }

    fn assert_refused(result: Result<EncryptedVault, Error>, pointer: &str) {
        assert!(
            matches!(result, Err(Error::VaultDeserializationError(_))),
            "unknown field at {pointer:?} was not refused"
        );
    }

    #[test]
    fn format2_file_round_trips() {
        let vault = filled_vault();
        let contents = vault.to_file_contents().unwrap();
        let back = EncryptedVault::parse(&contents).unwrap();
        assert_eq!(back.to_file_contents().unwrap(), contents);

        let file: Value = serde_json::from_str(&contents).unwrap();
        assert_eq!(file["format"], json!(VAULT_FORMAT));
        assert!(file["vault"].get("generation").is_none());
        assert!(file["vault"].get("replica_id").is_none());
    }

    #[test]
    fn generation_and_replica_id_are_written_if_set() {
        let mut vault = filled_vault();
        let replica_id = Uuid::new_v4();
        vault.generation = 7;
        vault.replica_id = Some(replica_id);
        let contents = vault.to_file_contents().unwrap();

        let file: Value = serde_json::from_str(&contents).unwrap();
        assert_eq!(file["vault"]["generation"], json!(7));
        assert_eq!(
            file["vault"]["replica_id"],
            json!(ShortId::encode_uuid(replica_id))
        );
        let back = EncryptedVault::parse(&contents).unwrap();
        assert_eq!(back.generation, 7);
        assert_eq!(back.replica_id, Some(replica_id));
    }

    #[test]
    fn every_id_in_vault_file_is_short() {
        let mut vault = filled_vault();
        vault.replica_id = Some(Uuid::new_v4());
        let contents = vault.to_file_contents().unwrap();

        // Vault id, replica id, and the ids of the item, its credential, its
        // history entry, its deleted credential, the deleted item, and the
        // credential and deleted credential of the deleted item.
        assert!(EncryptedVault::assert_short_ids_for_test(&contents) >= 9);
        let file: Value = serde_json::from_str(&contents).unwrap();
        assert_eq!(file["vault"]["id"], json!(ShortId::encode_uuid(vault.id)));
        assert!(!contents.contains(&vault.id.hyphenated().to_string()));
    }

    #[test]
    fn vault_file_with_hyphenated_ids_loads_and_saves_short_ids() {
        let mut vault = filled_vault();
        vault.replica_id = Some(Uuid::new_v4());
        let short = vault.to_file_contents().unwrap();
        let hyphenated = EncryptedVault::hyphenate_ids_for_test(&short);
        assert!(hyphenated.contains(&format!("\"{}\"", vault.id.hyphenated())));

        let back = EncryptedVault::parse(&hyphenated).unwrap();
        assert_eq!(back.id, vault.id);
        assert_eq!(back.replica_id, vault.replica_id);
        assert_eq!(VaultHeader::parse(&hyphenated).unwrap().id, vault.id);
        assert_eq!(back.to_file_contents().unwrap(), short);
    }

    #[test]
    fn blob_plaintext_with_hyphenated_ids_loads_and_saves_short_ids() {
        let folder = Uuid::new_v4();
        let section = Uuid::new_v4();
        let cred = Uuid::new_v4();
        let short = |id: Uuid| json!(ShortId::encode_uuid(id));

        let item: VaultItemMetadata = serde_json::from_value(json!({
            "title": "Item",
            "key": "item",
            "folder": folder,
            "sections": [{ "id": section, "title": "Section" }],
        }))
        .unwrap();
        assert_eq!(item.folder, Some(folder));
        let item = serde_json::to_value(&item).unwrap();
        assert_eq!(item["folder"], short(folder));
        assert_eq!(item["sections"][0]["id"], short(section));

        let credential: VaultCredentialMetadata = serde_json::from_value(json!({
            "title": "Password",
            "key": "password",
            "section": section,
        }))
        .unwrap();
        assert_eq!(credential.section, Some(section));
        let credential = serde_json::to_value(&credential).unwrap();
        assert_eq!(credential["section"], short(section));

        let autofill: ItemAutofill = serde_json::from_value(json!({
            "username": cred,
            "password": cred,
            "totp": cred,
        }))
        .unwrap();
        assert_eq!(autofill.password, Some(cred));
        let autofill = serde_json::to_value(&autofill).unwrap();
        for slot in ["username", "password", "totp"] {
            assert_eq!(autofill[slot], short(cred), "{slot}");
        }

        let metadata: VaultMetadata = serde_json::from_value(json!({
            "folders": [{ "id": folder, "title": "Work" }],
        }))
        .unwrap();
        assert_eq!(metadata.folders[0].id, folder);
        let metadata = serde_json::to_value(&metadata).unwrap();
        assert_eq!(metadata["folders"][0]["id"], short(folder));
    }

    #[test]
    fn unknown_format_fails_closed() {
        for format in [0, 1, 3, 1000] {
            let mut file = filled_file();
            file["format"] = json!(format);
            // A later format can add envelope fields. The format is checked
            // first.
            file["signature"] = json!("c2ln");
            let contents = file.to_string();

            let result = EncryptedVault::parse(&contents);
            assert!(
                matches!(result, Err(Error::UnsupportedVaultFormat(f)) if f == format),
                "format {format}"
            );
            let result = VaultHeader::parse(&contents);
            assert!(
                matches!(result, Err(Error::UnsupportedVaultFormat(f)) if f == format),
                "format {format}"
            );
        }
    }

    #[test]
    fn format2_file_key_with_members_shape_is_refused() {
        let shapes = [
            json!([{ "public_key": "key", "wrapped_key": [1, 2, 3] }]),
            json!({ "path": "/tmp/members.json" }),
        ];
        for shape in shapes {
            let mut file = filled_file();
            file["vault"]["file_key"] = shape.clone();
            let result = EncryptedVault::parse(&file.to_string());
            assert!(
                matches!(result, Err(Error::VaultDeserializationError(_))),
                "{shape}"
            );
        }
    }

    #[test]
    fn file_without_envelope_is_refused_as_format_1() {
        // A format 1 file is the vault object without an envelope.
        let contents = serde_json::to_string_pretty(&filled_vault()).unwrap();
        assert!(matches!(
            EncryptedVault::parse(&contents),
            Err(Error::UnsupportedVaultFormat(1))
        ));
        assert!(matches!(
            VaultHeader::parse(&contents),
            Err(Error::UnsupportedVaultFormat(1))
        ));
    }

    #[test]
    fn unknown_field_in_deleted_item_is_refused() {
        let file = filled_file();
        let deleted_item = only_entry(&file, "/vault/deleted");
        let deleted_credential = only_entry(&file, &format!("{deleted_item}/item/deleted"));
        let pointers = [
            deleted_item.clone(),
            format!("{deleted_item}/item"),
            deleted_credential.clone(),
            format!("{deleted_credential}/credential"),
        ];
        for pointer in pointers {
            assert_refused(parse_with_unknown_field(&file, &pointer), &pointer);
        }
    }

    #[test]
    fn unknown_field_in_deleted_credential_is_refused() {
        let file = filled_file();
        let item = only_entry(&file, "/vault/items");
        let deleted_credential = only_entry(&file, &format!("{item}/deleted"));
        for pointer in [
            deleted_credential.clone(),
            format!("{deleted_credential}/credential"),
        ] {
            assert_refused(parse_with_unknown_field(&file, &pointer), &pointer);
        }
    }

    #[test]
    fn unknown_field_in_any_outer_struct_is_refused() {
        let file = filled_file();
        EncryptedVault::parse(&file.to_string()).unwrap();

        let item = only_entry(&file, "/vault/items");
        let credential = only_entry(&file, &format!("{item}/credentials"));
        let deleted_credential = only_entry(&file, &format!("{item}/deleted"));
        let deleted_item = only_entry(&file, "/vault/deleted");
        let pointers = [
            String::new(),
            "/vault".to_string(),
            item,
            credential.clone(),
            format!("{credential}/history/0"),
            deleted_credential.clone(),
            format!("{deleted_credential}/credential"),
            deleted_item.clone(),
            format!("{deleted_item}/item"),
        ];
        for pointer in pointers {
            assert_refused(parse_with_unknown_field(&file, &pointer), &pointer);
        }
    }

    #[test]
    fn header_is_read_from_vault_file() {
        let dir = tempfile::tempdir().unwrap();
        let vault = filled_vault();
        let path = dir.path().join("filled.json");
        fs::write(&path, vault.to_file_contents().unwrap()).unwrap();

        let header = VaultHeader::peek(&path).unwrap();
        assert_eq!(header.id, vault.id);
        assert_eq!(header.name.as_deref(), Some("Filled"));
    }

    #[test]
    fn header_holds_vault_key() {
        let vault = filled_vault();
        let contents = vault.to_file_contents().unwrap();

        let file: Value = serde_json::from_str(&contents).unwrap();
        assert_eq!(file["vault"]["key"], json!("personal"));
        assert_eq!(VaultHeader::parse(&contents).unwrap().key, "personal");
        assert_eq!(EncryptedVault::parse(&contents).unwrap().key, "personal");
    }

    #[test]
    fn file_without_key_is_refused() {
        let mut file = filled_file();
        file["vault"].as_object_mut().unwrap().remove("key");
        let contents = file.to_string();

        assert!(matches!(
            EncryptedVault::parse(&contents),
            Err(Error::VaultDeserializationError(_))
        ));
        assert!(matches!(
            VaultHeader::parse(&contents),
            Err(Error::VaultDeserializationError(_))
        ));
    }

    #[test]
    fn file_with_key_that_is_not_normalized_is_refused() {
        for key in ["Personal", "my vault", "", "1password"] {
            let mut file = filled_file();
            file["vault"]["key"] = json!(key);
            let contents = file.to_string();

            assert!(
                matches!(
                    EncryptedVault::parse(&contents),
                    Err(Error::InvalidVaultKey(_))
                ),
                "{key:?}"
            );
            assert!(
                matches!(
                    VaultHeader::parse(&contents),
                    Err(Error::InvalidVaultKey(_))
                ),
                "{key:?}"
            );
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
