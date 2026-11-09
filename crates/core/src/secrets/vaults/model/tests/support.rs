use super::*;

pub(super) const TEST_FILE_KEY: [u8; 32] = [7u8; 32];

pub(super) fn test_vault() -> Vault {
    let id = Uuid::new_v4();
    Vault::empty(
        id,
        "test-vault".to_string(),
        Some("test vault".to_string()),
        VaultFileKey::new(vec![0u8; 32]),
        VaultCipher::new_with_bytes(&TEST_FILE_KEY, id),
    )
}

/// Set the value of credential `cred_key` of item `item_key`, and add the
/// credential if it is missing.
pub(super) fn set_value(vault: &mut Vault, item_key: &str, cred_key: &str, value: &str) {
    vault
        .add_or_update_item_credential(
            item_key,
            cred_key,
            cred_key,
            FieldKind::default(),
            SecretString::from(value.to_string()),
        )
        .unwrap();
}

/// Load `encrypted` with the test file key.
pub(super) fn try_load_encrypted(encrypted: EncryptedVault) -> Result<Vault, Error> {
    let cipher = VaultCipher::new_with_bytes(&TEST_FILE_KEY, encrypted.id);
    Vault::from_encrypted_with_cipher(cipher, encrypted)
}

/// [`try_load_encrypted`] for a file that loads.
pub(super) fn load_encrypted(encrypted: EncryptedVault) -> Vault {
    try_load_encrypted(encrypted).unwrap()
}

/// Save and load the vault, as a restart would.
pub(super) fn reload(vault: &Vault) -> Vault {
    load_encrypted(vault.to_encrypted(true).unwrap())
}

/// Credential `cred_id` of item `item_id` in `encrypted`.
pub(super) fn cred_mut(
    encrypted: &mut EncryptedVault,
    item_id: Uuid,
    cred_id: Uuid,
) -> &mut EncryptedVaultItemCredential {
    encrypted
        .items
        .get_mut(&item_id)
        .unwrap()
        .credentials
        .get_mut(&cred_id)
        .unwrap()
}

/// Placement of credential `key` in `section`.
pub(super) fn placement(key: &str, section: Option<Uuid>) -> CredentialPlacement {
    CredentialPlacement {
        key: key.to_string(),
        section,
    }
}

/// Add credential `cred_key` titled `title` to item `item_key`.
pub(super) fn add_cred(
    vault: &mut Vault,
    item_key: &str,
    cred_key: &str,
    title: &str,
    value: &str,
) {
    vault
        .add_item_credential(
            item_key,
            cred_key,
            title,
            FieldKind::default(),
            SecretString::from(value.to_string()),
        )
        .unwrap();
}

/// A vault with one item holding the given credential keys, plus a second
/// item with a single credential to test cross-item rejection.
pub(super) fn vault_with_credentials(item_key: &str, cred_keys: &[&str]) -> Vault {
    let mut vault = test_vault();
    vault.add_or_update_item(item_key, "Item").unwrap();
    for cred_key in cred_keys {
        vault
            .add_or_update_item_credential(
                item_key,
                cred_key,
                cred_key,
                FieldKind::default(),
                SecretString::from("secret"),
            )
            .unwrap();
    }

    vault.add_or_update_item("other-item", "Other").unwrap();
    vault
        .add_or_update_item_credential(
            "other-item",
            "elsewhere",
            "Elsewhere",
            FieldKind::default(),
            SecretString::from("secret"),
        )
        .unwrap();
    vault
}

/// Populate the metadata caches the way a load/save cycle would, so a
/// change has to invalidate them to take effect.
pub(super) fn populate_caches(vault: &mut Vault) {
    let encrypted = vault.to_encrypted(true).unwrap();
    vault.metadata_blob = encrypted.metadata;
    for (item_id, item) in encrypted.items {
        vault.item_blobs.insert(item_id, item.metadata);
        for (cred_id, cred) in item.credentials {
            vault.cred_blobs.insert(cred_id, cred.metadata);
        }
    }
}

pub(super) fn cred_id(vault: &Vault, item_key: &str, cred_key: &str) -> Uuid {
    vault.get_item_credential(item_key, cred_key).unwrap().id
}

pub(super) fn deleted_ids(vault: &Vault, item_key: &str) -> Vec<Uuid> {
    vault
        .list_deleted(item_key)
        .unwrap()
        .iter()
        .map(|t| t.credential.id)
        .collect()
}

pub(super) fn secret_of(vault: &Vault, item_key: &str, cred_key: &str) -> String {
    vault
        .get_item_credential_secret(item_key, cred_key)
        .unwrap()
        .unwrap()
        .expose_secret()
        .clone()
}

pub(super) fn item_id_of(vault: &Vault, item_key: &str) -> Uuid {
    *vault.get_item_id(item_key).unwrap()
}

/// Credential metadata plaintext read as a JSON object.
#[derive(serde::Serialize, serde::Deserialize, zeroize::Zeroize)]
pub(super) struct LooseMetadata {
    #[serde(flatten)]
    #[zeroize(skip)]
    pub(super) fields: BTreeMap<String, serde_json::Value>,
}
