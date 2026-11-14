use super::support::{
    LooseMetadata, TEST_FILE_KEY, cred_mut, reload, test_vault, vault_with_credentials,
};
use super::*;
use crate::secrets::vaults::format::short_id::ShortId;

/// File key wrapper that stores the raw key as is.
fn plain_wrap(raw: &[u8]) -> Result<VaultFileKey, Error> {
    Ok(VaultFileKey::new(raw.to_vec()))
}

/// Vault with the entries of [`Vault::fill_for_test`], saved and loaded, so
/// its caches hold the blobs of the file.
fn filled_test_vault() -> Vault {
    let mut vault = test_vault();
    vault.fill_for_test();
    reload(&vault)
}

/// Save and load a vault under its own file key.
fn reload_own_key(vault: &Vault) -> Vault {
    let encrypted = vault.to_encrypted(true).unwrap();
    Vault::from_encrypted_with_cipher(vault.cipher.duplicate(), encrypted).unwrap()
}

/// Place and kind of every blob in a vault filled by [`Vault::fill_for_test`],
/// as [`VaultCipher::blob_results_for_test`] names them.
const FILLED_BLOB_KINDS: [&str; 24] = [
    "deleted item deleted credential: credential metadata",
    "deleted item deleted credential: deleted info",
    "deleted item deleted credential: history info",
    "deleted item deleted credential: history value",
    "deleted item deleted credential: value",
    "deleted item: credential metadata",
    "deleted item: deleted item info",
    "deleted item: history info",
    "deleted item: history value",
    "deleted item: item autofill",
    "deleted item: item metadata",
    "deleted item: value",
    "live deleted credential: credential metadata",
    "live deleted credential: deleted info",
    "live deleted credential: history info",
    "live deleted credential: history value",
    "live deleted credential: value",
    "live: credential metadata",
    "live: history info",
    "live: history value",
    "live: item autofill",
    "live: item metadata",
    "live: value",
    "live: vault metadata",
];

/// Check that `cipher` decrypts every blob of the filled vault `encrypted` if
/// `decrypts` is set, and none of them otherwise.
fn assert_blobs_decrypt(cipher: &VaultCipher, encrypted: &EncryptedVault, decrypts: bool) {
    let results = cipher.blob_results_for_test(encrypted);
    let kinds: Vec<&str> = results.keys().map(String::as_str).collect();
    assert_eq!(kinds, FILLED_BLOB_KINDS);
    for (kind, oks) in &results {
        assert!(oks.iter().all(|ok| *ok == decrypts), "{kind}: {oks:?}");
    }
}

/// Credential metadata plaintext of `item_id/cred_id` as `vault` writes it.
fn stored_cred_metadata(
    vault: &Vault,
    item_id: Uuid,
    cred_id: Uuid,
) -> BTreeMap<String, serde_json::Value> {
    let encrypted = vault.to_encrypted(true).unwrap();
    let blob = &encrypted.items[&item_id].credentials[&cred_id].metadata;
    let metadata: SecretBox<LooseMetadata> = vault
        .cipher
        .decrypt_cred_metadata_as_for_test(item_id, cred_id, blob);
    metadata.expose_secret().fields.clone()
}

/// Filled vault in which `breaks` replaces value blobs of item `kept` with the
/// value blob of `alpha`. `breaks` receives the source vault, the encrypted
/// item, and that blob. A replaced blob fails to decrypt, since its AAD names
/// another credential.
fn filled_vault_with_broken_values(
    breaks: impl FnOnce(&Vault, &mut EncryptedVaultItem, &EncryptedBlob<String>),
) -> Vault {
    let source = filled_test_vault();
    let (item_id, alpha_id) = source.get_credential_ids("kept", "alpha").unwrap();
    let mut encrypted = source.to_encrypted(true).unwrap();
    let item = encrypted.items.get_mut(&item_id).unwrap();
    let alpha_value = item.credentials[&alpha_id].value.clone();
    breaks(&source, item, &alpha_value);
    Vault::from_encrypted_with_cipher(source.cipher.duplicate(), encrypted).unwrap()
}

#[test]
fn rekey_blobs_need_new_key() {
    let source = filled_test_vault();
    assert_blobs_decrypt(&source.cipher, &source.to_encrypted(true).unwrap(), true);

    let rekeyed = source.rekeyed(None, plain_wrap).unwrap();
    let encrypted = rekeyed.to_encrypted(true).unwrap();

    assert_eq!(encrypted.id, source.id());
    assert_blobs_decrypt(&rekeyed.cipher, &encrypted, true);
    assert_blobs_decrypt(&source.cipher, &encrypted, false);
}

#[test]
fn copy_blobs_need_new_vault_id() {
    let source = filled_test_vault();
    let new_id = Uuid::new_v4();

    let copy = source.rekeyed(Some(new_id), plain_wrap).unwrap();
    let encrypted = copy.to_encrypted(true).unwrap();

    assert_eq!(copy.id(), new_id);
    assert_eq!(encrypted.id, new_id);
    assert_blobs_decrypt(&copy.cipher, &encrypted, true);
    let old_id = copy.cipher.with_vault_id_for_test(source.id());
    assert_blobs_decrypt(&old_id, &encrypted, false);
    assert_blobs_decrypt(&source.cipher, &encrypted, false);
}

#[test]
fn rekeyed_vault_holds_every_entry_of_source() {
    let source = filled_test_vault();
    for new_id in [None, Some(Uuid::new_v4())] {
        let rekeyed = source.rekeyed(new_id, plain_wrap).unwrap();
        rekeyed.assert_filled_for_test();
        assert_eq!(rekeyed.entry_ids_for_test(), source.entry_ids_for_test());

        let reloaded = reload_own_key(&rekeyed);
        reloaded.assert_filled_for_test();
        assert_eq!(reloaded.entry_ids_for_test(), source.entry_ids_for_test());
    }
}

#[test]
fn copy_keeps_key_and_name_and_not_synced() {
    let mut source = filled_test_vault();
    source.generation = 5;
    source.replica_id = Some(Uuid::new_v4());

    let rekeyed = source.rekeyed(None, plain_wrap).unwrap();
    assert_eq!(rekeyed.id(), source.id());
    assert_eq!(rekeyed.generation, 5);
    assert_eq!(rekeyed.replica_id, source.replica_id);

    let new_id = Uuid::new_v4();
    let copy = source.rekeyed(Some(new_id), plain_wrap).unwrap();
    assert_eq!(copy.id(), new_id);
    assert_eq!(copy.generation, 0);
    assert_eq!(copy.replica_id, None);
    for vault in [&rekeyed, &copy] {
        assert_eq!(vault.key(), source.key());
        assert_eq!(vault.name, source.name);
    }
}

#[test]
fn source_unchanged_and_its_file_key_still_decrypts_it() {
    let source = filled_test_vault();
    let before = source.to_encrypted(true).unwrap().to_vault_json().unwrap();

    source.rekeyed(None, plain_wrap).unwrap();
    source.rekeyed(Some(Uuid::new_v4()), plain_wrap).unwrap();

    let after = source.to_encrypted(true).unwrap();
    assert_eq!(after.to_vault_json().unwrap(), before);
    assert_eq!(source.cipher.key_bytes_for_test(), TEST_FILE_KEY);
    let cipher = VaultCipher::new_with_bytes(&TEST_FILE_KEY, source.id());
    assert_blobs_decrypt(&cipher, &after, true);
    reload(&source).assert_filled_for_test();
}

#[test]
fn two_rekeys_of_one_vault_have_different_file_keys() {
    let source = filled_test_vault();

    let first = source.rekeyed(None, plain_wrap).unwrap();
    let second = source.rekeyed(None, plain_wrap).unwrap();

    let first_key = first.cipher.key_bytes_for_test();
    let second_key = second.cipher.key_bytes_for_test();
    assert_ne!(first_key, second_key);
    assert_ne!(first_key, TEST_FILE_KEY);
    assert_ne!(second_key, TEST_FILE_KEY);
    assert!(first.file_key != second.file_key);
}

#[test]
fn wrapper_receives_raw_key_of_rekeyed_vault() {
    let source = filled_test_vault();
    let mut seen = Vec::new();

    let rekeyed = source
        .rekeyed(None, |raw| {
            seen = raw.to_vec();
            Ok(VaultFileKey::new(vec![9u8; 4]))
        })
        .unwrap();

    assert_eq!(seen, rekeyed.cipher.key_bytes_for_test());
    let wrapped = VaultFileKey::new(vec![9u8; 4]);
    assert!(rekeyed.file_key == wrapped);
    assert!(rekeyed.to_encrypted(true).unwrap().file_key == wrapped);
}

#[test]
fn failed_wrap_fails_rekey() {
    let source = filled_test_vault();
    let result = source.rekeyed(None, |_| Err(Error::VaultFileKeyEncryptionError));
    assert!(matches!(result, Err(Error::VaultFileKeyEncryptionError)));
}

#[test]
fn blob_with_unknown_field_fails_load() {
    let source = filled_test_vault();
    let mut edited = BTreeSet::new();
    for n in 0.. {
        let mut encrypted = source.to_encrypted(true).unwrap();
        let Some(kind) = source.cipher.add_unknown_field_for_test(&mut encrypted, n) else {
            break;
        };

        let result = Vault::from_encrypted_with_cipher(source.cipher.duplicate(), encrypted);

        assert!(
            matches!(result, Err(Error::VaultSecretDecryptionError)),
            "{kind}"
        );
        edited.insert(kind);
    }
    // Every blob kind but values and previous values holds a struct.
    let expected: BTreeSet<String> = FILLED_BLOB_KINDS
        .iter()
        .filter(|kind| !kind.ends_with(": value") && !kind.ends_with(": history value"))
        .map(|kind| kind.to_string())
        .collect();
    assert_eq!(edited, expected);
}

#[test]
fn unknown_kind_survives_round_trip() {
    let kind = serde_json::json!({"band": 5, "ssid": "home", "type": "wifi"});
    let vault = vault_with_credentials("net", &["wifi"]);
    let (item_id, cred_id) = vault.get_credential_ids("net", "wifi").unwrap();
    let mut encrypted = vault.to_encrypted(true).unwrap();
    let newer = LooseMetadata {
        fields: BTreeMap::from([
            ("title".to_string(), serde_json::json!("Wifi")),
            ("key".to_string(), serde_json::json!("wifi")),
            ("kind".to_string(), kind.clone()),
            ("created_at".to_string(), serde_json::json!(5)),
        ]),
    };
    let blob = vault
        .cipher
        .encrypt_cred_metadata_as_for_test(item_id, cred_id, &newer);
    cred_mut(&mut encrypted, item_id, cred_id).metadata = blob;

    let mut loaded =
        Vault::from_encrypted_with_cipher(vault.cipher.duplicate(), encrypted).unwrap();

    let cred = loaded.get_item_credential("net", "wifi").unwrap();
    assert_eq!(cred.kind, FieldKind::Unknown(kind.clone()));
    // Moving the credential writes its metadata again from the parsed kind.
    let section_id = loaded.create_item_section("net", "Section").unwrap().id;
    loaded
        .move_item_credential("net", "wifi", Some(section_id))
        .unwrap();
    let fields = stored_cred_metadata(&loaded, item_id, cred_id);
    assert_eq!(fields["kind"], kind);
    assert_eq!(fields["section"], ShortId::encode_uuid(section_id));
    let reloaded = reload_own_key(&loaded);
    let cred = reloaded.get_item_credential("net", "wifi").unwrap();
    assert_eq!(cred.kind, FieldKind::Unknown(kind));
}

#[test]
fn deleted_entry_that_fails_to_decrypt_does_not_fail_export() {
    let vault = filled_vault_with_broken_values(|_, item, value| {
        for entry in item.deleted.values_mut() {
            entry.credential.value = value.clone();
        }
    });
    let cipher = Aes256Gcm::new(&Aes256Gcm::generate_key(OsRng));

    assert!(vault.rekeyed(None, plain_wrap).is_err());
    for include_passkeys in [true, false] {
        let bundled = vault.to_bundled_vault(None, Uuid::new_v4(), &cipher, include_passkeys);
        assert!(bundled.is_ok());
    }
}

#[test]
fn left_out_passkey_that_fails_to_decrypt_does_not_fail_export() {
    let vault = filled_vault_with_broken_values(|source, item, value| {
        let (_, passkey_id) = source.get_credential_ids("kept", "passkey").unwrap();
        item.credentials.get_mut(&passkey_id).unwrap().value = value.clone();
    });
    let cipher = Aes256Gcm::new(&Aes256Gcm::generate_key(OsRng));

    assert!(
        vault
            .to_bundled_vault(None, Uuid::new_v4(), &cipher, false)
            .is_ok()
    );
    assert!(
        vault
            .to_bundled_vault(None, Uuid::new_v4(), &cipher, true)
            .is_err()
    );
}

#[test]
fn unknown_field_kind_kept_by_rekey() {
    let kind = serde_json::json!({"type": "wifi", "ssid": "home", "band": 5});
    let mut vault = test_vault();
    vault.add_or_update_item("net", "Net").unwrap();
    vault
        .add_or_update_item_credential(
            "net",
            "wifi",
            "Wifi",
            FieldKind::Unknown(kind.clone()),
            SecretString::from("hunter2"),
        )
        .unwrap();
    let vault = reload(&vault);
    let (item_id, cred_id) = vault.get_credential_ids("net", "wifi").unwrap();

    let rekeyed = vault.rekeyed(None, plain_wrap).unwrap();

    assert_eq!(
        stored_cred_metadata(&rekeyed, item_id, cred_id)["kind"],
        kind
    );
    let reloaded = reload_own_key(&rekeyed);
    let cred = reloaded.get_item_credential("net", "wifi").unwrap();
    assert_eq!(cred.kind, FieldKind::Unknown(kind));
}
