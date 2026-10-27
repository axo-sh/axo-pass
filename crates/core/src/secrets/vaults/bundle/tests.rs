use std::collections::BTreeMap;
use std::fs;

use aes_gcm::{Aes256Gcm, KeyInit};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::audit::test_support::test_dir;
use crate::secrets::vaults::bundle::export_mode::{
    ExportMode, MAX_WORK_FACTOR, MIN_WORK_FACTOR, WorkFactor,
};
use crate::secrets::vaults::bundle::exported_bundle::{
    BUNDLE_VERSION, BundledVault, ExportedBundle, RawFileKey,
};
use crate::secrets::vaults::bundle::import_identity::ImportIdentity;
use crate::secrets::vaults::bundle::{ImportableBundle, PreparedVault};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::encrypted_blob::EncryptedBlob;
use crate::secrets::vaults::format::encrypted_vault::{EncryptedVault, VaultFileKey, VaultHeader};
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::format::vault_cipher::VaultCipher;
use crate::secrets::vaults::model::Vault;
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::storage::txn::VaultWriter;

#[test]
fn test_passphrase_round_trip() {
    let raw_key: Vec<u8> = (0..32).collect();
    let export_mode = ExportMode::passphrase("test-password-123");
    let wrapped = export_mode.encrypt(&raw_key).unwrap();
    assert!(wrapped.contains("BEGIN AGE ENCRYPTED FILE"));

    let identity = ImportIdentity::Passphrase("test-password-123".into());
    let unwrapped = identity.decrypt(&wrapped).unwrap();
    assert_eq!(raw_key, unwrapped);
}

#[test]
fn test_passphrase_wrong_password() {
    let raw_key: Vec<u8> = (0..32).collect();
    let export_mode = ExportMode::passphrase("correct-password");
    let wrapped = export_mode.encrypt(&raw_key).unwrap();

    let identity = ImportIdentity::Passphrase("wrong-password".into());
    let result = identity.decrypt(&wrapped);
    assert!(result.is_err());
}

#[test]
fn test_recipient_round_trip() {
    let raw_key: Vec<u8> = (0..32).collect();
    let identity = age::x25519::Identity::generate();
    let pubkey = identity.to_public().to_string();

    let export_mode = ExportMode::Recipient(pubkey);
    let wrapped = export_mode.encrypt(&raw_key).unwrap();

    let import_id = ImportIdentity::Identity(identity);
    let unwrapped = import_id.decrypt(&wrapped).unwrap();
    assert_eq!(raw_key, unwrapped);
}

#[test]
fn test_work_factor_parse() {
    assert_eq!(WorkFactor::parse("fast").unwrap(), WorkFactor::Fast);
    assert_eq!(WorkFactor::parse("PARANOID").unwrap(), WorkFactor::Paranoid);
    assert_eq!(WorkFactor::parse("18").unwrap(), WorkFactor::Custom(18));
    assert!(WorkFactor::parse("nope").is_err());
    assert!(WorkFactor::parse(&(MIN_WORK_FACTOR - 1).to_string()).is_err());
    assert!(WorkFactor::parse(&(MAX_WORK_FACTOR + 1).to_string()).is_err());
}

#[test]
fn test_custom_work_factor_round_trip() {
    let raw_key: Vec<u8> = (0..32).collect();
    let export_mode = ExportMode::Passphrase {
        passphrase: "pw".into(),
        work_factor: WorkFactor::Custom(MAX_WORK_FACTOR),
    };
    let wrapped = export_mode.encrypt(&raw_key).unwrap();

    let identity = ImportIdentity::Passphrase("pw".into());
    assert_eq!(identity.decrypt(&wrapped).unwrap(), raw_key);
}

/// Build a bundle with `count` vaults, each carrying a distinct 32-byte file
/// key, and serialize it to JSON.
fn make_bundle_json(count: usize) -> (String, Uuid, Vec<Vec<u8>>) {
    let bundle_id = Uuid::new_v4();
    let bundle_key = Aes256Gcm::generate_key(aes_gcm::aead::OsRng);
    let bundle_cipher = Aes256Gcm::new(&bundle_key);

    let mut file_keys = Vec::new();
    let mut vaults = Vec::new();
    for i in 0..count {
        let vault_id = Uuid::new_v4();
        let file_key: Vec<u8> = (0..32).map(|b| b ^ i as u8).collect();
        file_keys.push(file_key.clone());
        let wrapped_file_key = EncryptedBlob::encrypt(
            &RawFileKey(file_key),
            &bundle_cipher,
            ExportedBundle::file_key_aad(bundle_id, vault_id),
        )
        .unwrap();
        vaults.push(BundledVault {
            id: vault_id,
            name: Some(format!("vault {i}")),
            default_key: (i > 0).then(|| format!("vault-{i}")),
            wrapped_file_key,
            metadata: None,
            items: BTreeMap::new(),
        });
    }

    let age_bundle_key = ExportMode::passphrase("pw")
        .encrypt(bundle_key.as_slice())
        .unwrap();

    let bundle = ExportedBundle {
        version: BUNDLE_VERSION,
        id: bundle_id,
        exported_at: time::OffsetDateTime::now_utc(),
        age_bundle_key,
        vaults,
    };
    (
        serde_json::to_string_pretty(&bundle).unwrap(),
        bundle_id,
        file_keys,
    )
}

fn unwrap_bundle_file_keys(json: &str) -> Vec<Vec<u8>> {
    let bundle: ExportedBundle = serde_json::from_str(json).unwrap();
    assert_eq!(bundle.version, BUNDLE_VERSION);

    let bundle_key = ImportIdentity::Passphrase("pw".into())
        .decrypt(&bundle.age_bundle_key)
        .unwrap();
    let bundle_cipher = Aes256Gcm::new_from_slice(&bundle_key).unwrap();

    bundle
        .vaults
        .iter()
        .map(|v| {
            v.wrapped_file_key
                .decrypt(
                    &bundle_cipher,
                    ExportedBundle::file_key_aad(bundle.id, v.id),
                )
                .unwrap()
                .expose_secret()
                .0
                .clone()
        })
        .collect()
}

#[test]
fn test_bundle_single_vault_round_trip() {
    let (json, _id, file_keys) = make_bundle_json(1);
    assert_eq!(unwrap_bundle_file_keys(&json), file_keys);
}

#[test]
fn test_bundle_two_vault_round_trip() {
    let (json, _id, file_keys) = make_bundle_json(2);
    assert_eq!(unwrap_bundle_file_keys(&json), file_keys);
}

fn blob_json<T>(blob: &EncryptedBlob<T>) -> Value {
    serde_json::to_value(blob).unwrap()
}

#[test]
fn bundle_exported_before_vault_format_2_imports() {
    let bundle_id = Uuid::new_v4();
    let bundle_key = Aes256Gcm::generate_key(aes_gcm::aead::OsRng);
    let bundle_cipher = Aes256Gcm::new(&bundle_key);

    let mut vault = Vault::new_for_test();
    vault.add_or_update_item("login", "Login").unwrap();
    for value in ["old", "new"] {
        vault
            .add_or_update_item_credential(
                "login",
                "password",
                "Password",
                FieldKind::default(),
                SecretString::from(value.to_string()),
            )
            .unwrap();
    }
    let bundled = vault
        .to_bundled_vault(Some("old".to_string()), bundle_id, &bundle_cipher, true)
        .unwrap();

    // Bundle JSON with the field names of bundle version 1 as written before
    // vault format 2. Only the blobs come from the current code.
    let items: Map<String, Value> = bundled
        .items
        .iter()
        .map(|(item_id, item)| {
            let credentials: Map<String, Value> = item
                .credentials
                .iter()
                .map(|(cred_id, cred)| {
                    let history: Vec<Value> = cred
                        .history
                        .iter()
                        .map(|entry| {
                            json!({
                                "id": entry.id,
                                "value": blob_json(&entry.value),
                                "info": blob_json(&entry.info),
                            })
                        })
                        .collect();
                    let cred = json!({
                        "metadata": blob_json(&cred.metadata),
                        "value": blob_json(&cred.value),
                        "history": history,
                    });
                    (cred_id.to_string(), cred)
                })
                .collect();
            let item = json!({
                "metadata": blob_json(&item.metadata),
                "credentials": credentials,
            });
            (item_id.to_string(), item)
        })
        .collect();
    let bundle = json!({
        "version": 1,
        "id": bundle_id,
        "exported_at": "2026-10-01T12:00:00Z",
        "age_bundle_key": ExportMode::passphrase("pw").encrypt(bundle_key.as_slice()).unwrap(),
        "vaults": [{
            "id": bundled.id,
            "name": "Old",
            "default_key": "old",
            "wrapped_file_key": blob_json(&bundled.wrapped_file_key),
            "items": items,
        }],
    });
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.axovault");
    fs::write(&path, serde_json::to_string_pretty(&bundle).unwrap()).unwrap();

    let opened = ImportableBundle::open(&path, ImportIdentity::Passphrase("pw".into())).unwrap();
    let prepared = opened.vaults.into_iter().next().unwrap();
    assert_eq!(prepared.id, bundled.id);
    assert_eq!(prepared.default_key.as_deref(), Some("old"));
    let imported = prepared
        .into_vault("old".to_string(), VaultFileKey::new(vec![0u8; 32]))
        .unwrap();

    let value = imported
        .get_item_credential_secret("login", "password")
        .unwrap()
        .unwrap();
    assert_eq!(value.expose_secret(), "new");
    let history = imported.list_history("login", "password").unwrap();
    assert_eq!(history.len(), 1);
    let previous = imported
        .get_history_value("login", "password", history[0].id)
        .unwrap();
    assert_eq!(previous.expose_secret(), "old");

    // The bundle holds hyphenated ids. The imported vault is written with
    // short ids.
    let contents = imported
        .to_encrypted(true)
        .unwrap()
        .to_file_contents(&TestSigner::device())
        .unwrap();
    assert!(EncryptedVault::assert_short_ids_for_test(&contents) >= 4);
    assert!(!contents.contains(&bundled.id.hyphenated().to_string()));
}

#[test]
fn bundle_is_written_with_short_ids() {
    let bundle_id = Uuid::new_v4();
    let bundle_key = Aes256Gcm::generate_key(aes_gcm::aead::OsRng);
    let bundle_cipher = Aes256Gcm::new(&bundle_key);
    let mut vault = Vault::new_for_test();
    vault.add_or_update_item("login", "Login").unwrap();
    vault
        .add_or_update_item_credential(
            "login",
            "password",
            "Password",
            FieldKind::default(),
            SecretString::from("secret".to_string()),
        )
        .unwrap();
    let bundled = vault
        .to_bundled_vault(None, bundle_id, &bundle_cipher, true)
        .unwrap();
    let bundle = ExportedBundle {
        version: BUNDLE_VERSION,
        id: bundle_id,
        exported_at: time::OffsetDateTime::now_utc(),
        age_bundle_key: String::new(),
        vaults: vec![bundled],
    };

    let json = serde_json::to_value(&bundle).unwrap();

    assert_eq!(json["version"], json!(2));
    assert_eq!(json["id"], json!(ShortId::encode_uuid(bundle_id)));
    let vault_json = &json["vaults"][0];
    assert_eq!(vault_json["id"], json!(ShortId::encode_uuid(vault.id())));
    let items = vault_json["items"].as_object().unwrap();
    assert_eq!(items.len(), 1);
    for (item_id, item) in items {
        assert!(ShortId::decode(item_id).is_ok(), "{item_id}");
        assert_eq!(item_id.len(), 22);
        for cred_id in item["credentials"].as_object().unwrap().keys() {
            assert!(ShortId::decode(cred_id).is_ok(), "{cred_id}");
            assert_eq!(cred_id.len(), 22);
        }
    }

    // The wrapped file key AAD keeps the hyphenated ids.
    let read: ExportedBundle = serde_json::from_value(json).unwrap();
    let raw = read.vaults[0]
        .wrapped_file_key
        .decrypt(
            &bundle_cipher,
            vec![
                bundle_id.hyphenated().to_string(),
                vault.id().hyphenated().to_string(),
                "file-key".to_string(),
            ],
        )
        .unwrap();
    assert_eq!(raw.expose_secret().0.len(), 32);
}

#[test]
fn imported_vault_holds_selected_key_and_is_named_by_id() {
    // Import records an audit event.
    let _audit_dir = test_dir();
    let dir = tempfile::tempdir().unwrap();
    let vaults_dir = dir.path().join("vaults");
    let files = VaultWriter::isolated(dir.path().join("data"));
    let ids = [Uuid::new_v4(), Uuid::new_v4()];
    let selection = BTreeMap::from([
        (ids[0], "Work Vault".to_string()),
        (ids[1], "shared".to_string()),
    ]);

    let imported = ImportableBundle::for_test(&ids)
        .import_with(&selection, &vaults_dir, &files, || {
            Ok(Box::new(|raw: &[u8]| Ok(VaultFileKey::new(raw.to_vec()))))
        })
        .unwrap();

    let mut keys = Vec::new();
    for vh in &imported {
        let header = VaultHeader::peek(&vh.path).unwrap();
        let name = format!("{}.json", ShortId::encode_uuid(header.id));
        assert_eq!(vh.path, vaults_dir.join(name));
        assert_eq!(header.key, vh.key);
        keys.push((header.id, header.key));
    }
    keys.sort();
    let mut expected = vec![
        (ids[0], "work-vault".to_string()),
        (ids[1], "shared".to_string()),
    ];
    expected.sort();
    assert_eq!(keys, expected);
}

#[test]
fn imported_vault_is_signed_by_writer() {
    let _audit_dir = test_dir();
    let dir = tempfile::tempdir().unwrap();
    let files = VaultWriter::isolated(dir.path().join("data"));
    let id = Uuid::new_v4();
    let selection = BTreeMap::from([(id, "imported".to_string())]);

    let imported = ImportableBundle::for_test(&[id])
        .import_with(&selection, &dir.path().join("vaults"), &files, || {
            Ok(Box::new(|raw: &[u8]| Ok(VaultFileKey::new(raw.to_vec()))))
        })
        .unwrap();

    let path = &imported[0].path;
    let verified = EncryptedVault::load(path, files.signer().as_ref()).unwrap();
    assert_eq!(verified.id, id);
    assert!(matches!(
        EncryptedVault::load(path, &TestSigner::random()),
        Err(Error::VaultSignatureInvalid)
    ));
}

/// Vault with the entries of [`Vault::fill_for_test`], saved and loaded under
/// its own file key, so its caches hold the blobs of the file.
fn filled_vault() -> Vault {
    let mut vault = Vault::new_for_test();
    vault.fill_for_test();
    let cipher = vault.unlocked_key().cipher_for_test();
    Vault::from_encrypted_with_cipher(cipher, vault.to_encrypted(true).unwrap()).unwrap()
}

/// Raw file key of `vault`.
fn file_key_of(vault: &Vault) -> Vec<u8> {
    vault.unlocked_key().cipher_for_test().key_bytes_for_test()
}

/// Export `vault` to a bundle file and open the file again.
fn export_and_open(vault: &Vault, include_passkeys: bool) -> PreparedVault {
    let bundle_id = Uuid::new_v4();
    let bundle_key = Aes256Gcm::generate_key(aes_gcm::aead::OsRng);
    let bundled = vault
        .to_bundled_vault(
            None,
            bundle_id,
            &Aes256Gcm::new(&bundle_key),
            include_passkeys,
        )
        .unwrap();
    let identity = age::x25519::Identity::generate();
    let export_mode = ExportMode::Recipient(identity.to_public().to_string());
    let bundle = ExportedBundle {
        version: BUNDLE_VERSION,
        id: bundle_id,
        exported_at: time::OffsetDateTime::now_utc(),
        age_bundle_key: export_mode.encrypt(bundle_key.as_slice()).unwrap(),
        vaults: vec![bundled],
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("export.axovault");
    fs::write(&path, serde_json::to_string_pretty(&bundle).unwrap()).unwrap();

    let opened = ImportableBundle::open(&path, ImportIdentity::Identity(identity)).unwrap();
    opened.vaults.into_iter().next().unwrap()
}

/// Cipher of the file key an opened bundle vault holds.
fn export_cipher(prepared: &PreparedVault) -> VaultCipher {
    VaultCipher::new_with_bytes(prepared.raw_file_key.expose_secret(), prepared.id)
}

#[test]
fn export_file_key_differs_from_source_and_source_is_unchanged() {
    let vault = filled_vault();
    let source_key = file_key_of(&vault);
    let before = vault.to_encrypted(true).unwrap().to_vault_json().unwrap();

    let prepared = export_and_open(&vault, true);

    assert_ne!(*prepared.raw_file_key.expose_secret(), source_key);
    assert_eq!(file_key_of(&vault), source_key);
    let after = vault.to_encrypted(true).unwrap().to_vault_json().unwrap();
    assert_eq!(after, before);
    vault.assert_filled_for_test();
}

#[test]
fn two_exports_of_one_vault_have_different_file_keys() {
    let vault = filled_vault();

    let first = export_and_open(&vault, true);
    let second = export_and_open(&vault, true);

    assert_ne!(
        first.raw_file_key.expose_secret(),
        second.raw_file_key.expose_secret()
    );
}

#[test]
fn export_imports_with_values_and_history() {
    let vault = filled_vault();

    let prepared = export_and_open(&vault, true);
    assert_eq!(prepared.id, vault.id());
    let imported = prepared
        .into_vault("imported".to_string(), VaultFileKey::new(vec![0u8; 32]))
        .unwrap();

    imported.assert_live_filled_for_test();
    assert_eq!(imported.id(), vault.id());
    // Deleted entries are not exported.
    assert!(imported.list_deleted("kept").unwrap().is_empty());
    assert!(imported.list_deleted_items().is_empty());
}

#[test]
fn bundle_blobs_fail_to_decrypt_under_source_file_key() {
    let vault = filled_vault();
    let prepared = export_and_open(&vault, true);
    let cipher = export_cipher(&prepared);
    let exported = EncryptedVault {
        id: prepared.id,
        key: "exported".to_string(),
        name: None,
        generation: 0,
        replica_id: None,
        file_key: VaultFileKey::new(Vec::new()),
        metadata: prepared.metadata,
        items: prepared.items,
        deleted: BTreeMap::new(),
    };

    let under_export_key = cipher.blob_results_for_test(&exported);
    let under_source_key = vault
        .unlocked_key()
        .cipher_for_test()
        .blob_results_for_test(&exported);

    let kinds: Vec<&str> = under_export_key.keys().map(String::as_str).collect();
    assert_eq!(
        kinds,
        [
            "live: credential metadata",
            "live: history info",
            "live: history value",
            "live: item autofill",
            "live: item metadata",
            "live: value",
            "live: vault metadata",
        ]
    );
    for (kind, oks) in &under_export_key {
        assert!(oks.iter().all(|ok| *ok), "{kind}: {oks:?}");
    }
    for (kind, oks) in &under_source_key {
        assert!(oks.iter().all(|ok| !*ok), "{kind}: {oks:?}");
    }
}

#[test]
fn export_without_passkeys_holds_no_passkey_credential() {
    let vault = filled_vault();
    let kept_id = vault.get_item("kept").unwrap().id;
    let passkey_id = vault.get_item_credential("kept", "passkey").unwrap().id;

    let prepared = export_and_open(&vault, false);

    let cipher = export_cipher(&prepared);
    assert!(
        !prepared.items[&kept_id]
            .credentials
            .contains_key(&passkey_id)
    );
    for (item_id, item) in &prepared.items {
        for (cred_id, cred) in &item.credentials {
            let metadata = cipher
                .decrypt_cred_metadata(*item_id, *cred_id, &cred.metadata)
                .unwrap();
            assert_ne!(metadata.expose_secret().kind, FieldKind::Passkey);
            let value = cipher
                .decrypt_cred_value(*item_id, *cred_id, &cred.value)
                .unwrap();
            assert_ne!(value.expose_secret(), Vault::PASSKEY_VALUE_FOR_TEST);
        }
    }
    let imported = prepared
        .into_vault("imported".to_string(), VaultFileKey::new(vec![0u8; 32]))
        .unwrap();
    assert!(imported.get_item_credential("kept", "passkey").is_err());
    let alpha = imported
        .get_item_credential_secret("kept", "alpha")
        .unwrap();
    assert_eq!(alpha.unwrap().expose_secret(), "two");
}

#[test]
fn export_with_passkeys_holds_passkey_record_unchanged() {
    let vault = filled_vault();
    let kept_id = vault.get_item("kept").unwrap().id;
    let passkey_id = vault.get_item_credential("kept", "passkey").unwrap().id;

    let prepared = export_and_open(&vault, true);

    let cipher = export_cipher(&prepared);
    let passkey = &prepared.items[&kept_id].credentials[&passkey_id];
    let metadata = cipher
        .decrypt_cred_metadata(kept_id, passkey_id, &passkey.metadata)
        .unwrap();
    assert_eq!(metadata.expose_secret().kind, FieldKind::Passkey);
    let value = cipher
        .decrypt_cred_value(kept_id, passkey_id, &passkey.value)
        .unwrap();
    assert_eq!(value.expose_secret(), Vault::PASSKEY_VALUE_FOR_TEST);
}

#[test]
fn test_bundle_wrong_bundle_id_fails_aad() {
    let (json, _id, _file_keys) = make_bundle_json(1);
    let mut bundle: ExportedBundle = serde_json::from_str(&json).unwrap();
    bundle.id = Uuid::new_v4();

    let bundle_key = ImportIdentity::Passphrase("pw".into())
        .decrypt(&bundle.age_bundle_key)
        .unwrap();
    let bundle_cipher = Aes256Gcm::new_from_slice(&bundle_key).unwrap();
    let result = bundle.vaults[0].wrapped_file_key.decrypt(
        &bundle_cipher,
        ExportedBundle::file_key_aad(bundle.id, bundle.vaults[0].id),
    );
    assert!(result.is_err());
}
