use std::collections::BTreeMap;

use aes_gcm::{Aes256Gcm, KeyInit};
use secrecy::ExposeSecret;
use uuid::Uuid;

use crate::secrets::vaults::vault::encrypted_blob::EncryptedBlob;
use crate::secrets::vaults::vault_export::export_mode::ExportMode;
use crate::secrets::vaults::vault_export::exported_bundle::{
    BUNDLE_VERSION, BundledVault, ExportedBundle, RawFileKey,
};
use crate::secrets::vaults::vault_export::import_identity::ImportIdentity;

#[test]
fn test_passphrase_round_trip() {
    let raw_key: Vec<u8> = (0..32).collect();
    let export_mode = ExportMode::Passphrase("test-password-123".into());
    let wrapped = export_mode.encrypt(&raw_key).unwrap();
    assert!(wrapped.contains("BEGIN AGE ENCRYPTED FILE"));

    let identity = ImportIdentity::Passphrase("test-password-123".into());
    let unwrapped = identity.decrypt(&wrapped).unwrap();
    assert_eq!(raw_key, unwrapped);
}

#[test]
fn test_passphrase_wrong_password() {
    let raw_key: Vec<u8> = (0..32).collect();
    let export_mode = ExportMode::Passphrase("correct-password".into());
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

/// Build a bundle with `count` vaults, each carrying a distinct 32-byte file
/// key, and serialize it to JSON.
fn make_bundle_json(count: usize) -> (String, Uuid, Vec<Vec<u8>>) {
    let bundle_id = Uuid::new_v4();
    let bundle_key = Aes256Gcm::generate_key(aes_gcm::aead::OsRng);
    let bundle_cipher = Aes256Gcm::new(&bundle_key);

    let mut file_keys = Vec::new();
    let mut vaults = Vec::new();
    for i in 0..count {
        let file_key: Vec<u8> = (0..32).map(|b| b ^ i as u8).collect();
        file_keys.push(file_key.clone());
        let wrapped_file_key = EncryptedBlob::encrypt(
            &RawFileKey(file_key),
            &bundle_cipher,
            ExportedBundle::file_key_aad(bundle_id, Uuid::nil()),
        )
        .unwrap();
        vaults.push(BundledVault {
            id: Uuid::nil(),
            name: Some(format!("vault {i}")),
            default_key: (i > 0).then(|| format!("vault-{i}")),
            wrapped_file_key,
            items: BTreeMap::new(),
        });
    }

    let age_bundle_key = ExportMode::Passphrase("pw".into())
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
