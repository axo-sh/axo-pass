use aes_gcm::{Aes256Gcm, KeyInit};
use uuid::Uuid;

use super::make_bundle_json;
use crate::secrets::vaults::bundle::export_mode::{
    ExportMode, MAX_WORK_FACTOR, MIN_WORK_FACTOR, WorkFactor,
};
use crate::secrets::vaults::bundle::exported_bundle::ExportedBundle;
use crate::secrets::vaults::bundle::import_identity::ImportIdentity;

#[test]
fn passphrase_round_trip() {
    let raw_key: Vec<u8> = (0..32).collect();
    let export_mode = ExportMode::passphrase("test-password-123");
    let wrapped = export_mode.encrypt(&raw_key).unwrap();
    assert!(wrapped.contains("BEGIN AGE ENCRYPTED FILE"));

    let identity = ImportIdentity::Passphrase("test-password-123".into());
    let unwrapped = identity.decrypt(&wrapped).unwrap();
    assert_eq!(raw_key, unwrapped);
}

#[test]
fn passphrase_wrong_password() {
    let raw_key: Vec<u8> = (0..32).collect();
    let export_mode = ExportMode::passphrase("correct-password");
    let wrapped = export_mode.encrypt(&raw_key).unwrap();

    let identity = ImportIdentity::Passphrase("wrong-password".into());
    let result = identity.decrypt(&wrapped);
    assert!(result.is_err());
}

#[test]
fn recipient_round_trip() {
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
fn work_factor_parse() {
    assert_eq!(WorkFactor::parse("fast").unwrap(), WorkFactor::Fast);
    assert_eq!(WorkFactor::parse("PARANOID").unwrap(), WorkFactor::Paranoid);
    assert_eq!(WorkFactor::parse("18").unwrap(), WorkFactor::Custom(18));
    assert!(WorkFactor::parse("nope").is_err());
    assert!(WorkFactor::parse(&(MIN_WORK_FACTOR - 1).to_string()).is_err());
    assert!(WorkFactor::parse(&(MAX_WORK_FACTOR + 1).to_string()).is_err());
}

#[test]
fn custom_work_factor_round_trip() {
    let raw_key: Vec<u8> = (0..32).collect();
    let export_mode = ExportMode::Passphrase {
        passphrase: "pw".into(),
        work_factor: WorkFactor::Custom(MAX_WORK_FACTOR),
    };
    let wrapped = export_mode.encrypt(&raw_key).unwrap();

    let identity = ImportIdentity::Passphrase("pw".into());
    assert_eq!(identity.decrypt(&wrapped).unwrap(), raw_key);
}

#[test]
fn wrong_bundle_id_fails_aad() {
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
