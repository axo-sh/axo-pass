use crate::secrets::vaults::vault_export::export_mode::ExportMode;
use crate::secrets::vaults::vault_export::import_identity::ImportIdentity;

#[test]
fn test_passphrase_round_trip() {
    let raw_key: Vec<u8> = (0..32).collect();
    let export_mode = ExportMode::Passphrase("test-password-123".into());
    let wrapped = export_mode.wrap_file_key(&raw_key).unwrap();
    assert!(wrapped.contains("BEGIN AGE ENCRYPTED FILE"));

    let identity = ImportIdentity::Passphrase("test-password-123".into());
    let unwrapped = identity.unwrap_file_key(&wrapped).unwrap();
    assert_eq!(raw_key, unwrapped);
}

#[test]
fn test_passphrase_wrong_password() {
    let raw_key: Vec<u8> = (0..32).collect();
    let export_mode = ExportMode::Passphrase("correct-password".into());
    let wrapped = export_mode.wrap_file_key(&raw_key).unwrap();

    let identity = ImportIdentity::Passphrase("wrong-password".into());
    let result = identity.unwrap_file_key(&wrapped);
    assert!(result.is_err());
}

#[test]
fn test_recipient_round_trip() {
    let raw_key: Vec<u8> = (0..32).collect();
    let identity = age::x25519::Identity::generate();
    let pubkey = identity.to_public().to_string();

    let export_mode = ExportMode::Recipient(pubkey);
    let wrapped = export_mode.wrap_file_key(&raw_key).unwrap();

    let import_id = ImportIdentity::Identity(identity);
    let unwrapped = import_id.unwrap_file_key(&wrapped).unwrap();
    assert_eq!(raw_key, unwrapped);
}
