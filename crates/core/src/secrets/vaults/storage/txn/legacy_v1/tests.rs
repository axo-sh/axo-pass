// MIGRATE_V1: delete this file with the other MIGRATE_V1 markers.
use serde_json::json;

use super::*;
use crate::secrets::vaults::format::signing::TestSigner;

/// Smallest format 1 vault file.
fn legacy_file() -> serde_json::Value {
    json!({
        "id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
        "file_key": "AAAA",
        "items": {},
    })
}

#[test]
fn file_without_format_is_legacy() {
    assert!(is_legacy(&legacy_file().to_string()));
}

#[test]
fn file_with_format_not_legacy() {
    let mut file = legacy_file();
    file["format"] = json!(2);

    assert!(!is_legacy(&file.to_string()));
}

#[test]
fn unrelated_json_not_legacy() {
    assert!(!is_legacy(r#"{"name": "settings"}"#));
    assert!(!is_legacy("[]"));
    assert!(!is_legacy("not json"));
}

#[test]
fn members_file_key_refused() {
    let mut file = legacy_file();
    file["file_key"] = json!([{ "public_key": "key", "wrapped_key": [1, 2, 3] }]);

    let result = convert(&file.to_string(), "personal", &TestSigner::device());

    assert!(
        matches!(result, Err(Error::VaultDeserializationError(_))),
        "{:?}",
        result.err()
    );
}

#[test]
fn unknown_field_refused() {
    let mut file = legacy_file();
    file["unknown"] = json!(1);

    let result = convert(&file.to_string(), "personal", &TestSigner::device());

    assert!(matches!(result, Err(Error::VaultDeserializationError(_))));
}

#[test]
fn converted_file_verifies_with_key() {
    let signer = TestSigner::device();

    let contents = convert(&legacy_file().to_string(), "personal", &signer).unwrap();

    let vault = EncryptedVault::parse(&contents, &signer).unwrap();
    assert_eq!(vault.key, "personal");
    assert!(!is_legacy(&contents));
}

#[test]
fn invalid_key_refused() {
    let result = convert(
        &legacy_file().to_string(),
        "Personal",
        &TestSigner::device(),
    );

    assert!(matches!(result, Err(Error::InvalidVaultKey(_))));
}

#[test]
fn key_is_normalized_file_stem() {
    assert_eq!(
        legacy_key(Path::new("/v/Work Vault.json")).unwrap(),
        "work-vault"
    );
    assert!(matches!(
        legacy_key(Path::new("/v/x.json")),
        Err(Error::InvalidVaultKey(_))
    ));
}

#[test]
fn backup_appends_suffix_to_file_name() {
    assert_eq!(
        backup_path(Path::new("/v/personal.json")),
        Path::new("/v/personal.json.v1")
    );
}
