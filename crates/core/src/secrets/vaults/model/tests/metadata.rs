use super::support::{LooseMetadata, cred_mut, vault_with_credentials};
use super::*;
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::model::fields::TextField;

fn cred_metadata(title: &str, key: &str, kind: FieldKind) -> VaultCredentialMetadata {
    VaultCredentialMetadata {
        title: title.to_string(),
        key: key.to_string(),
        kind,
        position: None,
        section: None,
        last_used_day_at: None,
    }
}

#[test]
fn legacy_item_metadata_loads_with_defaults() {
    let meta: VaultItemMetadata = serde_json::from_str(r#"{"title":"Item","key":"item"}"#).unwrap();
    assert_eq!(meta.category, None);
    assert_eq!(meta.folder, None);
    assert!(meta.sections.is_empty());

    let json = serde_json::to_value(&meta).unwrap();
    assert!(json.get("category").is_none());
    assert!(json.get("folder").is_none());
    assert!(json.get("sections").is_none());
}

#[test]
fn default_kind_omitted_from_json() {
    let meta = cred_metadata("Password", "password", FieldKind::default());
    let json = serde_json::to_value(&meta).unwrap();
    assert!(json.get("kind").is_none());
}

#[test]
fn legacy_credential_metadata_loads_with_defaults() {
    let meta: VaultCredentialMetadata =
        serde_json::from_str(r#"{"title":"Password","key":"password"}"#).unwrap();
    assert_eq!(meta.kind, FieldKind::default());
    assert_eq!(meta.position, None);
    assert_eq!(meta.section, None);
}

#[test]
fn position_omitted_when_unset_and_roundtrips_when_set() {
    let meta = cred_metadata("Password", "password", FieldKind::default());
    let json = serde_json::to_value(&meta).unwrap();
    assert!(json.get("position").is_none());

    let mut meta = meta;
    meta.position = Some(2);
    let json = serde_json::to_value(&meta).unwrap();
    assert_eq!(json.get("position").and_then(|v| v.as_u64()), Some(2));
    let back: VaultCredentialMetadata = serde_json::from_value(json).unwrap();
    assert_eq!(back.position, Some(2));
}

#[test]
fn non_default_kind_roundtrips_through_metadata() {
    let meta = cred_metadata(
        "Notes",
        "notes",
        FieldKind::Text(TextField {
            multiline: Some(true),
        }),
    );
    let json = serde_json::to_value(&meta).unwrap();
    let back: VaultCredentialMetadata = serde_json::from_value(json).unwrap();
    assert_eq!(back.kind, meta.kind);
}

#[test]
fn folder_and_section_metadata_refuse_unknown_fields() {
    let id = ShortId::encode_uuid(Uuid::new_v4());
    let folder = serde_json::json!({"id": id, "title": "Folder"});
    let section = serde_json::json!({"id": id, "title": "Section"});
    let metadata = |folder: &serde_json::Value| serde_json::json!({"folders": [folder]});
    let item = |section: &serde_json::Value| serde_json::json!({"title": "Item", "key": "item", "sections": [section]});
    assert!(serde_json::from_value::<VaultMetadata>(metadata(&folder)).is_ok());
    assert!(serde_json::from_value::<VaultItemMetadata>(item(&section)).is_ok());

    let mut folder = folder;
    folder["x"] = serde_json::json!(1);
    let mut section = section;
    section["x"] = serde_json::json!(1);
    assert!(serde_json::from_value::<VaultMetadata>(metadata(&folder)).is_err());
    assert!(serde_json::from_value::<VaultItemMetadata>(item(&section)).is_err());
}

#[test]
fn stale_credential_metadata_field_fails_load() {
    let vault = vault_with_credentials("site", &["password"]);
    let (item_id, cred_id) = vault.get_credential_ids("site", "password").unwrap();
    let mut encrypted = vault.to_encrypted(true).unwrap();
    let stale = LooseMetadata {
        fields: BTreeMap::from([
            ("title".to_string(), serde_json::json!("Password")),
            ("key".to_string(), serde_json::json!("password")),
            ("last_used_at".to_string(), serde_json::json!(1_700_000_000)),
        ]),
    };
    let blob = vault
        .cipher
        .encrypt_cred_metadata_as_for_test(item_id, cred_id, &stale);
    cred_mut(&mut encrypted, item_id, cred_id).metadata = blob;

    let result = Vault::from_encrypted_with_cipher(vault.cipher.duplicate(), encrypted);
    assert!(matches!(result, Err(Error::VaultSecretDecryptionError)));
}
