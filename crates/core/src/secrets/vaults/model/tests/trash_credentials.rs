use super::support::{deleted_ids, populate_caches, reload, secret_of, vault_with_credentials};
use super::*;

#[test]
fn deleted_credentials_survive_save_and_load_as_deleted() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    populate_caches(&mut vault);
    let cred_id = vault.get_item_credential("item", "alpha").unwrap().id;

    vault.delete_item_credential("item", "alpha").unwrap();
    assert!(vault.get_item_credential("item", "alpha").is_err());
    assert_eq!(deleted_ids(&vault, "item"), vec![cred_id]);

    let vault = reload(&vault);
    assert!(vault.get_item_credential("item", "alpha").is_err());
    assert!(vault.get_item_credential("item", "beta").is_ok());
    let deleted = vault.list_deleted("item").unwrap();
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0].credential.id, cred_id);
    assert_eq!(deleted[0].credential.key, "alpha");
    assert!(deleted[0].deleted_at > 0);
    assert!(vault.list_deleted("other-item").unwrap().is_empty());
}

#[test]
fn deleting_credential_frees_its_key() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    vault.delete_item_credential("item", "alpha").unwrap();
    vault
        .add_item_credential(
            "item",
            "alpha",
            "New",
            FieldKind::default(),
            SecretString::from("new".to_string()),
        )
        .unwrap();
    assert_eq!(secret_of(&vault, "item", "alpha"), "new");
    assert_eq!(deleted_ids(&vault, "item").len(), 1);
}

#[test]
fn restoring_keeps_id_value_position_and_section() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    let section_id = vault.create_item_section("item", "Login").unwrap().id;
    let placements = vec![
        CredentialPlacement {
            key: "beta".to_string(),
            section: None,
        },
        CredentialPlacement {
            key: "alpha".to_string(),
            section: Some(section_id),
        },
    ];
    vault.reorder_item_credentials("item", &placements).unwrap();
    populate_caches(&mut vault);
    let cred_id = vault.get_item_credential("item", "alpha").unwrap().id;

    vault.delete_item_credential("item", "alpha").unwrap();
    let mut vault = reload(&vault);
    vault
        .restore_item_credential("item", cred_id, None)
        .unwrap();
    assert!(deleted_ids(&vault, "item").is_empty());

    let vault = reload(&vault);
    let cred = vault.get_item_credential("item", "alpha").unwrap();
    assert_eq!(cred.id, cred_id);
    assert_eq!(cred.position, Some(1));
    assert_eq!(cred.section, Some(section_id));
    assert_eq!(secret_of(&vault, "item", "alpha"), "secret");
}

#[test]
fn restoring_with_taken_key_fails_unless_new_key_given() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    populate_caches(&mut vault);
    let cred_id = vault.get_item_credential("item", "alpha").unwrap().id;
    vault.delete_item_credential("item", "alpha").unwrap();
    vault
        .add_item_credential(
            "item",
            "alpha",
            "New",
            FieldKind::default(),
            SecretString::from("new".to_string()),
        )
        .unwrap();

    let err = vault
        .restore_item_credential("item", cred_id, None)
        .unwrap_err();
    assert!(matches!(err, Error::DuplicateCredentialKey(_)));
    let err = vault
        .restore_item_credential("item", cred_id, Some("alpha".to_string()))
        .unwrap_err();
    assert!(matches!(err, Error::DuplicateCredentialKey(_)));
    // A failed restore leaves the credential deleted.
    assert_eq!(deleted_ids(&vault, "item"), vec![cred_id]);

    vault
        .restore_item_credential("item", cred_id, Some("alpha-old".to_string()))
        .unwrap();
    let vault = reload(&vault);
    assert_eq!(secret_of(&vault, "item", "alpha-old"), "secret");
    assert_eq!(secret_of(&vault, "item", "alpha"), "new");
    assert_eq!(
        vault.get_item_credential("item", "alpha-old").unwrap().id,
        cred_id
    );
}

#[test]
fn restoring_with_invalid_new_key_fails() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let cred_id = vault.get_item_credential("item", "alpha").unwrap().id;
    vault.delete_item_credential("item", "alpha").unwrap();
    let err = vault
        .restore_item_credential("item", cred_id, Some("  ".to_string()))
        .unwrap_err();
    assert!(matches!(err, Error::InvalidCredentialKey(_)));
    assert_eq!(deleted_ids(&vault, "item"), vec![cred_id]);
}

#[test]
fn restoring_through_another_item_fails() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let cred_id = vault.get_item_credential("item", "alpha").unwrap().id;
    vault.delete_item_credential("item", "alpha").unwrap();
    let err = vault
        .restore_item_credential("other-item", cred_id, None)
        .unwrap_err();
    assert!(matches!(err, Error::InvalidCredentialKey(_)));
    let err = vault
        .purge_item_credential("other-item", cred_id)
        .unwrap_err();
    assert!(matches!(err, Error::InvalidCredentialKey(_)));
    assert_eq!(deleted_ids(&vault, "item"), vec![cred_id]);
}

#[test]
fn purging_removes_deleted_credential_for_good() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    let alpha = vault.get_item_credential("item", "alpha").unwrap().id;
    vault.delete_item_credential("item", "alpha").unwrap();
    vault.delete_item_credential("item", "beta").unwrap();

    vault.purge_item_credential("item", alpha).unwrap();
    assert!(matches!(
        vault.restore_item_credential("item", alpha, None),
        Err(Error::InvalidCredentialKey(_))
    ));

    let vault = reload(&vault);
    assert_eq!(vault.list_deleted("item").unwrap().len(), 1);
    assert_eq!(
        vault.list_deleted("item").unwrap()[0].credential.key,
        "beta"
    );
}

#[test]
fn purge_deleted_removes_entries_older_than_cutoff() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    vault.delete_item_credential("item", "alpha").unwrap();
    vault.delete_item_credential("item", "beta").unwrap();

    assert_eq!(vault.purge_deleted(0), 0);
    assert_eq!(vault.list_deleted("item").unwrap().len(), 2);
    assert_eq!(vault.purge_deleted(i64::MAX), 2);
    assert!(vault.list_deleted("item").unwrap().is_empty());
}
