use super::support::{
    add_cred, cred_id, populate_caches, reload, set_value, vault_with_credentials,
};
use super::*;
use crate::secrets::vaults::model::fields::TextField;

#[test]
fn export_leaves_out_passkeys_unless_asked() {
    let mut vault = vault_with_credentials("site", &["password"]);
    vault
        .add_or_update_item_credential(
            "site",
            "passkey-1",
            "Passkey",
            FieldKind::Passkey,
            SecretString::from("{}"),
        )
        .unwrap();
    let cipher = Aes256Gcm::new(&Aes256Gcm::generate_key(OsRng));
    let item_id = *vault.get_item_id("site").unwrap();
    let count = |include_passkeys| {
        vault
            .to_bundled_vault(None, Uuid::new_v4(), &cipher, include_passkeys)
            .unwrap()
            .items[&item_id]
            .credentials
            .len()
    };

    assert_eq!(count(true), 2);
    assert_eq!(count(false), 1);
    // The vault itself keeps the passkey.
    assert_eq!(vault.get_item("site").unwrap().credentials.len(), 2);
}

#[test]
fn updating_credential_kind_persists_through_save() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    assert_eq!(
        vault.get_item_credential("item", "alpha").unwrap().kind,
        FieldKind::default()
    );
    populate_caches(&mut vault);

    let new_kind = FieldKind::Text(TextField {
        multiline: Some(true),
    });
    vault
        .add_or_update_item_credential(
            "item",
            "alpha",
            "alpha",
            new_kind.clone(),
            SecretString::from("secret"),
        )
        .unwrap();
    assert_eq!(
        vault.get_item_credential("item", "alpha").unwrap().kind,
        new_kind
    );

    let vault = reload(&vault);
    assert_eq!(
        vault.get_item_credential("item", "alpha").unwrap().kind,
        new_kind
    );
}

#[test]
fn transferring_credential_keeps_its_value_history_and_id() {
    let mut vault = vault_with_credentials("item", &["password"]);
    set_value(&mut vault, "item", "password", "new");
    let id = cred_id(&vault, "item", "password");
    let section = vault.create_item_section("other-item", "Old").unwrap().id;

    vault
        .transfer_item_credential(
            "item",
            "password",
            "other-item",
            "old-password",
            Some(section),
        )
        .unwrap();
    // The blobs are re-encrypted for the destination, so they decrypt there
    // after a save.
    let vault = reload(&vault);

    assert!(vault.get_item_credential("item", "password").is_err());
    let moved = vault
        .get_item_credential("other-item", "old-password")
        .unwrap();
    assert_eq!(moved.id, id);
    assert_eq!(moved.section, Some(section));
    let value = vault
        .get_item_credential_secret("other-item", "old-password")
        .unwrap()
        .unwrap();
    assert_eq!(value.expose_secret(), "new");
    let history = vault.list_history("other-item", "old-password").unwrap();
    assert_eq!(history.len(), 1);
    let previous = vault
        .get_history_value("other-item", "old-password", history[0].id)
        .unwrap();
    assert_eq!(previous.expose_secret(), "secret");
}

#[test]
fn transferring_credential_rejects_taken_key() {
    let mut vault = vault_with_credentials("item", &["password"]);
    let err = vault
        .transfer_item_credential("item", "password", "other-item", "elsewhere", None)
        .unwrap_err();
    assert!(matches!(err, Error::DuplicateCredentialKey(_)));
    assert!(vault.get_item_credential("item", "password").is_ok());
}

#[test]
fn records_resolve_by_id_after_credential_renamed() {
    let mut vault = vault_with_credentials("item", &["password"]);
    let item_id = *vault.get_item_id("item").unwrap();
    let id = cred_id(&vault, "item", "password");

    vault
        .add_or_update_item_credential(
            "item",
            "password",
            "Renamed",
            FieldKind::default(),
            SecretString::from("new-secret"),
        )
        .unwrap();

    let secret = vault
        .get_item_credential_secret_by_id(item_id, id)
        .unwrap()
        .unwrap();
    assert_eq!(secret.expose_secret(), "new-secret");
    assert_eq!(
        vault.get_item_credential_by_id(item_id, id).unwrap().title,
        "Renamed"
    );
    assert!(vault.get_item_by_id(Uuid::new_v4()).is_err());
    assert!(
        vault
            .get_item_credential_by_id(item_id, Uuid::new_v4())
            .is_err()
    );
}

#[test]
fn updating_credential_keeps_its_value_and_persists() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    populate_caches(&mut vault);

    let new_kind = FieldKind::Text(TextField {
        multiline: Some(true),
    });
    vault
        .update_item_credential(
            "item",
            "alpha",
            CredentialUpdate {
                key: Some("renamed".to_string()),
                title: Some(" Renamed ".to_string()),
                kind: Some(new_kind.clone()),
            },
        )
        .unwrap();

    let vault = reload(&vault);
    assert!(matches!(
        vault.get_item_credential("item", "alpha"),
        Err(Error::InvalidCredentialKey(_))
    ));
    let cred = vault.get_item_credential("item", "renamed").unwrap();
    assert_eq!(cred.title, "Renamed");
    assert_eq!(cred.kind, new_kind);
    let secret = vault
        .get_item_credential_secret("item", "renamed")
        .unwrap()
        .unwrap();
    assert_eq!(secret.expose_secret(), "secret");
}

#[test]
fn marking_credential_used_persists_without_history() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    populate_caches(&mut vault);
    let marked = vault
        .mark_credential_used("item", "alpha", 1_750_000_000, &TimeZone::UTC)
        .unwrap();
    assert!(marked);

    let vault = reload(&vault);
    let cred = vault.get_item_credential("item", "alpha").unwrap();
    assert_eq!(cred.last_used_day_at, Some(1_750_000_000));
    assert!(vault.list_history("item", "alpha").unwrap().is_empty());
    let secret = vault
        .get_item_credential_secret("item", "alpha")
        .unwrap()
        .unwrap();
    assert_eq!(secret.expose_secret(), "secret");
}

#[test]
fn use_on_same_local_day_not_written() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let zone = TimeZone::fixed(jiff::tz::Offset::from_seconds(-7 * 3600).unwrap());
    let first = jiff::civil::date(2026, 10, 22)
        .at(8, 0, 0, 0)
        .to_zoned(zone.clone())
        .unwrap()
        .timestamp()
        .as_second();
    assert!(
        vault
            .mark_credential_used("item", "alpha", first, &zone)
            .unwrap()
    );
    populate_caches(&mut vault);
    let (_, cred_id) = vault.get_credential_ids("item", "alpha").unwrap();
    let cached = |vault: &Vault| {
        vault
            .cred_blobs
            .get(&cred_id)
            .map(|blob| serde_json::to_string(blob).unwrap())
    };
    let before = cached(&vault);
    assert!(before.is_some());

    // 23:59 the same day at UTC-7, and on the next day in UTC.
    let marked = vault
        .mark_credential_used("item", "alpha", first + 15 * 3600 + 59 * 60, &zone)
        .unwrap();

    assert!(!marked);
    assert_eq!(cached(&vault), before);
    let cred = vault.get_item_credential("item", "alpha").unwrap();
    assert_eq!(cred.last_used_day_at, Some(first));
}

#[test]
fn adding_credential_with_taken_key_fails() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let err = vault
        .add_item_credential(
            "item",
            "alpha",
            "Title",
            FieldKind::default(),
            SecretString::from("other".to_string()),
        )
        .unwrap_err();
    assert!(matches!(err, Error::DuplicateCredentialKey(_)));
    let secret = vault
        .get_item_credential_secret("item", "alpha")
        .unwrap()
        .unwrap();
    assert_ne!(secret.expose_secret(), "other");
    add_cred(&mut vault, "item", "gamma", "Title", "new");
}

#[test]
fn updating_credential_to_taken_key_fails() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    let err = vault
        .update_item_credential(
            "item",
            "alpha",
            CredentialUpdate {
                key: Some("beta".to_string()),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert!(matches!(err, Error::DuplicateCredentialKey(_)));
    // The same key is not a conflict with itself.
    vault
        .update_item_credential(
            "item",
            "alpha",
            CredentialUpdate {
                key: Some("alpha".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
}
