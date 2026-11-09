use super::support::{cred_id, reload, vault_with_credentials};
use super::*;

#[test]
fn autofill_survives_save_and_decrypts_with_its_own_aad() {
    use crate::secrets::vaults::autofill::item::{MatchKind, Website};

    let mut vault = vault_with_credentials("item", &["username", "password", "totp"]);
    let autofill = ItemAutofill {
        websites: vec![Website::new("github.com", MatchKind::Host)],
        username: Some(cred_id(&vault, "item", "username")),
        password: Some(cred_id(&vault, "item", "password")),
        totp: Some(cred_id(&vault, "item", "totp")),
    };
    vault.set_item_autofill("item", autofill.clone()).unwrap();
    vault
        .set_item_category("item", Some("login".to_string()))
        .unwrap();

    let encrypted = vault.to_encrypted(true).unwrap();
    let item_id = *vault.get_item_id("item").unwrap();
    let enc_item = encrypted.items.get(&item_id).unwrap();
    let blob = enc_item.autofill.as_ref().unwrap();

    let decrypted = vault.cipher.decrypt_item_autofill(item_id, blob).unwrap();
    assert_eq!(*decrypted.expose_secret(), autofill);

    // The blob is bound to its item and role.
    assert!(
        vault
            .cipher
            .decrypt_item_autofill(Uuid::new_v4(), blob)
            .is_err()
    );
    let meta = vault
        .cipher
        .decrypt_item_metadata(item_id, &enc_item.metadata)
        .unwrap();
    assert_eq!(meta.expose_secret().category.as_deref(), Some("login"));
}

#[test]
fn items_without_autofill_store_no_blob() {
    let vault = vault_with_credentials("item", &["password"]);
    let encrypted = vault.to_encrypted(true).unwrap();
    assert!(encrypted.items.values().all(|item| item.autofill.is_none()));
}

#[test]
fn autofill_and_category_survive_delete_and_restore() {
    let mut vault = vault_with_credentials("item", &["username", "password"]);
    let autofill = ItemAutofill {
        username: Some(cred_id(&vault, "item", "username")),
        password: Some(cred_id(&vault, "item", "password")),
        ..Default::default()
    };
    vault.set_item_autofill("item", autofill.clone()).unwrap();
    vault
        .set_item_category("item", Some("login".to_string()))
        .unwrap();
    let item_id = *vault.get_item_id("item").unwrap();

    vault.delete_item("item").unwrap();
    let mut vault = reload(&vault);
    vault.restore_item(item_id, None).unwrap();
    let vault = reload(&vault);

    let item = vault.get_item("item").unwrap();
    assert_eq!(item.autofill, autofill);
    assert_eq!(item.category.as_deref(), Some("login"));
}

#[test]
fn deleting_credential_clears_its_role_slot() {
    let mut vault = vault_with_credentials("item", &["username", "password"]);
    vault
        .set_item_autofill(
            "item",
            ItemAutofill {
                username: Some(cred_id(&vault, "item", "username")),
                password: Some(cred_id(&vault, "item", "password")),
                ..Default::default()
            },
        )
        .unwrap();

    vault.delete_item_credential("item", "password").unwrap();

    let item = vault.get_item("item").unwrap();
    assert!(item.autofill.password.is_none());
    assert!(item.autofill.username.is_some());
}

#[test]
fn restoring_credential_gives_back_its_role() {
    let mut vault = vault_with_credentials("item", &["username", "password"]);
    let password = cred_id(&vault, "item", "password");
    vault
        .set_item_autofill(
            "item",
            ItemAutofill {
                username: Some(cred_id(&vault, "item", "username")),
                password: Some(password),
                ..Default::default()
            },
        )
        .unwrap();

    vault.delete_item_credential("item", "password").unwrap();
    // The role survives a save while the credential is deleted.
    let mut vault = reload(&vault);
    vault
        .restore_item_credential("item", password, None)
        .unwrap();
    let vault = reload(&vault);

    let item = vault.get_item("item").unwrap();
    assert_eq!(item.autofill.password, Some(password));
}

#[test]
fn restoring_credential_leaves_role_another_credential_took() {
    let mut vault = vault_with_credentials("item", &["password", "new-password"]);
    let old = cred_id(&vault, "item", "password");
    let new = cred_id(&vault, "item", "new-password");
    vault
        .set_item_autofill(
            "item",
            ItemAutofill {
                password: Some(old),
                ..Default::default()
            },
        )
        .unwrap();

    vault.delete_item_credential("item", "password").unwrap();
    vault
        .set_item_autofill(
            "item",
            ItemAutofill {
                password: Some(new),
                ..Default::default()
            },
        )
        .unwrap();
    vault.restore_item_credential("item", old, None).unwrap();

    let item = vault.get_item("item").unwrap();
    assert_eq!(item.autofill.password, Some(new));
    assert_eq!(item.autofill.role_of(old), None);
}

#[test]
fn one_credential_cannot_fill_both_roles() {
    let mut vault = vault_with_credentials("item", &["password"]);
    let id = cred_id(&vault, "item", "password");
    let err = vault
        .set_item_autofill(
            "item",
            ItemAutofill {
                username: Some(id),
                password: Some(id),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert!(matches!(err, Error::InvalidAutofill(_)));
}

#[test]
fn two_websites_with_one_url_refused() {
    use crate::secrets::vaults::autofill::item::{MatchKind, Website};

    let mut vault = vault_with_credentials("item", &["password"]);
    let autofill = ItemAutofill {
        websites: vec![
            Website::new("github.com", MatchKind::Domain),
            Website::new("github.com", MatchKind::Host),
        ],
        ..Default::default()
    };
    let err = vault.set_item_autofill("item", autofill).unwrap_err();
    assert!(matches!(err, Error::InvalidAutofill(_)));
    assert!(vault.get_item("item").unwrap().autofill.websites.is_empty());
}

#[test]
fn role_slot_must_point_into_item() {
    let mut vault = vault_with_credentials("item", &["password"]);
    let elsewhere = cred_id(&vault, "other-item", "elsewhere");
    let err = vault
        .set_item_autofill(
            "item",
            ItemAutofill {
                password: Some(elsewhere),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert!(matches!(err, Error::InvalidAutofill(_)));
}
