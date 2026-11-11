use super::support::{
    cred_id, deleted_ids, item_id_of, load_encrypted, populate_caches, reload, secret_of,
    try_load_encrypted, vault_with_credentials,
};
use super::*;

#[test]
fn changing_item_key_moves_credentials_and_survives_reload() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let item_id = item_id_of(&vault, "item");
    let secret = secret_of(&vault, "item", "alpha");

    let item = vault.change_item_key("item", "Renamed Item").unwrap();
    assert_eq!(item.key, "renamed-item");
    assert!(vault.get_item("item").is_err());
    assert!(vault.get_item_credential("item", "alpha").is_err());
    assert_eq!(secret_of(&vault, "renamed-item", "alpha"), secret);

    let vault = reload(&vault);
    assert_eq!(item_id_of(&vault, "renamed-item"), item_id);
    assert_eq!(secret_of(&vault, "renamed-item", "alpha"), secret);
}

#[test]
fn changing_item_key_rejects_taken_and_invalid_keys() {
    let mut vault = vault_with_credentials("item", &["alpha"]);

    let err = vault.change_item_key("item", "other-item").unwrap_err();
    assert!(matches!(err, Error::DuplicateItemKey(_)));
    let err = vault.change_item_key("item", "").unwrap_err();
    assert!(matches!(err, Error::InvalidItemKey(_)));
    assert!(vault.change_item_key("item", "item").is_ok());
    assert!(vault.get_item_credential("item", "alpha").is_ok());
}

#[test]
fn deleting_item_drops_its_cached_credential_metadata() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    populate_caches(&mut vault);
    let cred_id = cred_id(&vault, "item", "alpha");

    vault.delete_item("item").unwrap();
    assert!(!vault.cred_blobs.contains_key(&cred_id));
}

#[test]
fn deleted_item_survives_save_and_load_and_frees_its_key() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    populate_caches(&mut vault);
    let item_id = item_id_of(&vault, "item");

    vault.delete_item("item").unwrap();
    assert!(vault.get_item("item").is_err());
    assert!(vault.get_item_credential("item", "alpha").is_err());
    assert!(vault.get_item("other-item").is_ok());

    let mut vault = reload(&vault);
    assert!(vault.get_item("item").is_err());
    let deleted = vault.list_deleted_items();
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0].item.id, item_id);
    assert_eq!(deleted[0].item.key, "item");
    assert_eq!(deleted[0].item.credentials.len(), 2);
    assert!(deleted[0].deleted_at > 0);

    // The key can be used by a new item.
    vault.add_or_update_item("item", "New").unwrap();
    assert_ne!(item_id_of(&vault, "item"), item_id);
}

#[test]
fn restoring_item_brings_back_credentials_values_and_layout() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    let folder_id = vault.create_folder("Work").id;
    vault.move_item("item", Some(folder_id)).unwrap();
    let section_id = vault.create_item_section("item", "Login").unwrap().id;
    vault
        .move_item_credential("item", "beta", Some(section_id))
        .unwrap();
    let alpha_id = cred_id(&vault, "item", "alpha");
    populate_caches(&mut vault);
    let item_id = item_id_of(&vault, "item");

    vault.delete_item("item").unwrap();
    let mut vault = reload(&vault);
    vault.restore_item(item_id, None).unwrap();
    assert!(vault.list_deleted_items().is_empty());

    let vault = reload(&vault);
    let item = vault.get_item("item").unwrap();
    assert_eq!(item.id, item_id);
    assert_eq!(item.folder, Some(folder_id));
    assert_eq!(item.sections.get(&section_id).unwrap().title, "Login");
    assert_eq!(cred_id(&vault, "item", "alpha"), alpha_id);
    assert_eq!(
        vault.get_item_credential("item", "beta").unwrap().section,
        Some(section_id)
    );
    assert_eq!(secret_of(&vault, "item", "alpha"), "secret");
    assert_eq!(secret_of(&vault, "item", "beta"), "secret");
}

#[test]
fn deleted_item_keeps_its_own_deleted_credentials() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    populate_caches(&mut vault);
    let alpha_id = cred_id(&vault, "item", "alpha");
    let item_id = item_id_of(&vault, "item");
    vault.delete_item_credential("item", "alpha").unwrap();

    vault.delete_item("item").unwrap();
    assert!(vault.deleted.is_empty());
    assert_eq!(vault.list_deleted_items()[0].deleted_credentials.len(), 1);

    let mut vault = reload(&vault);
    vault.restore_item(item_id, None).unwrap();
    assert_eq!(deleted_ids(&vault, "item"), vec![alpha_id]);
    assert!(vault.get_item_credential("item", "beta").is_ok());

    vault
        .restore_item_credential("item", alpha_id, None)
        .unwrap();
    let vault = reload(&vault);
    assert_eq!(secret_of(&vault, "item", "alpha"), "secret");
}

#[test]
fn restoring_item_needs_new_key_if_taken() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let item_id = item_id_of(&vault, "item");
    vault.delete_item("item").unwrap();
    vault.add_or_update_item("item", "New").unwrap();

    let err = vault.restore_item(item_id, None).unwrap_err();
    assert!(matches!(err, Error::DuplicateItemKey(_)));
    let err = vault
        .restore_item(item_id, Some("item".to_string()))
        .unwrap_err();
    assert!(matches!(err, Error::DuplicateItemKey(_)));
    let err = vault
        .restore_item(item_id, Some("  ".to_string()))
        .unwrap_err();
    assert!(matches!(err, Error::InvalidItemKey(_)));
    // A failed restore leaves the item deleted.
    assert_eq!(vault.list_deleted_items().len(), 1);

    vault
        .restore_item(item_id, Some("item-old".to_string()))
        .unwrap();
    let vault = reload(&vault);
    assert_eq!(vault.get_item("item-old").unwrap().id, item_id);
    assert_eq!(secret_of(&vault, "item-old", "alpha"), "secret");
    assert_ne!(item_id_of(&vault, "item"), item_id);
}

#[test]
fn restoring_item_into_deleted_folder_unfiles_it() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let folder_id = vault.create_folder("Work").id;
    vault.move_item("item", Some(folder_id)).unwrap();
    populate_caches(&mut vault);
    let item_id = item_id_of(&vault, "item");

    vault.delete_item("item").unwrap();
    vault.delete_folder(folder_id).unwrap();
    vault.restore_item(item_id, None).unwrap();

    let vault = reload(&vault);
    assert_eq!(vault.get_item("item").unwrap().folder, None);
}

fn deleted_secret_of(vault: &Vault, item_id: Uuid, cred_id: Uuid) -> String {
    vault
        .get_deleted_credential_secret(item_id, cred_id)
        .unwrap()
        .expose_secret()
        .clone()
}

#[test]
fn list_all_deleted_groups_by_live_item() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    let alpha_id = cred_id(&vault, "item", "alpha");
    let elsewhere_id = cred_id(&vault, "other-item", "elsewhere");
    vault.delete_item_credential("item", "alpha").unwrap();
    vault
        .delete_item_credential("other-item", "elsewhere")
        .unwrap();

    let vault = reload(&vault);
    let all = vault.list_all_deleted();
    let mut found: Vec<(Uuid, &str)> = all
        .iter()
        .map(|e| (e.credential.credential.id, e.item.key.as_str()))
        .collect();
    found.sort();
    let mut expected = vec![(alpha_id, "item"), (elsewhere_id, "other-item")];
    expected.sort();
    assert_eq!(found, expected);
}

#[test]
fn list_all_deleted_leaves_out_credentials_of_deleted_items() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    vault.delete_item_credential("item", "alpha").unwrap();
    vault.delete_item("item").unwrap();
    assert!(vault.list_all_deleted().is_empty());
}

#[test]
fn deleted_secrets_can_be_read_in_every_deleted_location() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    let item_id = item_id_of(&vault, "item");
    let alpha_id = cred_id(&vault, "item", "alpha");
    let beta_id = cred_id(&vault, "item", "beta");
    let other_item_id = item_id_of(&vault, "other-item");

    // Deleted from a live item.
    vault.delete_item_credential("item", "alpha").unwrap();
    let vault = reload(&vault);
    assert_eq!(deleted_secret_of(&vault, item_id, alpha_id), "secret");

    // In a deleted item, and deleted before the item.
    let mut vault = vault;
    vault.delete_item("item").unwrap();
    let vault = reload(&vault);
    assert_eq!(deleted_secret_of(&vault, item_id, alpha_id), "secret");
    assert_eq!(deleted_secret_of(&vault, item_id, beta_id), "secret");

    // A credential id is only valid with its own item.
    assert!(matches!(
        vault.get_deleted_credential_secret(other_item_id, alpha_id),
        Err(Error::InvalidCredentialKey(_))
    ));
    assert!(matches!(
        vault.get_deleted_credential_secret(item_id, Uuid::new_v4()),
        Err(Error::InvalidCredentialKey(_))
    ));
}

#[test]
fn live_credential_has_no_deleted_secret() {
    let vault = vault_with_credentials("item", &["alpha"]);
    let item_id = item_id_of(&vault, "item");
    let alpha_id = cred_id(&vault, "item", "alpha");
    assert!(matches!(
        vault.get_deleted_credential_secret(item_id, alpha_id),
        Err(Error::InvalidCredentialKey(_))
    ));
}

#[test]
fn purging_item_removes_it_and_its_deleted_credentials() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    vault.delete_item_credential("item", "alpha").unwrap();
    let item_id = item_id_of(&vault, "item");
    vault.delete_item("item").unwrap();

    vault.purge_item(item_id).unwrap();
    assert!(matches!(
        vault.restore_item(item_id, None),
        Err(Error::DeletedItemNotFound(_))
    ));
    assert!(matches!(
        vault.purge_item(item_id),
        Err(Error::DeletedItemNotFound(_))
    ));

    let encrypted = vault.to_encrypted(true).unwrap();
    assert!(encrypted.deleted.is_empty());
    assert!(vault.deleted.is_empty());
}

#[test]
fn purge_deleted_includes_deleted_credentials_of_deleted_items() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    vault.delete_item_credential("item", "alpha").unwrap();
    vault
        .delete_item_credential("other-item", "elsewhere")
        .unwrap();
    let item_id = item_id_of(&vault, "item");
    vault.delete_item("item").unwrap();

    assert_eq!(vault.purge_deleted(i64::MAX), 2);
    assert!(vault.deleted.is_empty());
    assert_eq!(vault.list_deleted_items()[0].deleted_credentials.len(), 0);

    // The deleted item itself is kept.
    vault.restore_item(item_id, None).unwrap();
    assert!(vault.list_deleted("item").unwrap().is_empty());
    assert!(vault.get_item_credential("item", "beta").is_ok());
}

#[test]
fn purge_deleted_items_removes_entries_older_than_cutoff() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    vault.delete_item("item").unwrap();
    vault.delete_item("other-item").unwrap();

    assert_eq!(vault.purge_deleted_items(0), 0);
    assert_eq!(vault.list_deleted_items().len(), 2);
    assert_eq!(vault.purge_deleted_items(i64::MAX), 2);
    assert!(vault.list_deleted_items().is_empty());
}

#[test]
fn bundled_export_leaves_out_deleted_items() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    vault.delete_item("item").unwrap();

    assert_eq!(vault.to_encrypted(true).unwrap().deleted.len(), 1);
    let without = vault.to_encrypted(false).unwrap();
    assert!(without.deleted.is_empty());
    assert_eq!(without.items.len(), 1);
}

#[test]
fn vault_file_without_deleted_field_loads_with_no_deleted_items() {
    let vault = vault_with_credentials("item", &["alpha"]);
    let json = serde_json::to_value(vault.to_encrypted(true).unwrap()).unwrap();
    assert!(json.get("deleted").is_none());

    let encrypted: EncryptedVault = serde_json::from_value(json).unwrap();
    let vault = load_encrypted(encrypted);
    assert!(vault.list_deleted_items().is_empty());
}

#[test]
fn deleted_item_info_is_bound_to_its_item() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    vault.delete_item("item").unwrap();
    vault.delete_item("other-item").unwrap();

    // Swap the info blobs of the two deleted items.
    let mut encrypted = vault.to_encrypted(true).unwrap();
    let mut entries = encrypted.deleted.values_mut();
    let (first, second) = (entries.next().unwrap(), entries.next().unwrap());
    std::mem::swap(&mut first.info, &mut second.info);

    assert!(try_load_encrypted(encrypted).is_err());
}

#[test]
fn bundled_export_leaves_out_deleted_credentials() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    vault.delete_item_credential("item", "alpha").unwrap();

    let with_deleted = vault.to_encrypted(true).unwrap();
    assert!(
        with_deleted
            .items
            .values()
            .any(|item| !item.deleted.is_empty())
    );
    let without_deleted = vault.to_encrypted(false).unwrap();
    assert!(
        without_deleted
            .items
            .values()
            .all(|item| item.deleted.is_empty())
    );
}

#[test]
fn old_item_file_without_deleted_loads() {
    let vault = vault_with_credentials("item", &["alpha"]);
    let json = serde_json::to_value(vault.to_encrypted(true).unwrap()).unwrap();
    for item in json["items"].as_object().unwrap().values() {
        assert!(item.get("deleted").is_none());
    }

    let encrypted: EncryptedVault = serde_json::from_value(json).unwrap();
    let vault = load_encrypted(encrypted);
    assert!(vault.deleted.is_empty());
    assert!(vault.get_item_credential("item", "alpha").is_ok());
}

#[test]
fn deleted_info_is_bound_to_its_credential() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    vault.delete_item_credential("item", "alpha").unwrap();
    vault.delete_item_credential("item", "beta").unwrap();

    // Swap the info blobs of the two deleted entries.
    let mut encrypted = vault.to_encrypted(true).unwrap();
    let item = encrypted
        .items
        .values_mut()
        .find(|item| item.deleted.len() == 2)
        .unwrap();
    let mut entries = item.deleted.values_mut();
    let (first, second) = (entries.next().unwrap(), entries.next().unwrap());
    std::mem::swap(&mut first.info, &mut second.info);

    assert!(try_load_encrypted(encrypted).is_err());
}
