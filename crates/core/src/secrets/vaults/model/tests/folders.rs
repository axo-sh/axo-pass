use super::support::{load_encrypted, populate_caches, reload, test_vault, vault_with_credentials};
use super::*;

#[test]
fn folders_and_filing_survive_save_and_load() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let folder_id = vault.create_folder(" Work ").id;
    vault.move_item("item", Some(folder_id)).unwrap();

    let vault = reload(&vault);
    assert_eq!(vault.get_folder(folder_id).unwrap().title, "Work");
    assert_eq!(vault.get_item("item").unwrap().folder, Some(folder_id));
    assert_eq!(vault.get_item("other-item").unwrap().folder, None);
}

#[test]
fn moving_item_invalidates_its_cached_metadata() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let folder_id = vault.create_folder("Work").id;
    populate_caches(&mut vault);

    vault.move_item("item", Some(folder_id)).unwrap();
    let vault = reload(&vault);
    assert_eq!(vault.get_item("item").unwrap().folder, Some(folder_id));
}

#[test]
fn moving_item_to_unknown_folder_fails() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let err = vault.move_item("item", Some(Uuid::new_v4())).unwrap_err();
    assert!(matches!(err, Error::InvalidFolder(_)));
    assert_eq!(vault.get_item("item").unwrap().folder, None);
}

#[test]
fn renaming_folder_persists() {
    let mut vault = test_vault();
    let folder_id = vault.create_folder("Work").id;
    populate_caches(&mut vault);

    vault.rename_folder(folder_id, "Personal").unwrap();
    let vault = reload(&vault);
    assert_eq!(vault.get_folder(folder_id).unwrap().title, "Personal");
}

#[test]
fn deleting_folder_unfiles_its_items() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let folder_id = vault.create_folder("Work").id;
    vault.move_item("item", Some(folder_id)).unwrap();
    populate_caches(&mut vault);

    vault.delete_folder(folder_id).unwrap();
    assert_eq!(vault.get_item("item").unwrap().folder, None);

    let vault = reload(&vault);
    assert!(vault.list_folders().is_empty());
    assert_eq!(vault.get_item("item").unwrap().folder, None);
    assert!(vault.get_item_credential("item", "alpha").is_ok());
}

#[test]
fn passkey_reports_persist_in_vault_metadata() {
    use crate::secrets::vaults::passkey::signals::Report;

    let mut vault = test_vault();
    let folder_id = vault.create_folder("Work").id;
    populate_caches(&mut vault);

    let mut reports = SignalStore::new();
    reports.record(
        Report::Unknown {
            rp_id: "example.com".into(),
            credential_id: vec![1],
        },
        10,
    );
    vault.update_passkey_signals(|store| store.merge(&reports));
    let vault = reload(&vault);
    assert_eq!(vault.passkey_signals(), &reports);
    assert_eq!(vault.get_folder(folder_id).unwrap().title, "Work");
}

#[test]
fn item_in_missing_folder_loads_unfiled() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let folder_id = vault.create_folder("Work").id;
    vault.move_item("item", Some(folder_id)).unwrap();

    let mut encrypted = vault.to_encrypted(true).unwrap();
    encrypted.metadata = None;
    let vault = load_encrypted(encrypted);

    assert_eq!(vault.get_item("item").unwrap().folder, None);
    // The stale blob is not cached, so the next save writes the fix.
    assert!(
        !vault
            .item_blobs
            .contains_key(&vault.get_item("item").unwrap().id)
    );
}

#[test]
fn reorder_folders_requires_every_folder_once() {
    let mut vault = test_vault();
    let a = vault.create_folder("A").id;
    let b = vault.create_folder("B").id;

    assert!(matches!(
        vault.reorder_folders(&[a]),
        Err(Error::InvalidFolderOrder)
    ));
    assert!(matches!(
        vault.reorder_folders(&[a, a]),
        Err(Error::InvalidFolderOrder)
    ));
    assert!(matches!(
        vault.reorder_folders(&[a, Uuid::new_v4()]),
        Err(Error::InvalidFolderOrder)
    ));

    vault.reorder_folders(&[b, a]).unwrap();
    let vault = reload(&vault);
    assert_eq!(vault.get_folder(b).unwrap().position, Some(0));
    assert_eq!(vault.get_folder(a).unwrap().position, Some(1));
}
