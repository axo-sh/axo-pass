use super::support::{cred_id, populate_caches, reload, vault_with_credentials};
use super::*;

#[test]
fn sections_and_placement_survive_save_and_load() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    let section_id = vault.create_item_section("item", "Login").unwrap().id;
    vault
        .move_item_credential("item", "beta", Some(section_id))
        .unwrap();

    let vault = reload(&vault);
    let item = vault.get_item("item").unwrap();
    assert_eq!(item.sections.get(&section_id).unwrap().title, "Login");
    assert_eq!(
        vault.get_item_credential("item", "beta").unwrap().section,
        Some(section_id)
    );
    assert_eq!(
        vault.get_item_credential("item", "alpha").unwrap().section,
        None
    );
}

#[test]
fn moving_credential_to_another_items_section_fails() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let other_section = vault.create_item_section("other-item", "S").unwrap().id;
    let err = vault
        .move_item_credential("item", "alpha", Some(other_section))
        .unwrap_err();
    assert!(matches!(err, Error::InvalidSection(_)));
}

#[test]
fn deleting_section_keeps_its_credentials() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let section_id = vault.create_item_section("item", "Login").unwrap().id;
    vault
        .move_item_credential("item", "alpha", Some(section_id))
        .unwrap();
    populate_caches(&mut vault);

    vault.delete_item_section("item", section_id).unwrap();

    let vault = reload(&vault);
    assert!(vault.get_item("item").unwrap().sections.is_empty());
    assert_eq!(
        vault.get_item_credential("item", "alpha").unwrap().section,
        None
    );
}

#[test]
fn renaming_and_reordering_sections_persists() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let a = vault.create_item_section("item", "A").unwrap().id;
    let b = vault.create_item_section("item", "B").unwrap().id;
    populate_caches(&mut vault);

    vault.rename_item_section("item", a, "Renamed").unwrap();
    assert!(matches!(
        vault.reorder_item_sections("item", &[b]),
        Err(Error::InvalidSectionOrder(_))
    ));
    vault.reorder_item_sections("item", &[b, a]).unwrap();

    let vault = reload(&vault);
    let sections = &vault.get_item("item").unwrap().sections;
    assert_eq!(sections.get(&a).unwrap().title, "Renamed");
    assert_eq!(sections.get(&a).unwrap().position, Some(1));
    assert_eq!(sections.get(&b).unwrap().position, Some(0));
}

#[test]
fn new_sections_go_last_regardless_of_title() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let a = vault.create_item_section("item", "zeta").unwrap().id;
    let b = vault.create_item_section("item", "Alpha").unwrap().id;
    // Without a position this section would sort first by title.
    let mut legacy = VaultItemSection::new("beta");
    legacy.position = None;
    let legacy_id = legacy.id;
    vault
        .edit_item("item", |item| {
            item.sections.insert(legacy_id, legacy);
            Ok(())
        })
        .unwrap();
    let c = vault.create_item_section("item", "Another").unwrap().id;

    let sections = &vault.get_item("item").unwrap().sections;
    let position = |id: Uuid| sections.get(&id).unwrap().position;
    assert_eq!(
        [position(a), position(b), position(legacy_id), position(c)],
        [Some(0), Some(1), Some(2), Some(3)]
    );
}

#[test]
fn credential_in_missing_section_loads_unsectioned() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let section_id = vault.create_item_section("item", "Login").unwrap().id;
    vault
        .move_item_credential("item", "alpha", Some(section_id))
        .unwrap();
    // Drop the section from the item without touching the credential, as
    // a stale or hand-edited file could.
    vault
        .items
        .values_mut()
        .for_each(|item| item.sections.clear());

    let vault = reload(&vault);
    assert_eq!(
        vault.get_item_credential("item", "alpha").unwrap().section,
        None
    );
}

#[test]
fn restoring_into_deleted_section_drops_section() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let section_id = vault.create_item_section("item", "Login").unwrap().id;
    vault
        .move_item_credential("item", "alpha", Some(section_id))
        .unwrap();
    populate_caches(&mut vault);
    let cred_id = cred_id(&vault, "item", "alpha");

    vault.delete_item_credential("item", "alpha").unwrap();
    vault.delete_item_section("item", section_id).unwrap();
    vault
        .restore_item_credential("item", cred_id, None)
        .unwrap();

    let vault = reload(&vault);
    assert_eq!(
        vault.get_item_credential("item", "alpha").unwrap().section,
        None
    );
}
