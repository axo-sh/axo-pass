use super::support::{placement, populate_caches, reload, vault_with_credentials};
use super::*;

fn unsectioned(cred_keys: &[&str]) -> Vec<CredentialPlacement> {
    cred_keys.iter().map(|k| placement(k, None)).collect()
}

fn positions(vault: &Vault, item_key: &str, cred_keys: &[&str]) -> Vec<Option<u32>> {
    cred_keys
        .iter()
        .map(|k| vault.get_item_credential(item_key, k).unwrap().position)
        .collect()
}

#[test]
fn reorder_assigns_positions_in_given_order() {
    let keys = ["alpha", "beta", "gamma"];
    let mut vault = vault_with_credentials("item", &keys);
    assert_eq!(positions(&vault, "item", &keys), vec![None, None, None]);

    vault
        .reorder_item_credentials("item", &unsectioned(&["gamma", "alpha", "beta"]))
        .unwrap();

    assert_eq!(
        positions(&vault, "item", &keys),
        vec![Some(1), Some(2), Some(0)]
    );
}

#[test]
fn reorder_invalidates_metadata_cache() {
    let keys = ["alpha", "beta"];
    let mut vault = vault_with_credentials("item", &keys);
    populate_caches(&mut vault);

    vault
        .reorder_item_credentials("item", &unsectioned(&["beta", "alpha"]))
        .unwrap();

    let vault = reload(&vault);
    assert_eq!(positions(&vault, "item", &keys), vec![Some(1), Some(0)]);
}

#[test]
fn reorder_rejects_partial_list() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta", "gamma"]);
    let err = vault
        .reorder_item_credentials("item", &unsectioned(&["beta", "alpha"]))
        .unwrap_err();
    assert!(matches!(err, Error::InvalidCredentialOrder(_)));
    assert_eq!(
        positions(&vault, "item", &["alpha", "beta", "gamma"]),
        vec![None, None, None]
    );
}

#[test]
fn reorder_rejects_duplicated_key() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    let err = vault
        .reorder_item_credentials("item", &unsectioned(&["alpha", "alpha"]))
        .unwrap_err();
    assert!(matches!(err, Error::InvalidCredentialOrder(_)));
}

#[test]
fn reorder_rejects_unknown_key() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    let err = vault
        .reorder_item_credentials("item", &unsectioned(&["alpha", "nope"]))
        .unwrap_err();
    assert!(matches!(err, Error::InvalidCredentialKey(_)));
}

#[test]
fn reorder_rejects_key_from_another_item() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    let err = vault
        .reorder_item_credentials("item", &unsectioned(&["alpha", "elsewhere"]))
        .unwrap_err();
    assert!(matches!(err, Error::InvalidCredentialKey(_)));
}

#[test]
fn reorder_rejects_unknown_item() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let err = vault
        .reorder_item_credentials("nope", &unsectioned(&["alpha"]))
        .unwrap_err();
    assert!(matches!(err, Error::InvalidItemKey(_)));
}

#[test]
fn reordered_positions_survive_save_and_load() {
    let keys = ["alpha", "beta", "gamma"];
    let mut vault = vault_with_credentials("item", &keys);
    vault
        .reorder_item_credentials("item", &unsectioned(&["gamma", "beta", "alpha"]))
        .unwrap();

    let vault = reload(&vault);
    assert_eq!(
        positions(&vault, "item", &keys),
        vec![Some(2), Some(1), Some(0)]
    );
}

#[test]
fn reorder_sets_sections_and_positions() {
    let keys = ["alpha", "beta", "gamma"];
    let mut vault = vault_with_credentials("item", &keys);
    let section_id = vault.create_item_section("item", "Login").unwrap().id;

    let placements = vec![
        placement("gamma", None),
        placement("alpha", Some(section_id)),
        placement("beta", Some(section_id)),
    ];
    vault.reorder_item_credentials("item", &placements).unwrap();

    let vault = reload(&vault);
    assert_eq!(
        positions(&vault, "item", &keys),
        vec![Some(1), Some(2), Some(0)]
    );
    let sections: Vec<Option<Uuid>> = keys
        .iter()
        .map(|k| vault.get_item_credential("item", k).unwrap().section)
        .collect();
    assert_eq!(sections, vec![Some(section_id), Some(section_id), None]);
}

#[test]
fn reorder_rejects_unknown_section_without_changes() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let placements = vec![placement("alpha", Some(Uuid::new_v4()))];
    let err = vault
        .reorder_item_credentials("item", &placements)
        .unwrap_err();
    assert!(matches!(err, Error::InvalidSection(_)));
    assert_eq!(positions(&vault, "item", &["alpha"]), vec![None]);
}
