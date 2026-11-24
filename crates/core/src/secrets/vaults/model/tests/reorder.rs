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
fn reorder_rejects_invalid_unsectioned_lists() {
    type Expected = fn(&Error) -> bool;
    type Case = (
        &'static str,
        &'static str,
        &'static [&'static str],
        &'static [&'static str],
        Expected,
    );
    let cases: [Case; 5] = [
        (
            "partial list",
            "item",
            &["alpha", "beta", "gamma"],
            &["beta", "alpha"],
            |err| matches!(err, Error::InvalidCredentialOrder(_)),
        ),
        (
            "duplicated key",
            "item",
            &["alpha", "beta"],
            &["alpha", "alpha"],
            |err| matches!(err, Error::InvalidCredentialOrder(_)),
        ),
        (
            "unknown key",
            "item",
            &["alpha", "beta"],
            &["alpha", "nope"],
            |err| matches!(err, Error::InvalidCredentialKey(_)),
        ),
        (
            "key from another item",
            "item",
            &["alpha", "beta"],
            &["alpha", "elsewhere"],
            |err| matches!(err, Error::InvalidCredentialKey(_)),
        ),
        ("unknown item", "nope", &["alpha"], &["alpha"], |err| {
            matches!(err, Error::InvalidItemKey(_))
        }),
    ];
    for (case, item_key, keys, order, expected) in cases {
        let mut vault = vault_with_credentials("item", keys);

        let err = vault
            .reorder_item_credentials(item_key, &unsectioned(order))
            .unwrap_err();

        assert!(expected(&err), "{case}: {err:?}");
        let unchanged = vec![None; keys.len()];
        assert_eq!(positions(&vault, "item", keys), unchanged, "{case}");
    }
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
