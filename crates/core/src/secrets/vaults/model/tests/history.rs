use super::support::{
    add_cred, cred_id, cred_mut, item_id_of, load_encrypted, reload, secret_of, set_value,
    try_load_encrypted, vault_with_credentials,
};
use super::*;

fn history_values(vault: &Vault, item_key: &str, cred_key: &str) -> Vec<String> {
    vault
        .list_history(item_key, cred_key)
        .unwrap()
        .iter()
        .map(|h| {
            vault
                .get_history_value(item_key, cred_key, h.id)
                .unwrap()
                .expose_secret()
                .clone()
        })
        .collect()
}

#[test]
fn changing_value_keeps_old_value_in_history() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    assert!(vault.list_history("item", "alpha").unwrap().is_empty());

    set_value(&mut vault, "item", "alpha", "second");
    set_value(&mut vault, "item", "alpha", "third");

    assert_eq!(secret_of(&vault, "item", "alpha"), "third");
    // Most recently replaced first.
    assert_eq!(
        history_values(&vault, "item", "alpha"),
        vec!["second", "secret"]
    );
    assert!(
        vault
            .list_history("item", "alpha")
            .unwrap()
            .iter()
            .all(|h| h.replaced_at > 0)
    );
}

#[test]
fn saving_same_or_first_or_empty_value_adds_no_history() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    set_value(&mut vault, "item", "alpha", "secret");
    assert!(vault.list_history("item", "alpha").unwrap().is_empty());

    // A credential created with no value yet, then given one.
    add_cred(&mut vault, "item", "empty", "Empty", "");
    set_value(&mut vault, "item", "empty", "first");
    assert!(vault.list_history("item", "empty").unwrap().is_empty());
    set_value(&mut vault, "item", "empty", "second");
    assert_eq!(history_values(&vault, "item", "empty"), vec!["first"]);
}

#[test]
fn history_survives_save_and_load() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    set_value(&mut vault, "item", "alpha", "second");
    set_value(&mut vault, "item", "alpha", "third");

    let vault = reload(&vault);
    assert_eq!(secret_of(&vault, "item", "alpha"), "third");
    assert_eq!(
        history_values(&vault, "item", "alpha"),
        vec!["second", "secret"]
    );
}

#[test]
fn restoring_previous_value_swaps_it_with_current_value() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    set_value(&mut vault, "item", "alpha", "second");
    let first = vault.list_history("item", "alpha").unwrap()[0].id;

    vault.restore_history_value("item", "alpha", first).unwrap();

    assert_eq!(secret_of(&vault, "item", "alpha"), "secret");
    assert_eq!(history_values(&vault, "item", "alpha"), vec!["second"]);
    let vault = reload(&vault);
    assert_eq!(secret_of(&vault, "item", "alpha"), "secret");
    assert_eq!(history_values(&vault, "item", "alpha"), vec!["second"]);
}

#[test]
fn restoring_only_previous_value_clears_history() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    set_value(&mut vault, "item", "alpha", "");
    let first = vault.list_history("item", "alpha").unwrap()[0].id;

    vault.restore_history_value("item", "alpha", first).unwrap();

    assert_eq!(secret_of(&vault, "item", "alpha"), "secret");
    assert!(vault.history.is_empty());
}

#[test]
fn history_info_that_fails_to_decrypt_fails_load() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    set_value(&mut vault, "item", "alpha", "second");
    set_value(&mut vault, "item", "alpha", "third");
    let item_id = item_id_of(&vault, "item");
    let cred_id = cred_id(&vault, "item", "alpha");

    let mut encrypted = vault.to_encrypted(true).unwrap();
    let cred = cred_mut(&mut encrypted, item_id, cred_id);
    let first_info = cred.history[0].info.clone();
    cred.history[1].info = first_info;

    let result = try_load_encrypted(encrypted);
    assert!(matches!(result, Err(Error::VaultSecretDecryptionError)));
}

#[test]
fn restoring_unknown_previous_value_fails() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    set_value(&mut vault, "item", "alpha", "second");
    assert!(matches!(
        vault.restore_history_value("item", "alpha", Uuid::new_v4()),
        Err(Error::InvalidHistoryEntry(_))
    ));
    assert!(matches!(
        vault.get_history_value("item", "alpha", Uuid::new_v4()),
        Err(Error::InvalidHistoryEntry(_))
    ));
    assert!(matches!(
        vault.purge_history("item", "alpha", Uuid::new_v4()),
        Err(Error::InvalidHistoryEntry(_))
    ));
    assert_eq!(secret_of(&vault, "item", "alpha"), "second");
}

#[test]
fn purging_previous_value_removes_it_for_good() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    set_value(&mut vault, "item", "alpha", "second");
    set_value(&mut vault, "item", "alpha", "third");
    let newest = vault.list_history("item", "alpha").unwrap()[0].id;

    vault.purge_history("item", "alpha", newest).unwrap();
    assert_eq!(history_values(&vault, "item", "alpha"), vec!["secret"]);

    let vault = reload(&vault);
    assert_eq!(history_values(&vault, "item", "alpha"), vec!["secret"]);
    assert_eq!(secret_of(&vault, "item", "alpha"), "third");
}

#[test]
fn history_follows_credential_through_delete_and_restore() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    set_value(&mut vault, "item", "alpha", "second");
    let cred_id = cred_id(&vault, "item", "alpha");

    vault.delete_item_credential("item", "alpha").unwrap();
    assert!(vault.history.is_empty());

    let mut vault = reload(&vault);
    vault
        .restore_item_credential("item", cred_id, None)
        .unwrap();
    assert_eq!(history_values(&vault, "item", "alpha"), vec!["secret"]);
    assert_eq!(secret_of(&vault, "item", "alpha"), "second");
}

#[test]
fn history_follows_credential_through_item_delete_and_restore() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    set_value(&mut vault, "item", "alpha", "second");
    let item_id = item_id_of(&vault, "item");

    vault.delete_item("item").unwrap();
    assert!(vault.history.is_empty());

    let mut vault = reload(&vault);
    vault.restore_item(item_id, None).unwrap();
    assert_eq!(history_values(&vault, "item", "alpha"), vec!["secret"]);

    let vault = reload(&vault);
    assert_eq!(history_values(&vault, "item", "alpha"), vec!["secret"]);
    assert_eq!(secret_of(&vault, "item", "alpha"), "second");
}

#[test]
fn history_exported_and_omitted_from_file_when_empty() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    set_value(&mut vault, "item", "alpha", "second");

    let json = serde_json::to_value(vault.to_encrypted(false).unwrap()).unwrap();
    let creds = json["items"]
        .as_object()
        .unwrap()
        .values()
        .flat_map(|item| item["credentials"].as_object().unwrap().values())
        .collect::<Vec<_>>();
    assert_eq!(
        creds.iter().filter(|c| c.get("history").is_some()).count(),
        1
    );
}

#[test]
fn previous_value_cannot_be_swapped_into_another_place() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    set_value(&mut vault, "item", "alpha", "second");
    set_value(&mut vault, "item", "alpha", "third");
    let item_id = item_id_of(&vault, "item");
    let cred_id = cred_id(&vault, "item", "alpha");

    // A history value in the live value's place.
    let mut encrypted = vault.to_encrypted(true).unwrap();
    let cred = cred_mut(&mut encrypted, item_id, cred_id);
    cred.value = cred.history[0].value.clone();
    let swapped = load_encrypted(encrypted);
    assert!(swapped.get_item_credential_secret("item", "alpha").is_err());

    // A history value in another history entry's place.
    let mut encrypted = vault.to_encrypted(true).unwrap();
    let cred = cred_mut(&mut encrypted, item_id, cred_id);
    let first_value = cred.history[0].value.clone();
    cred.history[1].value = first_value;
    let swapped = load_encrypted(encrypted);
    let ids: Vec<Uuid> = swapped
        .list_history("item", "alpha")
        .unwrap()
        .iter()
        .map(|h| h.id)
        .collect();
    let decrypted: Vec<bool> = ids
        .iter()
        .map(|id| swapped.get_history_value("item", "alpha", *id).is_ok())
        .collect();
    // Only the entry that kept its own value decrypts.
    assert_eq!(decrypted.iter().filter(|ok| **ok).count(), 1);
}
