use super::support::{
    add_cred, cred_id, cred_mut, item_id_of, load_encrypted, reload, secret_of, set_value,
    test_vault, try_load_encrypted, vault_with_credentials,
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
fn import_item_in_other_vault_preserves_history() {
    let mut source = vault_with_credentials("item", &["alpha"]);
    set_value(&mut source, "item", "alpha", "second");
    set_value(&mut source, "item", "alpha", "third");
    let item_id = item_id_of(&source, "item");
    let cred_id = cred_id(&source, "item", "alpha");
    let history_ids: Vec<_> = source
        .list_history("item", "alpha")
        .unwrap()
        .iter()
        .map(|h| h.id)
        .collect();

    let transfer = source.export_item("item").unwrap();
    let mut dest = test_vault();
    let imported = dest.import_item(transfer, Some("Moved Item")).unwrap();
    assert_eq!(imported.key, "moved-item");
    assert_eq!(imported.id, item_id);
    assert_eq!(imported.credentials.keys().next(), Some(&cred_id));

    assert_eq!(secret_of(&dest, "moved-item", "alpha"), "third");
    assert_eq!(
        history_values(&dest, "moved-item", "alpha"),
        vec!["second", "secret"]
    );
    let moved_ids: Vec<_> = dest
        .list_history("moved-item", "alpha")
        .unwrap()
        .iter()
        .map(|h| h.id)
        .collect();
    assert_eq!(moved_ids, history_ids);

    let dest = reload(&dest);
    assert_eq!(secret_of(&dest, "moved-item", "alpha"), "third");
    assert_eq!(
        history_values(&dest, "moved-item", "alpha"),
        vec!["second", "secret"]
    );
}

#[test]
fn import_item_rejects_taken_key() {
    let source = vault_with_credentials("item", &["alpha"]);
    let mut dest = vault_with_credentials("item", &["beta"]);

    let transfer = source.export_item("item").unwrap();
    let err = dest.import_item(transfer, None).unwrap_err();
    assert!(matches!(err, Error::DuplicateItemKey(_)));
    assert!(dest.get_item_credential("item", "alpha").is_err());
    assert!(dest.get_item_credential("item", "beta").is_ok());
}

#[test]
fn importing_item_unfiles_it() {
    let mut source = vault_with_credentials("item", &["alpha"]);
    let folder = source.create_folder("Folder").id;
    source.move_item("item", Some(folder)).unwrap();

    let transfer = source.export_item("item").unwrap();
    let mut dest = test_vault();
    assert_eq!(dest.import_item(transfer, None).unwrap().folder, None);
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
            .all(|h| h.at > 0 && h.kind == HistoryKind::ValueUpdated)
    );
}

#[test]
fn added_history_values_precede_stored_entries_and_keep_times() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    set_value(&mut vault, "item", "alpha", "second");

    let entries = [
        (10, secrecy::SecretString::from("a")),
        (20, secrecy::SecretString::from("b")),
    ];
    vault.add_history_values("item", "alpha", &entries).unwrap();

    assert_eq!(secret_of(&vault, "item", "alpha"), "second");
    let vault = reload(&vault);
    assert_eq!(
        history_values(&vault, "item", "alpha"),
        vec!["secret", "b", "a"]
    );
    let times: Vec<i64> = vault
        .list_history("item", "alpha")
        .unwrap()
        .iter()
        .map(|h| h.at)
        .collect();
    assert_eq!(&times[1..], [20, 10]);
}

/// Kinds of the stored history entries of a live credential, oldest first.
fn history_kinds(vault: &Vault, item_key: &str, cred_key: &str) -> Vec<HistoryKind> {
    let item_id = item_id_of(vault, item_key);
    let cred_id = cred_id(vault, item_key, cred_key);
    vault
        .history_overviews(item_id, cred_id, vault.history.get(&cred_id))
        .into_iter()
        .map(|h| h.kind)
        .collect()
}

#[test]
fn first_non_empty_value_adds_created_entry() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    assert_eq!(
        history_kinds(&vault, "item", "alpha"),
        [HistoryKind::ValueCreated]
    );
    let created = vault.history[&cred_id(&vault, "item", "alpha")][0].id;
    assert!(matches!(
        vault.get_history_value("item", "alpha", created),
        Err(Error::InvalidHistoryEntry(_))
    ));

    // A credential created with no value has no entry until it is given one.
    add_cred(&mut vault, "item", "empty", "Empty", "");
    assert!(history_kinds(&vault, "item", "empty").is_empty());
    set_value(&mut vault, "item", "empty", "first");
    set_value(&mut vault, "item", "empty", "second");
    assert_eq!(
        history_kinds(&vault, "item", "empty"),
        [HistoryKind::ValueCreated, HistoryKind::ValueUpdated]
    );

    let vault = reload(&vault);
    assert_eq!(
        history_kinds(&vault, "item", "empty"),
        [HistoryKind::ValueCreated, HistoryKind::ValueUpdated]
    );
}

#[test]
fn unknown_history_kind_survives_reload_and_rekey() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    let (item_id, cred_id) = vault.get_credential_ids("item", "alpha").unwrap();
    let kind = HistoryKind::Unknown(serde_json::json!({"type": "renamed", "from": "Old"}));
    let entry = DecryptedHistoryEntry {
        id: Uuid::new_v4(),
        metadata: HistoryMetadata {
            at: 5,
            kind: kind.clone(),
        },
        value: None,
    };
    let encrypted = vault
        .cipher
        .encrypt_history_entry(item_id, cred_id, &entry)
        .unwrap();
    vault.history.entry(cred_id).or_default().push(encrypted);
    let expected = [HistoryKind::ValueCreated, kind];

    let vault = reload(&vault);
    assert_eq!(history_kinds(&vault, "item", "alpha"), expected);
    let rekeyed = vault
        .rekeyed(None, |raw| Ok(VaultFileKey::new(raw.to_vec())))
        .unwrap();
    assert_eq!(history_kinds(&rekeyed, "item", "alpha"), expected);
    // An unknown kind is not a previous value.
    assert!(rekeyed.list_history("item", "alpha").unwrap().is_empty());
}

#[test]
fn item_history_lists_events_newest_first() {
    let mut vault = vault_with_credentials("item", &["alpha", "beta"]);
    set_value(&mut vault, "item", "alpha", "second");
    vault.delete_item_credential("item", "beta").unwrap();

    let events = vault.item_history("item").unwrap();
    assert!(events.windows(2).all(|pair| pair[0].at >= pair[1].at));
    let mut seen: Vec<(String, Option<&str>, bool)> = events
        .iter()
        .map(|event| {
            let change = match &event.change {
                ItemChange::History { kind, .. } => format!("{kind:?}"),
                other => format!("{other:?}"),
            };
            let key = event.credential.map(|c| c.key.as_str());
            (change, key, event.credential_deleted)
        })
        .collect();
    seen.sort();
    let expected = [
        ("CredentialDeleted", Some("beta"), true),
        ("ItemCreated", None, false),
        ("ValueCreated", Some("alpha"), false),
        ("ValueCreated", Some("beta"), true),
        ("ValueUpdated", Some("alpha"), false),
    ]
    .map(|(change, key, deleted)| (change.to_string(), key, deleted));
    assert_eq!(seen, expected);
}

#[test]
fn save_same_first_or_empty_adds_no_previous() {
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
fn restore_only_previous_over_empty_records_created() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    set_value(&mut vault, "item", "alpha", "");
    let first = vault.list_history("item", "alpha").unwrap()[0].id;

    vault.restore_history_value("item", "alpha", first).unwrap();

    assert_eq!(secret_of(&vault, "item", "alpha"), "secret");
    assert!(vault.list_history("item", "alpha").unwrap().is_empty());
    assert_eq!(
        history_kinds(&vault, "item", "alpha"),
        [HistoryKind::ValueCreated, HistoryKind::ValueCreated]
    );
}

#[test]
fn history_metadata_that_fails_to_decrypt_fails_load() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    set_value(&mut vault, "item", "alpha", "second");
    set_value(&mut vault, "item", "alpha", "third");
    let item_id = item_id_of(&vault, "item");
    let cred_id = cred_id(&vault, "item", "alpha");

    let mut encrypted = vault.to_encrypted(true).unwrap();
    let cred = cred_mut(&mut encrypted, item_id, cred_id);
    let first_metadata = cred.history[0].metadata.clone();
    cred.history[1].metadata = first_metadata;

    let result = try_load_encrypted(encrypted);
    assert!(matches!(result, Err(Error::VaultSecretDecryptionError)));
}

#[test]
fn history_value_presence_not_matching_kind_fails_load() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    set_value(&mut vault, "item", "alpha", "second");
    let item_id = item_id_of(&vault, "item");
    let cred_id = cred_id(&vault, "item", "alpha");

    // A `value-updated` entry without its value.
    let mut encrypted = vault.to_encrypted(true).unwrap();
    cred_mut(&mut encrypted, item_id, cred_id).history[1].value = None;
    assert!(matches!(
        try_load_encrypted(encrypted),
        Err(Error::InvalidHistoryEntry(_))
    ));

    // A `value-created` entry with a value.
    let mut encrypted = vault.to_encrypted(true).unwrap();
    let cred = cred_mut(&mut encrypted, item_id, cred_id);
    cred.history[0].value = cred.history[1].value.clone();
    assert!(matches!(
        try_load_encrypted(encrypted),
        Err(Error::InvalidHistoryEntry(_))
    ));
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
    assert!(!vault.history.contains_key(&cred_id));

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
    let cred_id = cred_id(&vault, "item", "alpha");

    vault.delete_item("item").unwrap();
    assert!(!vault.history.contains_key(&cred_id));

    let mut vault = reload(&vault);
    vault.restore_item(item_id, None).unwrap();
    assert_eq!(history_values(&vault, "item", "alpha"), vec!["secret"]);

    let vault = reload(&vault);
    assert_eq!(history_values(&vault, "item", "alpha"), vec!["secret"]);
    assert_eq!(secret_of(&vault, "item", "alpha"), "second");
}

#[test]
fn history_exported_and_omitted_from_file_when_empty() {
    let mut vault = vault_with_credentials("item", &["alpha"]);
    add_cred(&mut vault, "item", "empty", "Empty", "");

    let json = serde_json::to_value(vault.to_encrypted(false).unwrap()).unwrap();
    let creds = json["items"]
        .as_object()
        .unwrap()
        .values()
        .flat_map(|item| item["credentials"].as_object().unwrap().values())
        .collect::<Vec<_>>();
    // Only the credential with no value has no history.
    assert_eq!(
        creds.iter().filter(|c| c.get("history").is_none()).count(),
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

    // Entry 0 is `value-created`, which holds no value.
    // A history value in the live value's place.
    let mut encrypted = vault.to_encrypted(true).unwrap();
    let cred = cred_mut(&mut encrypted, item_id, cred_id);
    cred.value = cred.history[1].value.clone().unwrap();
    let swapped = load_encrypted(encrypted);
    assert!(swapped.get_item_credential_secret("item", "alpha").is_err());

    // A history value in another history entry's place.
    let mut encrypted = vault.to_encrypted(true).unwrap();
    let cred = cred_mut(&mut encrypted, item_id, cred_id);
    let first_value = cred.history[1].value.clone();
    cred.history[2].value = first_value;
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
