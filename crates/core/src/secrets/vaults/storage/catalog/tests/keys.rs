use super::*;

#[test]
fn vault_key_read_from_file_and_not_from_file_name() {
    let fx = Fixture::new();
    fx.write_edited("misnamed", other_vault("work"));

    let vaults = fx.catalog.list();

    assert_eq!(vaults.into_keys().collect::<Vec<_>>(), ["personal", "work"]);
}

#[test]
fn file_without_key_not_listed() {
    let fx = Fixture::new();
    fx.write_edited("keyless", |vault| {
        vault["id"] = json!(ShortId::encode_uuid(Uuid::new_v4()));
        vault.as_object_mut().unwrap().remove("key");
    });

    let scan = fx.catalog.scan();

    assert_eq!(scan.vaults.into_keys().collect::<Vec<_>>(), ["personal"]);
    assert!(scan.duplicate_keys.is_empty(), "{:?}", scan.duplicate_keys);
}

#[test]
fn files_that_claim_one_key_both_reported() {
    let fx = Fixture::new();
    fx.write_edited("other", other_vault("personal"));
    let other_id = VaultHeader::peek(&fx.vault_path("other")).unwrap().id;

    let scan = fx.catalog.scan();

    assert_eq!(
        scan.duplicate_keys,
        [DuplicateVaultKeys {
            key: "personal".to_string(),
            paths: vec![fx.vault_path("other"), fx.vault_path("personal")],
        }]
    );
    assert!(scan.duplicates.is_empty(), "{:?}", scan.duplicates);
    assert!(scan.vaults.is_empty(), "{:?}", scan.vaults.keys());
    assert!(!fx.is_tracked(fx.personal_id()));
    assert!(!fx.is_tracked(other_id));
}

#[test]
fn internal_and_external_files_that_claim_one_key_both_reported() {
    let fx = Fixture::with_external(&["outside"]);
    fx.write_copy(&fx.external_path("outside"), other_vault("personal"));

    let scan = fx.catalog.scan();

    assert_eq!(
        scan.duplicate_keys,
        [DuplicateVaultKeys {
            key: "personal".to_string(),
            paths: vec![fx.external_path("outside"), fx.vault_path("personal")],
        }]
    );
    assert!(scan.vaults.is_empty(), "{:?}", scan.vaults.keys());
    assert!(!fx.is_tracked(fx.personal_id()));
}

#[test]
fn file_with_duplicate_id_and_key_reported_for_each() {
    let fx = Fixture::new();
    fx.write_edited("copy", |vault| vault["key"] = json!("personal"));
    let paths = vec![fx.vault_path("copy"), fx.vault_path("personal")];

    let scan = fx.catalog.scan();

    assert_eq!(
        scan.duplicates,
        [DuplicateVaults {
            id: fx.personal_id(),
            paths: paths.clone(),
        }]
    );
    assert_eq!(
        scan.duplicate_keys,
        [DuplicateVaultKeys {
            key: "personal".to_string(),
            paths,
        }]
    );
    assert!(scan.vaults.is_empty());
}

#[test]
fn file_whose_key_differs_only_in_case_not_listed() {
    let fx = Fixture::new();
    fx.write_edited("upper", other_vault("Personal"));

    let scan = fx.catalog.scan();

    // A stored key must already be normalized, so `Personal` is refused
    // as an invalid key and does not claim `personal`.
    assert_eq!(scan.vaults.into_keys().collect::<Vec<_>>(), ["personal"]);
    assert!(scan.duplicate_keys.is_empty(), "{:?}", scan.duplicate_keys);
}

#[test]
fn load_refuses_key_whose_id_held_by_two_files() {
    let fx = Fixture::new();
    fx.write_edited("copy", |_| {});

    for key in ["personal", "copy"] {
        let result = fx.catalog.load(key);
        assert!(
            matches!(result, Err(Error::DuplicateVaultId(_))),
            "{key}: {:?}",
            result.err()
        );
    }
    assert!(!fx.is_tracked(fx.personal_id()));
}

#[test]
fn load_refuses_key_held_by_two_files() {
    let fx = Fixture::new();
    fx.write_edited("other", other_vault("personal"));

    let result = fx.catalog.load("personal");

    assert!(
        matches!(result, Err(Error::DuplicateVaultKey(_))),
        "{:?}",
        result.err()
    );
    assert!(!fx.is_tracked(fx.personal_id()));
}

#[test]
fn load_finds_vault_by_key_stored_in_file() {
    let fx = Fixture::new();
    fx.write_edited("misnamed", other_vault("work"));

    let vh = fx.catalog.load("work").unwrap();

    assert_eq!(vh.path, fx.vault_path("misnamed"));
    assert!(matches!(
        fx.catalog.load("misnamed"),
        Err(Error::VaultNotFound(_))
    ));
}

#[test]
fn write_through_key_of_one_of_two_files_with_one_id_fails() {
    let fx = Fixture::new();
    fx.write_edited("copy", |_| {});
    let before = [
        fs::read_to_string(fx.vault_path("personal")).unwrap(),
        fs::read_to_string(fx.vault_path("copy")).unwrap(),
    ];
    let manager = Mutex::new(VaultsManager::with(fx.catalog.clone()));

    for key in ["personal", "copy"] {
        let result = VaultsManager::write_vault::<_, _, Error>(&manager, key, |vh| {
            vh.add_item("item", "Item").map(|_| ())
        });
        assert!(
            matches!(result, Err(Error::DuplicateVaultId(_))),
            "{key}: {:?}",
            result.err()
        );
    }

    let after = [
        fs::read_to_string(fx.vault_path("personal")).unwrap(),
        fs::read_to_string(fx.vault_path("copy")).unwrap(),
    ];
    assert_eq!(after, before);
    let versions = fx.catalog.files().list_versions(fx.personal_id()).unwrap();
    assert!(versions.is_empty());
}

#[test]
fn created_vault_named_by_id_and_holds_its_key() {
    let fx = Fixture::new();
    let key = fx.catalog.unclaimed_key("Work Vault", None).unwrap();
    let mut vault = Vault::new_for_test();
    vault.set_key(key);

    let vh = fx.catalog.create_vault(vault).unwrap();

    let id = vh.vault_id().unwrap();
    let name = format!("{}.json", ShortId::encode_uuid(id));
    assert_eq!(vh.path, fx.catalog.vaults_dir().join(name));
    let header = VaultHeader::peek(&vh.path).unwrap();
    assert_eq!(header.id, id);
    assert_eq!(header.key, "work-vault");
    assert_eq!(fx.catalog.load("work-vault").unwrap().path, vh.path);
}

#[test]
fn create_refuses_key_another_vault_holds_in_any_letter_case() {
    let fx = Fixture::new();

    // `normalized_key` lowercases and replaces whitespace with `-`, so
    // each of these is `personal`. The check runs before the keychain is
    // read.
    for key in ["personal", "Personal", " PERSONAL "] {
        let result = fx.catalog.create(None, key);
        assert!(
            matches!(&result, Err(Error::InvalidVaultKey(message)) if message.contains("already exists")),
            "{key}: {:?}",
            result.err()
        );
    }
    assert_eq!(fs::read_dir(fx.catalog.vaults_dir()).unwrap().count(), 1);
}

#[test]
fn key_of_file_refused_for_its_id_is_still_claimed() {
    let fx = Fixture::new();
    fx.write_edited("copy", |_| {});

    assert!(fx.catalog.unclaimed_key("copy", None).is_err());
    assert!(fx.catalog.unclaimed_key("personal", None).is_err());
    assert_eq!(fx.catalog.unclaimed_key("work", None).unwrap(), "work");
}

#[test]
fn key_of_another_vault_claimed_and_own_key_not() {
    let fx = Fixture::new();
    fx.write_edited("work", other_vault("work"));
    let own = fx.vault_path("personal");

    assert!(fx.catalog.unclaimed_key("work", Some(&own)).is_err());
    assert_eq!(
        fx.catalog.unclaimed_key("personal", Some(&own)).unwrap(),
        "personal"
    );
}

#[test]
fn import_refuses_key_another_vault_holds() {
    let fx = Fixture::new();
    let id = Uuid::new_v4();
    let bundle = ImportableBundle::for_test(&[id]);
    let selection = BTreeMap::from([(id, import_as("PERSONAL"))]);

    let result = fx
        .catalog
        .import(bundle, &selection, AuthContext::SharedThreadLocal);

    assert!(
        matches!(&result, Err(Error::InvalidVaultKey(message)) if message.contains("already exists")),
        "{:?}",
        result.err()
    );
    assert_eq!(fs::read_dir(fx.catalog.vaults_dir()).unwrap().count(), 1);
}
