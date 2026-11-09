use super::*;

#[test]
fn default_import_of_existing_id_writes_nothing_and_names_id() {
    let fx = Fixture::new();
    let other = Uuid::new_v4();
    let bundle = ImportableBundle::for_test(&[fx.personal_id(), other]);
    let selection = BTreeMap::from([
        (fx.personal_id(), import_as("restored")),
        (other, import_as("other")),
    ]);
    let before = fx.vault_file_names();

    // The refusal comes before the keychain is read.
    let result = fx
        .without_keychain()
        .import(bundle, &selection, AuthContext::SharedThreadLocal);

    let Err(Error::VaultIdExists(ids)) = result else {
        panic!("{:?}", result.err());
    };
    assert_eq!(ids, ShortId::encode_uuid(fx.personal_id()));
    assert_eq!(fx.vault_file_names(), before);
}

#[test]
fn refusal_names_every_existing_id() {
    let fx = Fixture::new();
    fx.write_edited("work", other_vault("work"));
    let work_id = VaultHeader::peek(&fx.vault_path("work")).unwrap().id;
    let ids = [fx.personal_id(), work_id];
    let selection = BTreeMap::from([(ids[0], import_as("a")), (ids[1], import_as("b"))]);

    let result = fx.without_keychain().import(
        ImportableBundle::for_test(&ids),
        &selection,
        AuthContext::SharedThreadLocal,
    );

    let Err(Error::VaultIdExists(named)) = result else {
        panic!("{:?}", result.err());
    };
    for id in ids {
        assert!(named.contains(&ShortId::encode_uuid(id)), "{named}");
    }
}

#[test]
fn copy_has_new_id_and_file_key_and_both_vaults_load_verified() {
    let _audit = test_dir();
    let fx = Fixture::new();
    fx.write_personal("secret");
    let source = fs::read_to_string(fx.vault_path("personal")).unwrap();
    let bundle = fx.export_personal();
    let selection = BTreeMap::from([(
        fx.personal_id(),
        ImportSelection::new("Personal Copy", ImportAction::Copy),
    )]);

    let imported = fx
        .catalog
        .import(bundle, &selection, AuthContext::SharedThreadLocal)
        .unwrap();

    let copy_id = imported[0].peek_vault_id().unwrap();
    assert_ne!(copy_id, fx.personal_id());
    let copy_name = format!("{}.json", ShortId::encode_uuid(copy_id));
    assert_eq!(imported[0].path, fx.catalog.vaults_dir().join(copy_name));
    let signer = fx.catalog.signer().as_ref();
    let copy = EncryptedVault::load(&imported[0].path, signer).unwrap();
    let original = EncryptedVault::load(&fx.vault_path("personal"), signer).unwrap();
    assert_eq!(copy.key, "personal-copy");
    assert_eq!(copy.name.as_deref(), Some("Personal"));
    assert_eq!(copy.generation, 0);
    assert_eq!(copy.replica_id, None);
    assert!(copy.file_key != original.file_key);
    assert_eq!(fx.token("personal-copy").as_deref(), Some("secret"));
    assert_eq!(fx.token("personal").as_deref(), Some("secret"));
    assert_eq!(
        fs::read_to_string(fx.vault_path("personal")).unwrap(),
        source
    );
    let scan = fx.catalog.scan();
    assert!(scan.duplicates.is_empty(), "{:?}", scan.duplicates);
    assert_eq!(
        scan.vaults.into_keys().collect::<Vec<_>>(),
        ["personal", "personal-copy"]
    );

    // The event names the copy and the bundle vault it was made from.
    let event = audit::read(&AuditFilter::default())
        .events
        .into_iter()
        .find(|event| event.action == Action::VaultImported)
        .unwrap();
    assert_eq!(event.detail["vault_id"], ShortId::encode_uuid(copy_id));
    assert_eq!(
        event.detail[SOURCE_VAULT_ID],
        ShortId::encode_uuid(fx.personal_id())
    );
}

#[test]
fn copy_refused_under_key_of_its_source() {
    let fx = Fixture::new();
    let selection = BTreeMap::from([(
        fx.personal_id(),
        ImportSelection::new("personal", ImportAction::Copy),
    )]);

    let result = fx.without_keychain().import(
        ImportableBundle::for_test(&[fx.personal_id()]),
        &selection,
        AuthContext::SharedThreadLocal,
    );

    assert!(
        matches!(&result, Err(Error::InvalidVaultKey(message)) if message.contains("already exists")),
        "{:?}",
        result.err()
    );
    assert_eq!(fx.vault_file_names().len(), 1);
}

#[test]
fn action_applies_to_its_vault_only() {
    let _audit = test_dir();
    let fx = Fixture::new();
    let other = Uuid::new_v4();
    let selection = BTreeMap::from([
        (
            fx.personal_id(),
            ImportSelection::new("personal-copy", ImportAction::Copy),
        ),
        (other, import_as("other")),
    ]);

    let imported = fx
        .catalog
        .import(
            ImportableBundle::for_test(&[fx.personal_id(), other]),
            &selection,
            AuthContext::SharedThreadLocal,
        )
        .unwrap();

    let ids: BTreeMap<String, Uuid> = imported
        .iter()
        .map(|vh| (vh.key.clone(), vh.peek_vault_id().unwrap()))
        .collect();
    assert_eq!(ids["other"], other);
    assert_ne!(ids["personal-copy"], fx.personal_id());
    assert_eq!(fx.read("other").vault_id().unwrap(), other);
    assert_eq!(
        fx.read("personal-copy").vault_id().unwrap(),
        ids["personal-copy"]
    );
    assert_eq!(fx.read("personal").vault_id().unwrap(), fx.personal_id());
}
