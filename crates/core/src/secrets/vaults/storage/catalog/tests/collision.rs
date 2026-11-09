use super::*;

#[test]
fn id_check_finds_external_vault_not_tracked() {
    let fx = Fixture::with_external(&["outside"]);
    fx.write_copy(&fx.external_path("outside"), other_vault("outside"));
    let id = VaultHeader::peek(&fx.external_path("outside")).unwrap().id;
    assert!(!fx.is_tracked(id));

    let catalog = fx.without_keychain();
    assert_eq!(catalog.existing_ids([id]), BTreeSet::from([id]));
    let result = catalog.import(
        ImportableBundle::for_test(&[id]),
        &BTreeMap::from([(id, import_as("elsewhere"))]),
        AuthContext::SharedThreadLocal,
    );

    assert!(
        matches!(result, Err(Error::VaultIdExists(_))),
        "{:?}",
        result.err()
    );
    assert_eq!(fx.vault_file_names().len(), 1);
}

#[test]
fn id_check_finds_id_that_differs_only_in_letter_case() {
    let fx = Fixture::new();
    let lower = "bhRFe93MKwHktZwXKG599a";
    let upper_id = ShortId::parse_uuid("bhRFe93MKwHktZwXKG599A").unwrap();
    fx.write_edited("lower", |vault| vault["id"] = json!(lower));

    let catalog = fx.without_keychain();
    assert_eq!(catalog.existing_ids([upper_id]), BTreeSet::from([upper_id]));
    let result = catalog.import(
        ImportableBundle::for_test(&[upper_id]),
        &BTreeMap::from([(upper_id, import_as("upper"))]),
        AuthContext::SharedThreadLocal,
    );

    assert!(
        matches!(result, Err(Error::VaultIdExists(_))),
        "{:?}",
        result.err()
    );
}

#[test]
fn collision_report_lists_ids_without_keychain() {
    let fx = Fixture::new();
    // A file refused for a duplicate id and an unsigned file still hold
    // their ids.
    fx.write_edited("copy", |_| {});
    fx.write_edited("unsigned", other_vault("unsigned"));
    let path = fx.vault_path("unsigned");
    let unsigned_id = VaultHeader::peek(&path).unwrap().id;
    let mut fields: BTreeMap<String, Box<serde_json::value::RawValue>> =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    fields.remove("signature").unwrap();
    fs::write(&path, serde_json::to_string_pretty(&fields).unwrap()).unwrap();
    fx.write_edited("work", other_vault("work"));
    let work_id = VaultHeader::peek(&fx.vault_path("work")).unwrap().id;
    let absent = Uuid::new_v4();

    let existing = fx
        .without_keychain()
        .existing_ids([fx.personal_id(), unsigned_id, absent]);

    assert_eq!(existing, BTreeSet::from([fx.personal_id(), unsigned_id]));
    assert!(!existing.contains(&work_id));
}
