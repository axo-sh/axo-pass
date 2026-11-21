use super::*;

#[test]
fn vault_with_unparsable_items_listed_by_name() {
    let fx = Fixture::new();
    fx.break_items();

    let vaults = fx.catalog.list();

    let vh = vaults.get("personal").expect("vault is listed");
    assert_eq!(vh.vault_name(), Some("Personal"));
}

#[test]
fn vault_with_unparsable_items_fails_to_unlock() {
    let fx = Fixture::new();
    fx.break_items();

    let err = fx
        .catalog
        .open("personal", AuthContext::SharedThreadLocal)
        .err()
        .expect("unlock fails");

    assert!(
        matches!(err, Error::VaultDeserializationError(_)),
        "{err:?}"
    );
}

#[test]
fn file_without_id_not_listed() {
    let fx = Fixture::new();
    fx.write_edited("missing-id", |vault| {
        vault.as_object_mut().unwrap().remove("id");
    });

    let vaults = fx.catalog.list();

    assert_eq!(vaults.into_keys().collect::<Vec<_>>(), ["personal"]);
}

#[test]
fn file_whose_id_not_uuid_not_listed() {
    let fx = Fixture::new();
    fx.write_edited("bad-id", |vault| vault["id"] = json!("not-a-uuid"));

    let vaults = fx.catalog.list();

    assert_eq!(vaults.into_keys().collect::<Vec<_>>(), ["personal"]);
}

#[test]
fn files_in_vaults_dir_with_one_id_both_reported() {
    let fx = Fixture::new();
    fx.write_edited("copy", |_| {});

    let scan = fx.catalog.scan();

    assert_eq!(
        scan.duplicates,
        [DuplicateVaults {
            id: fx.personal_id(),
            paths: vec![fx.vault_path("copy"), fx.vault_path("personal")],
        }]
    );
}

#[test]
fn files_whose_ids_differ_only_in_case_both_reported() {
    let fx = Fixture::new();
    let lower = "bhRFe93MKwHktZwXKG599a";
    let upper = "bhRFe93MKwHktZwXKG599A";
    fx.write_edited("lower", |vault| vault["id"] = json!(lower));
    fx.write_edited("upper", |vault| vault["id"] = json!(upper));
    let lower_id = ShortId::parse_uuid(lower).unwrap();
    let upper_id = ShortId::parse_uuid(upper).unwrap();
    assert_ne!(lower_id, upper_id);

    let scan = fx.catalog.scan();

    assert_eq!(
        scan.duplicates,
        [DuplicateVaults {
            id: lower_id.min(upper_id),
            paths: vec![fx.vault_path("lower"), fx.vault_path("upper")],
        }]
    );
    assert_eq!(scan.vaults.into_keys().collect::<Vec<_>>(), ["personal"]);
    assert!(!fx.is_tracked(lower_id));
    assert!(!fx.is_tracked(upper_id));
}

#[test]
fn hyphenated_and_short_forms_of_one_id_both_reported() {
    let fx = Fixture::new();
    let short = ShortId::encode_uuid(fx.personal_id());
    fx.write_edited("short", |vault| vault["id"] = json!(short));
    let hyphenated = fx.personal_id().hyphenated().to_string().to_uppercase();
    fx.write_edited("upper", |vault| vault["id"] = json!(hyphenated));

    let scan = fx.catalog.scan();

    assert_eq!(
        scan.duplicates,
        [DuplicateVaults {
            id: fx.personal_id(),
            paths: vec![
                fx.vault_path("personal"),
                fx.vault_path("short"),
                fx.vault_path("upper"),
            ],
        }]
    );
    assert!(scan.vaults.is_empty());
}

#[test]
fn external_vault_signed_and_verified() {
    let fx = Fixture::with_external(&["outside"]);
    let path = fx.external_path("outside");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let vh = VaultHandle::new_for_test_at(path.clone());
    fx.catalog.files().create(&vh).unwrap();
    let signer = fx.catalog.signer().as_ref();

    assert_eq!(
        EncryptedVault::load(&path, signer).unwrap().id,
        vh.vault_id().unwrap()
    );
    let committed = fx
        .catalog
        .files()
        .write_unlocked::<_, Error>(&vh, |vw| vw.add_item("item", "Item").map(|_| ()))
        .unwrap();
    assert!(committed.changed);
    EncryptedVault::load(&path, signer).unwrap();
    assert!(fx.catalog.list().contains_key("outside"));

    // An edit by hand under the old signature is refused at the next
    // write, and the file is not modified.
    let saved = fs::read_to_string(&path).unwrap();
    let edited = saved.replacen("\"key\": \"outside\"", "\"key\": \"edited\"", 1);
    assert_ne!(edited, saved);
    fs::write(&path, &edited).unwrap();
    let result = fx
        .catalog
        .files()
        .write_unlocked::<_, Error>(&vh, |vw| vw.add_item("other", "Other").map(|_| ()));
    assert!(matches!(result, Err(Error::VaultSignatureInvalid)));
    assert_eq!(fs::read_to_string(&path).unwrap(), edited);
}

#[test]
fn unsigned_file_that_claims_key_of_vault_refuses_both() {
    // The scan reads headers without verifying them, so an unsigned file
    // claims a key as a signed one does.
    let fx = Fixture::new();
    fx.write_edited("forged", other_vault("personal"));
    let path = fx.vault_path("forged");
    let mut fields: BTreeMap<String, Box<serde_json::value::RawValue>> =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    fields.remove("signature").unwrap();
    fs::write(&path, serde_json::to_string_pretty(&fields).unwrap()).unwrap();

    let scan = fx.catalog.scan();

    assert_eq!(
        scan.duplicate_keys,
        [DuplicateVaultKeys {
            key: "personal".to_string(),
            paths: vec![path, fx.vault_path("personal")],
        }]
    );
    assert!(scan.vaults.is_empty());
}

#[test]
fn internal_and_external_files_with_one_id_both_reported() {
    let fx = Fixture::with_external(&["outside"]);
    fx.write_copy(&fx.external_path("outside"), |_| {});

    let scan = fx.catalog.scan();

    assert_eq!(
        scan.duplicates,
        [DuplicateVaults {
            id: fx.personal_id(),
            paths: vec![fx.external_path("outside"), fx.vault_path("personal")],
        }]
    );
    assert!(scan.vaults.is_empty());
    assert!(!fx.is_tracked(fx.personal_id()));
}

#[test]
fn files_with_one_id_neither_listed_nor_tracked() {
    let fx = Fixture::new();
    fx.write_edited("copy", |_| {});

    let vaults = fx.catalog.list();

    assert!(vaults.is_empty(), "{:?}", vaults.keys());
    assert!(!fx.is_tracked(fx.personal_id()));
}

#[test]
fn vault_with_another_id_listed_beside_duplicates() {
    let fx = Fixture::new();
    fx.write_edited("copy", |_| {});
    let work_id = Uuid::new_v4();
    fx.write_edited("work", |vault| vault["id"] = json!(work_id));

    let scan = fx.catalog.scan();

    assert_eq!(scan.vaults.into_keys().collect::<Vec<_>>(), ["work"]);
    assert!(fx.is_tracked(work_id));
    assert_eq!(scan.duplicates.len(), 1);
    assert_eq!(scan.duplicates[0].id, fx.personal_id());
}

#[test]
fn external_link_to_listed_file_not_duplicate() {
    let fx = Fixture::with_external(&["alias"]);
    let link = fx.external_path("alias");
    fs::create_dir_all(link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(fx.vault_path("personal"), &link).unwrap();

    let scan = fx.catalog.scan();

    assert!(scan.duplicates.is_empty(), "{:?}", scan.duplicates);
    assert!(scan.duplicate_keys.is_empty(), "{:?}", scan.duplicate_keys);
    assert_eq!(scan.vaults.into_keys().collect::<Vec<_>>(), ["personal"]);
    assert!(fx.is_tracked(fx.personal_id()));
}
