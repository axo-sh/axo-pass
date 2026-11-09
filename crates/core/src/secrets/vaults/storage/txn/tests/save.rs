use super::*;

#[test]
fn saved_vault_signed_and_reloads_unchanged() {
    let fx = Fixture::new();
    fx.add(&fx.target(), "alpha", "one");

    let saved = fs::read_to_string(&fx.vault.path).unwrap();
    let file: serde_json::Value = serde_json::from_str(&saved).unwrap();
    assert!(file["signature"].is_string());
    let reloaded = fx.read(&fx.vault.path);
    assert_eq!(reloaded.vault_json().unwrap(), raw(&saved));
    assert_eq!(fx.value(&fx.vault.path, "alpha").as_deref(), Some("one"));
}

#[test]
fn reload_verifies_before_file_key_compared() {
    let fx = Fixture::new();
    let before = fs::read_to_string(&fx.vault.path).unwrap();
    let file: serde_json::Value = serde_json::from_str(&before).unwrap();
    let file_key = file["vault"]["file_key"].to_string();
    let other_key = serde_json::to_string(&VaultFileKey::new(vec![1u8; 32])).unwrap();
    assert_eq!(before.matches(&file_key).count(), 1);
    // A planted file key under the old signature. Without the signature
    // check, the file key comparison would retry and fail with
    // `VaultFileKeyChanged`.
    let planted = before.replacen(&file_key, &other_key, 1);
    fs::write(&fx.vault.path, &planted).unwrap();

    let ran = AtomicBool::new(false);
    let result = fx.files.write::<_, Error>(&fx.target(), fx.unlock(), |_| {
        ran.store(true, Ordering::SeqCst);
        Ok(())
    });

    assert!(matches!(result, Err(Error::VaultSignatureInvalid)));
    assert!(!ran.load(Ordering::SeqCst));
    assert_eq!(fs::read_to_string(&fx.vault.path).unwrap(), planted);
    assert!(fx.versions().is_empty());
}

#[test]
fn unsigned_file_refused_and_not_modified() {
    let fx = Fixture::new();
    let before = fs::read_to_string(&fx.vault.path).unwrap();
    let mut fields: BTreeMap<String, Box<RawValue>> = serde_json::from_str(&before).unwrap();
    fields.remove("signature").unwrap();
    let unsigned = serde_json::to_string_pretty(&fields).unwrap();
    fs::write(&fx.vault.path, &unsigned).unwrap();

    let result = fx.files.write::<_, Error>(&fx.target(), fx.unlock(), |vw| {
        add_credential(vw, "alpha", "one")
    });

    assert!(matches!(result, Err(Error::VaultSignatureMissing)));
    assert_eq!(fs::read_to_string(&fx.vault.path).unwrap(), unsigned);
    assert!(fx.versions().is_empty());
}

#[test]
fn file_signed_by_another_key_refused_and_not_modified() {
    let fx = Fixture::new();
    let other_mac =
        VaultWriter::isolated_with_signer(fx.dir.path().join("other"), TestSigner::random());
    let vh = VaultHandle::new_for_test_at(fx.dir.path().join("vaults").join("other.json"));
    other_mac.create(&vh).unwrap();
    let before = fs::read_to_string(&vh.path).unwrap();

    let result = fx
        .files
        .write_unlocked::<_, Error>(&vh, |vw| add_credential(vw, "alpha", "one"));

    assert!(matches!(result, Err(Error::VaultSignatureInvalid)));
    assert_eq!(fs::read_to_string(&vh.path).unwrap(), before);
    let id = vh.vault_id().unwrap();
    assert!(fx.files.list_versions(id).unwrap().is_empty());
}

#[test]
fn retained_version_whose_signature_fails_not_restored() {
    let fx = Fixture::new();
    fx.add(&fx.target(), "alpha", "one");
    fx.add(&fx.target(), "alpha", "two");
    let versions = fx.versions();
    let name = &versions[0].name;
    let path = fx.files.versions(fx.id()).file(name);
    let version = fs::read_to_string(&path).unwrap();
    let forged = EncryptedVault::sign_vault_json(raw(&version), &TestSigner::random()).unwrap();
    fs::write(&path, forged).unwrap();
    let before = fs::read_to_string(&fx.vault.path).unwrap();

    let result = fx.files.restore_version(&fx.target(), fx.unlock(), name);

    assert!(matches!(result, Err(Error::VaultSignatureInvalid)));
    assert_eq!(fs::read_to_string(&fx.vault.path).unwrap(), before);
    assert_eq!(fx.value(&fx.vault.path, "alpha").as_deref(), Some("two"));
    assert_eq!(fx.versions().len(), 2);
}

#[test]
fn creating_vault_writes_once_and_retains_nothing() {
    let fx = Fixture::new();
    assert!(fx.vault.path.exists());
    assert!(fx.versions().is_empty());
    let entry = fx.files.locks().entry(fx.id(), &fx.vault.path);
    assert_eq!(entry.save_count(), 1);
}

#[test]
fn creating_vault_over_existing_file_fails() {
    let fx = Fixture::new();
    let other = VaultHandle::new_for_test_at(fx.vault.path.clone());
    assert!(matches!(
        fx.files.create(&other),
        Err(Error::DuplicateVaultId(_))
    ));
    assert_eq!(VaultHeader::peek(&fx.vault.path).unwrap().id, fx.id());
}

#[test]
fn write_saves_and_retains_replaced_file() {
    let fx = Fixture::new();
    let before = fs::read_to_string(&fx.vault.path).unwrap();

    let committed = fx.add(&fx.target(), "alpha", "one");

    assert!(committed.changed);
    assert_eq!(fx.value(&fx.vault.path, "alpha").as_deref(), Some("one"));
    let versions = fx.versions();
    assert_eq!(versions.len(), 1);
    let retained = fs::read_to_string(fx.files.versions(fx.id()).file(&versions[0].name)).unwrap();
    assert_eq!(retained, before);
}

/// Vault with entries of every kind, created at `vaults/personal.json` in
/// `dir`.
fn filled_vault(dir: &TempDir, files: &VaultWriter) -> VaultHandle {
    let mut vault = Vault::new_for_test();
    vault.fill_for_test();
    let path = dir.path().join("vaults").join("personal.json");
    let vh = VaultHandle::unlocked(path, vault);
    files.create(&vh).unwrap();
    vh
}

#[test]
fn vault_with_every_entry_kind_saved_and_reloaded() {
    let dir = tempfile::tempdir().unwrap();
    let files = VaultWriter::isolated(dir.path().join("data"));
    let vh = filled_vault(&dir, &files);

    files
        .write_unlocked::<_, Error>(&vh, |vw| vw.add_item("new", "New").map(|_| ()))
        .unwrap();

    let json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&vh.path).unwrap()).unwrap();
    assert_eq!(json["format"], serde_json::json!(VAULT_FORMAT));
    let enc_vault = EncryptedVault::load(&vh.path, files.signer().as_ref()).unwrap();
    let vault = Vault::from_unlocked_key(&vh.unlocked_key().unwrap(), enc_vault).unwrap();
    vault.assert_filled_for_test();
    assert!(vault.get_item("new").is_ok());
}

#[test]
fn unchanged_vault_with_every_entry_kind_saves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let files = VaultWriter::isolated(dir.path().join("data"));
    let vh = filled_vault(&dir, &files);
    // Each signature differs, so equal bytes show that nothing was saved.
    let signer = files.signer().as_ref();
    assert_ne!(
        vh.file_contents(signer).unwrap(),
        vh.file_contents(signer).unwrap()
    );
    let before = fs::read_to_string(&vh.path).unwrap();

    let committed = files
        .write_unlocked::<_, Error>(&vh, |vw| vw.list_items().map(|_| ()))
        .unwrap();

    assert!(!committed.changed);
    assert_eq!(fs::read_to_string(&vh.path).unwrap(), before);
    assert!(
        files
            .list_versions(vh.vault_id().unwrap())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn rekeyed_copy_saves_beside_source_and_reloads_verified() {
    let dir = tempfile::tempdir().unwrap();
    let files = VaultWriter::isolated(dir.path().join("data"));
    let source = filled_vault(&dir, &files);
    let source_vault = {
        let enc_vault = EncryptedVault::load(&source.path, files.signer().as_ref()).unwrap();
        Vault::from_unlocked_key(&source.unlocked_key().unwrap(), enc_vault).unwrap()
    };
    let source_before = fs::read_to_string(&source.path).unwrap();

    let new_id = Uuid::new_v4();
    let mut copy = source_vault
        .rekeyed(Some(new_id), |raw| Ok(VaultFileKey::new(raw.to_vec())))
        .unwrap();
    copy.set_key("copy".to_string());
    let path = VaultHandle::file_path(&dir.path().join("vaults"), new_id);
    let vh = VaultHandle::unlocked(path.clone(), copy);
    files.create(&vh).unwrap();

    let enc_vault = EncryptedVault::load(&path, files.signer().as_ref()).unwrap();
    let reloaded = Vault::from_unlocked_key(&vh.unlocked_key().unwrap(), enc_vault).unwrap();
    assert_eq!(reloaded.id(), new_id);
    assert_eq!(reloaded.key(), "copy");
    reloaded.assert_filled_for_test();
    assert_eq!(
        reloaded.entry_ids_for_test(),
        source_vault.entry_ids_for_test()
    );

    // The source file is unchanged and still opens with its own key.
    assert_eq!(fs::read_to_string(&source.path).unwrap(), source_before);
    let enc_vault = EncryptedVault::load(&source.path, files.signer().as_ref()).unwrap();
    let source_reloaded =
        Vault::from_unlocked_key(&source.unlocked_key().unwrap(), enc_vault).unwrap();
    source_reloaded.assert_filled_for_test();
    let enc_vault = EncryptedVault::load(&path, files.signer().as_ref()).unwrap();
    assert!(matches!(
        Vault::from_unlocked_key(&source.unlocked_key().unwrap(), enc_vault),
        Err(Error::VaultFileKeyChanged)
    ));
}

#[test]
fn vault_with_hyphenated_ids_loads_and_next_save_writes_short_ids() {
    let dir = tempfile::tempdir().unwrap();
    let files = VaultWriter::isolated(dir.path().join("data"));
    let vh = filled_vault(&dir, &files);
    let id = vh.vault_id().unwrap();
    let short = fs::read_to_string(&vh.path).unwrap();
    let hyphenated = EncryptedVault::hyphenate_ids_for_test(&short, files.signer().as_ref());
    fs::write(&vh.path, &hyphenated).unwrap();

    assert_eq!(VaultHeader::peek(&vh.path).unwrap().id, id);
    let committed = files
        .write_unlocked::<_, Error>(&vh, |vw| vw.list_items().map(|_| ()))
        .unwrap();

    // The raw vault bytes differ from the saved form, so the save rewrites
    // them. The new signature differs from the first one.
    assert!(committed.changed);
    let saved = fs::read_to_string(&vh.path).unwrap();
    assert_eq!(raw(&saved), raw(&short));
    assert!(EncryptedVault::assert_short_ids_for_test(&saved) > 0);
    let enc_vault = EncryptedVault::load(&vh.path, files.signer().as_ref()).unwrap();
    let vault = Vault::from_unlocked_key(&vh.unlocked_key().unwrap(), enc_vault).unwrap();
    vault.assert_filled_for_test();

    // The replaced file is retained unchanged, in a directory named by the
    // short id.
    let versions = files.list_versions(id).unwrap();
    assert_eq!(versions.len(), 1);
    let short_id = ShortId::encode_uuid(id);
    let retained = dir
        .path()
        .join("data")
        .join("versions")
        .join(&short_id)
        .join(&versions[0].name);
    assert_eq!(fs::read_to_string(retained).unwrap(), hyphenated);
    let lock = dir
        .path()
        .join("data")
        .join("locks")
        .join(format!("{short_id}.lock"));
    assert!(lock.exists());
}

#[test]
fn failed_change_writes_nothing() {
    let fx = Fixture::new();
    let before = fs::read_to_string(&fx.vault.path).unwrap();
    let result = fx
        .files
        .write::<(), Error>(&fx.target(), fx.unlock(), |vw| {
            vw.add_item("item", "Item")?;
            Err(Error::InvalidItemKey("refused".to_string()))
        });
    assert!(result.is_err());
    assert_eq!(fs::read_to_string(&fx.vault.path).unwrap(), before);
}
