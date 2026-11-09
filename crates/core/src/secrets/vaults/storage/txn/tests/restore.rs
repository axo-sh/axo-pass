use super::*;

#[test]
fn restoring_version_replaces_vault_and_retains_replaced_file() {
    let fx = Fixture::new();
    fx.add(&fx.target(), "alpha", "one");
    fx.add(&fx.target(), "alpha", "two");
    let before_restore = fs::read_to_string(&fx.vault.path).unwrap();
    // Newest first: the version before "two" holds "one".
    let versions = fx.versions();
    assert_eq!(versions.len(), 2);

    let committed = fx
        .files
        .restore_version(&fx.target(), fx.unlock(), &versions[0].name)
        .unwrap();

    assert!(committed.changed);
    assert_eq!(fx.value(&fx.vault.path, "alpha").as_deref(), Some("one"));
    let after = fx.versions();
    assert_eq!(after.len(), 3);
    let retained = fs::read_to_string(fx.files.versions(fx.id()).file(&after[0].name)).unwrap();
    assert_eq!(retained, before_restore);
}

#[test]
fn restoring_missing_version_fails() {
    let fx = Fixture::new();
    for name in ["1-0.json", "../personal.json", "nonsense"] {
        assert!(matches!(
            fx.files.restore_version(&fx.target(), fx.unlock(), name),
            Err(Error::VaultVersionNotFound(_))
        ));
    }
}

#[test]
fn restoring_version_with_another_file_key_fails() {
    let fx = Fixture::new();
    let signer = fx.files.signer().as_ref();
    let mut enc_vault = EncryptedVault::load(&fx.vault.path, signer)
        .unwrap()
        .into_inner();
    enc_vault.file_key = VaultFileKey::new(vec![1u8; 32]);
    let dir = fx.files.versions(fx.id());
    fs::create_dir_all(&dir.path).unwrap();
    fs::write(
        dir.file("1-0.json"),
        enc_vault.to_file_contents(signer).unwrap(),
    )
    .unwrap();

    assert!(matches!(
        fx.files
            .restore_version(&fx.target(), fx.unlock(), "1-0.json"),
        Err(Error::VaultVersionKeyChanged(_))
    ));
}

#[test]
fn restore_over_refused_file_keeps_bytes() {
    let fx = Fixture::new();
    fx.add(&fx.target(), "alpha", "one");
    fx.add(&fx.target(), "alpha", "two");
    let versions = fx.versions();
    let refused = refuse(&fx.vault.path);
    assert!(matches!(
        fx.files
            .write::<_, Error>(&fx.target(), fx.unlock(), |_| Ok(())),
        Err(Error::VaultSignatureInvalid)
    ));

    let committed = fx
        .files
        .restore_refused(&fx.target(), fx.unlock(), &versions[0].name)
        .unwrap();

    assert!(committed.changed);
    assert_eq!(fx.value(&fx.vault.path, "alpha").as_deref(), Some("one"));
    let invalid = fx.files.list_invalid(fx.id());
    assert_eq!(invalid.len(), 1);
    assert!(invalid[0].ends_with(".invalid.json"), "{}", invalid[0]);
    let kept = fs::read_to_string(fx.files.versions(fx.id()).file(&invalid[0])).unwrap();
    assert_eq!(kept, refused);
    // The invalid file is not listed or restored as a version.
    assert_eq!(fx.versions(), versions);
    assert!(matches!(
        fx.files
            .restore_version(&fx.target(), fx.unlock(), &invalid[0]),
        Err(Error::VaultVersionNotFound(_))
    ));
}

#[test]
fn restore_over_refused_file_refuses_file_that_verifies() {
    let fx = Fixture::new();
    fx.add(&fx.target(), "alpha", "one");
    let versions = fx.versions();
    let before = fs::read_to_string(&fx.vault.path).unwrap();

    let result = fx
        .files
        .restore_refused(&fx.target(), fx.unlock(), &versions[0].name);

    assert!(matches!(result, Err(Error::VaultNotRefused(_))));
    assert_eq!(fs::read_to_string(&fx.vault.path).unwrap(), before);
    assert!(fx.files.list_invalid(fx.id()).is_empty());
}

#[test]
fn failed_unlock_or_forged_version_writes_no_invalid_file() {
    let fx = Fixture::new();
    fx.add(&fx.target(), "alpha", "one");
    fx.add(&fx.target(), "alpha", "two");
    let versions = fx.versions();
    let forged_name = &versions[0].name;
    let path = fx.files.versions(fx.id()).file(forged_name);
    let version = fs::read_to_string(&path).unwrap();
    let forged = EncryptedVault::sign_vault_json(raw(&version), &TestSigner::random()).unwrap();
    fs::write(&path, forged).unwrap();
    let refused = refuse(&fx.vault.path);
    let id = fx.id();
    let wrong_key =
        || UnlockedKey::for_test(VaultFileKey::new(vec![9u8; 32]), VaultCipher::new(id));

    let forged = fx
        .files
        .restore_refused(&fx.target(), fx.unlock(), forged_name);
    let missing = fx
        .files
        .restore_refused(&fx.target(), fx.unlock(), "1-0.json");
    let wrong = fx
        .files
        .restore_refused(&fx.target(), Unlock::Test(&wrong_key), &versions[1].name);

    assert!(matches!(forged, Err(Error::VaultSignatureInvalid)));
    assert!(matches!(missing, Err(Error::VaultVersionNotFound(_))));
    assert!(matches!(wrong, Err(Error::VaultVersionKeyChanged(_))));
    assert_eq!(fs::read_to_string(&fx.vault.path).unwrap(), refused);
    assert!(fx.files.list_invalid(fx.id()).is_empty());
}
