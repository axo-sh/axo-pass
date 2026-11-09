use super::*;

#[test]
fn import_of_held_or_leaving_vault_refused() {
    let transport = Arc::new(FakeTransport::default());
    let a = Fixture::with_transport(0, None, transport.clone());
    let setup = enable(&a, root());

    // A vault file of the id makes the join an `Existing` one.
    let b = Mac::new(transport.clone());
    b.copy_of(&a);
    let join = recovered(&setup, &*transport);
    assert!(matches!(
        b.join(&join, JoinInto::New, MAC_B, &file_key(a.id(), 2)),
        Err(Error::VaultIdExists(_))
    ));
    assert_eq!(b.sync_files(a.id()), [false; 3]);

    let b = Mac::new(transport.clone());
    let mut leaving = state(a.id(), REPLICA, GENERATION);
    leaving.leaving = true;
    leaving.save(&b.root, &TestSigner::device()).unwrap();
    let writes = transport.writes();
    assert!(matches!(
        b.join(&join, JoinInto::New, MAC_B, &file_key(a.id(), 2)),
        Err(Error::SyncDisableInProgress)
    ));
    assert!(!VaultHandle::file_path(&b.vaults_dir, a.id()).exists());
    assert_eq!(b.sync_files(a.id()), [true, false, false]);
    assert_eq!(transport.writes(), writes);
}

#[test]
fn import_builds_vault_as_view_with_new_file_key_and_vault_key_from_view_name_made_unique() {
    let transport = Arc::new(FakeTransport::default());
    let a = Fixture::with_transport(0, None, transport.clone());
    a.write(|vh| {
        vh.get_unlocked_vault_mut()?.name = Some("Family".to_string());
        vh.add_item("item", "Item").map(|_| ())
    })
    .unwrap();
    let setup = enable(&a, root());
    // Mac B holds another vault with the key of the view name.
    let b = Mac::new(transport.clone());
    let other = Vault::with_unlocked_key("family".to_string(), &file_key(Uuid::new_v4(), 3));
    b.catalog
        .files()
        .create(&VaultHandle::new_in(&b.vaults_dir, other))
        .unwrap();

    let join = recovered(&setup, &*transport);
    let today = || Zoned::now().date().strftime("%Y%m%d").to_string();
    let day_before = today();
    let committed = b
        .join(&join, JoinInto::New, MAC_B, &file_key(a.id(), 2))
        .unwrap();

    let keys = [day_before, today()].map(|date| format!("family-{date}-1"));
    assert!(
        keys.contains(&committed.vault.key),
        "{}",
        committed.vault.key
    );
    assert_eq!(
        committed.vault.path,
        VaultHandle::file_path(&b.vaults_dir, a.id())
    );
    assert!(committed.changed);
    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    let (local, state) = opened(&b.root, a.id());
    let vault = b.saved(&committed.vault);
    assert_eq!(local.generation, 1);
    assert_eq!(vault.generation(), 1);
    assert_eq!(vault.replica_id(), Some(join.replica_id().0));
    assert_eq!(vault.name.as_deref(), Some("Family"));
    assert_eq!(vault.get_item("item").unwrap().title, "Item");
    assert!(
        LocalEdits::find(&state, &vault, join.replica_id())
            .unwrap()
            .is_empty()
    );
    // The vault file is under the new file key of Mac B, not that of Mac A.
    let file = EncryptedVault::load(&committed.vault.path, &TestSigner::device()).unwrap();
    assert!(matches!(
        Vault::from_unlocked_key(&a.vault.unlocked_key().unwrap(), file),
        Err(Error::VaultFileKeyChanged)
    ));
    assert!(b.catalog.list().contains_key(&committed.vault.key));
}
