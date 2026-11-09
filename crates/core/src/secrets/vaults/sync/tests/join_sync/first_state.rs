use super::*;

#[test]
fn first_state_of_join_holds_own_name_and_keys_and_pins_paired_mac_and_other_peers_at_first_use() {
    let transport = Arc::new(FakeTransport::default());
    let a = Fixture::with_transport(0, None, transport.clone());
    let setup = enable(&a, root());
    let c = Mac::new(transport.clone());
    let c_join = recovered(&setup, &*transport);
    c.join(&c_join, JoinInto::New, MAC_C, &file_key(a.id(), 3))
        .unwrap();
    // Mac B pairs with Mac A. Every Mac has the test keys.
    let keys = ReplicaKeys {
        encryption: TestKeyWrapper::public_key(),
        signing: PublicKey(device_key()),
    };
    let paired = PairedVault {
        vault_id: a.id(),
        replica_id: ReplicaId::generate(),
        key_id: KeyId(1),
        key: setup.key().clone(),
        peer: setup.replica_id(),
        pin: PinnedKeys {
            source: PinSource::Pairing,
            encryption: keys.encryption.clone(),
            signing: keys.signing.clone(),
            revoked: false,
        },
    };
    let join = JoinKey::paired(paired);
    let b = Mac::new(transport.clone());
    b.join(&join, JoinInto::New, MAC_B, &file_key(a.id(), 2))
        .unwrap();

    let (local, state) = opened(&b.root, a.id());
    let own = join.replica_id();
    assert_eq!(
        state.store.replica_names.get(&own).unwrap().shown(),
        Some(&MAC_B.to_string())
    );
    assert_eq!(
        state.store.replica_keys.get(&own).unwrap().shown(),
        Some(&keys)
    );
    // A new vault adds no difference, so the own registers are the one
    // write of the one actor of Mac B.
    let actors: Vec<_> = state
        .actors
        .iter()
        .filter(|(_, info)| info.replica == own)
        .map(|(actor, _)| *actor)
        .collect();
    assert_eq!(actors.len(), 1);
    assert_eq!(state.context.get(actors[0]), 1);
    assert_eq!(
        local
            .pinned_keys
            .get(&setup.replica_id())
            .map(|pin| pin.source),
        Some(PinSource::Pairing)
    );
    assert_eq!(
        local
            .pinned_keys
            .get(&c_join.replica_id())
            .map(|pin| pin.source),
        Some(PinSource::FirstUse)
    );
    assert_eq!(local.pinned_keys.len(), 2);
}

#[test]
fn next_transaction_after_join_finds_no_drift_and_publishes_nothing_and_macs_converge() {
    let transport = Arc::new(FakeTransport::default());
    let a = Fixture::with_transport(0, None, transport.clone());
    a.write(|vh| vh.add_item("item", "Item").map(|_| ()))
        .unwrap();
    let setup = enable(&a, root());
    let b = Mac::new(transport.clone());
    let join = recovered(&setup, &*transport);
    let b_vault = b
        .join(&join, JoinInto::New, MAC_B, &file_key(a.id(), 2))
        .unwrap()
        .vault;
    let writes = transport.writes();
    let (_, before) = opened(&b.root, a.id());

    let committed = b.write(&b_vault, |_| Ok(())).unwrap();

    assert!(!committed.changed);
    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    assert_eq!(transport.writes(), writes);
    let (local, state) = opened(&b.root, a.id());
    assert_eq!(state, before);
    assert_eq!(local.stopped_build, None);

    // An edit on Mac B reaches Mac A, and both Macs hold one view.
    b.write(&b_vault, |vh| vh.add_item("home", "Home").map(|_| ()))
        .unwrap();
    a.write(|_| Ok(())).unwrap();
    b.write(&b_vault, |_| Ok(())).unwrap();
    let (_, a_state) = opened(&a.root, a.id());
    let (_, b_state) = opened(&b.root, a.id());
    assert_eq!(VaultView::of(&a_state), VaultView::of(&b_state));
    assert!(saved_vault(&a).get_item("home").is_ok());
    assert!(b.saved(&b_vault).get_item("item").is_ok());
    assert_eq!(a.write_case(), SyncLoad::Current);
}

#[test]
fn peer_file_that_is_remote_at_join_requested_and_joined_by_later_transaction() {
    let transport = Arc::new(FakeTransport::default());
    let a = Fixture::with_transport(0, None, transport.clone());
    a.write(|vh| vh.add_item("item", "Item").map(|_| ()))
        .unwrap();
    let setup = enable(&a, root());
    let join = recovered(&setup, &*transport);
    // The state file of Mac A is not local on Mac B yet.
    let published = Sidecar::load(&a.root, a.id()).last_publish.unwrap();
    let a_replica = setup.replica_id();
    let ReadResult::Local(bytes) = transport
        .read(a.id(), a_replica, FileName::State(published))
        .unwrap()
    else {
        panic!("published state file is not local");
    };
    transport.put_remote_with(
        a.id(),
        a_replica,
        &StateFile::name(a.id(), published),
        &bytes,
    );
    let b = Mac::new(transport.clone());

    let committed = b
        .join(&join, JoinInto::New, MAC_B, &file_key(a.id(), 2))
        .unwrap();

    let b_vault = committed.vault;
    assert!(b.saved(&b_vault).get_item("item").is_err());
    assert_eq!(transport.download_requests(), [a.id()]);

    assert_eq!(transport.complete_downloads(a.id()), 1);
    let committed = b.write(&b_vault, |_| Ok(())).unwrap();
    assert!(committed.changed);
    assert!(b.saved(&b_vault).get_item("item").is_ok());
}

#[test]
fn folder_with_no_meta_json_for_vault_or_newer_one_fails_join() {
    let transport = Arc::new(FakeTransport::default());
    let b = Mac::new(transport.clone());
    let vault_id = Uuid::new_v4();
    let join = JoinKey::recovered(RecoveredKey {
        vault_id,
        key_id: KeyId(1),
        key: key(),
        replica_id: ReplicaId::generate(),
    });

    assert!(matches!(
        b.join(&join, JoinInto::New, MAC_B, &file_key(vault_id, 2)),
        Err(Error::SyncFolderLacksVault)
    ));
    let newer = format!(r#"{{"format_version":2,"vault_id":"{vault_id}"}}"#);
    transport.put_meta(vault_id, newer.as_bytes());
    assert!(matches!(
        b.join(&join, JoinInto::New, MAC_B, &file_key(vault_id, 2)),
        Err(Error::SyncMetaFileError(MetaFileError::VersionSkew(_)))
    ));
    assert_eq!(b.sync_files(vault_id), [false; 3]);
    assert!(!VaultHandle::file_path(&b.vaults_dir, vault_id).exists());
    assert_eq!(transport.writes(), 0);

    // A local vault of the id is not joined either.
    let fx = Fixture::with_transport(0, None, transport.clone());
    let on_disk = fx.on_disk();
    assert!(matches!(
        join_fx(&fx, &relink_key(&fx)),
        Err(Error::SyncFolderLacksVault)
    ));
    assert_eq!(fx.on_disk(), on_disk);
    assert_eq!(transport.writes(), 0);
}

#[test]
fn join_through_folder_transport_with_plain_io_writes_own_state_file_and_key_json() {
    let folder = Folder::new();
    let a = Fixture::with_transport(0, None, folder.transport.clone());
    a.write(|vh| vh.add_item("item", "Item").map(|_| ()))
        .unwrap();
    let setup = enable(&a, folder.transport_root());
    let join = recovered(&setup, &*folder.transport);
    let b = Mac::new(folder.transport.clone());
    let b_key = file_key(a.id(), 2);
    let key = || b_key.duplicate_for_test();

    let committed = b
        .catalog
        .join_sync(
            &join,
            JoinInto::New,
            &folder.transport_root(),
            MAC_B,
            Unlock::Test(&key),
        )
        .unwrap();

    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    let sidecar = Sidecar::load(&b.root, a.id());
    assert_eq!(sidecar.transport, Some(folder.transport_root()));
    let replica_dir = folder
        .root
        .join(ShortId::encode_uuid(a.id()))
        .join(ShortId::encode_uuid(join.replica_id().0));
    let mut names = vec![
        StateFile::name(a.id(), sidecar.last_publish.unwrap()),
        "key.json".to_string(),
    ];
    names.sort();
    assert_eq!(Folder::names(&replica_dir), names);
    assert!(b.saved(&committed.vault).get_item("item").is_ok());

    // Mac A joins the state of Mac B.
    a.write(|_| Ok(())).unwrap();
    let (_, a_state) = opened(&a.root, a.id());
    assert_eq!(
        a_state
            .store
            .replica_names
            .get(&join.replica_id())
            .unwrap()
            .shown(),
        Some(&MAC_B.to_string())
    );
}

#[test]
fn conflict_copy_of_meta_json_not_read_at_import() {
    let folder = Folder::new();
    let vault_id = Uuid::new_v4();
    let vault_dir = folder.root.join(ShortId::encode_uuid(vault_id));
    fs::create_dir(&vault_dir).unwrap();
    fs::write(
        vault_dir.join("meta 2.json"),
        MetaFile::new(vault_id).to_bytes(),
    )
    .unwrap();
    let b = Mac::new(folder.transport.clone());
    let join = JoinKey::recovered(RecoveredKey {
        vault_id,
        key_id: KeyId(1),
        key: key(),
        replica_id: ReplicaId::generate(),
    });

    assert!(matches!(
        b.join(&join, JoinInto::New, MAC_B, &file_key(vault_id, 2)),
        Err(Error::SyncFolderLacksVault)
    ));
    assert_eq!(Folder::names(&vault_dir), ["meta 2.json"]);
    assert_eq!(b.sync_files(vault_id), [false; 3]);
    assert!(!VaultHandle::file_path(&b.vaults_dir, vault_id).exists());
}
