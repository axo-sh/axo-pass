use super::*;

#[test]
fn joining_folder_from_vault_imported_from_export_adds_local_entries_and_shows_title_as_conflict() {
    let transport = Arc::new(FakeTransport::default());
    let a = Fixture::with_transport(0, None, transport.clone());
    a.write(|vh| {
        vh.add_item("shared", "Shared")?;
        vh.add_item("kept", "Kept").map(|_| ())
    })
    .unwrap();
    // Both Macs import one export.
    let b = Mac::new(transport.clone());
    let b_vault = b.copy_of(&a);
    let setup = enable(&a, root());
    // Mac B edits a title and adds an item, then joins with the kit of A.
    b.write(&b_vault, |vh| {
        vh.add_item("shared", "Home")?;
        vh.add_item("local", "Local").map(|_| ())
    })
    .unwrap();
    let join = recovered(&setup, &*transport);
    let committed = b
        .join(
            &join,
            JoinInto::Existing(Target::of(&b_vault)),
            MAC_B,
            &b_vault.unlocked_key().unwrap(),
        )
        .unwrap();

    assert!(committed.changed);
    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    assert!(committed.value.is_empty());
    let (local, state) = opened(&b.root, a.id());
    assert_eq!(local.replica_id, join.replica_id());
    let vault = b.saved(&b_vault);
    let shared = vault.get_item("shared").unwrap().id;
    let view = VaultView::of(&state);
    // The differing title is a conflict. The joined value is shown, and the
    // local value is kept in the register.
    assert_eq!(view.conflicts(), [title_conflict(shared)]);
    assert_eq!(
        titles(&state, shared),
        BTreeSet::from(["Home".to_string(), "Shared".to_string()])
    );
    assert_eq!(vault.get_item("shared").unwrap().title, "Shared");
    // No local entry is lost.
    for key in ["kept", "local"] {
        assert!(vault.get_item(key).is_ok(), "{key}");
    }
    assert!(
        LocalEdits::find(&state, &vault, join.replica_id())
            .unwrap()
            .is_empty()
    );

    // Mac A joins the published state of Mac B.
    a.write(|_| Ok(())).unwrap();
    let (_, a_state) = opened(&a.root, a.id());
    assert_eq!(VaultView::of(&a_state), view);
    assert!(saved_vault(&a).get_item("local").is_ok());
}

#[test]
fn relink_after_bad_signature_shows_edits_as_conflicts() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    put_meta(&transport, &fx);
    fx.write(|vh| vh.add_item("item", "Item").map(|_| ()))
        .unwrap();
    // The sync state fails its signature, and edits are saved while sync is
    // stopped.
    let (local, _) = saved(&fx);
    fx.put(&local, &TestSigner::random());
    assert!(matches!(fx.write_case(), SyncLoad::SignatureFailed(_)));
    fx.write(|vh| {
        vh.add_item("item", "Local")?;
        vh.add_item("added", "Added").map(|_| ())
    })
    .unwrap();
    let v = saved_vault(&fx).generation();

    let join = relink_key(&fx);
    let committed = join_fx(&fx, &join).unwrap();

    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    let (local, state) = saved(&fx);
    assert_eq!(local.replica_id, join.replica_id());
    assert_ne!(local.replica_id, REPLICA);
    assert_eq!(local.generation, v + 1);
    let vault = saved_vault(&fx);
    assert_eq!(vault.generation(), v + 1);
    assert_eq!(vault.replica_id(), Some(join.replica_id().0));
    // The published title of the old replica is shown, and the edit saved
    // while stopped is a conflict.
    let item = vault.get_item("item").unwrap().id;
    assert_eq!(VaultView::of(&state).conflicts(), [title_conflict(item)]);
    assert_eq!(
        titles(&state, item),
        BTreeSet::from(["Item".to_string(), "Local".to_string()])
    );
    assert_eq!(vault.get_item("item").unwrap().title, "Item");
    assert!(vault.get_item("added").is_ok());
    assert_eq!(fx.read_case(), SyncLoad::Current);
}

#[test]
fn relink_of_vault_whose_sync_state_is_missing_takes_new_replica_id_and_merges() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    put_meta(&transport, &fx);
    fx.add_item().unwrap();
    fs::remove_file(fx.state_path()).unwrap();
    assert_eq!(fx.write_case(), SyncLoad::StateMissing);
    fx.write(|vh| vh.add_item("item", "Local").map(|_| ()))
        .unwrap();

    let join = relink_key(&fx);
    join_fx(&fx, &join).unwrap();

    let (local, state) = saved(&fx);
    assert_eq!(local.replica_id, join.replica_id());
    assert_ne!(local.replica_id, REPLICA);
    // The files of the old replica are joined as those of a peer.
    assert_eq!(
        local.pinned_keys.get(&REPLICA).map(|pin| pin.source),
        Some(PinSource::FirstUse)
    );
    let vault = saved_vault(&fx);
    let item = vault.get_item("item").unwrap().id;
    assert_eq!(VaultView::of(&state).conflicts(), [title_conflict(item)]);
    assert_eq!(vault.replica_id(), Some(join.replica_id().0));
    assert_eq!(fx.read_case(), SyncLoad::Current);
}

#[test]
fn join_of_vault_whose_sync_runs_stopped_or_is_leaving_refused_and_writes_nothing() {
    let transport = Arc::new(FakeTransport::default());

    let fx = synced(&transport);
    fx.add_item().unwrap();
    put_meta(&transport, &fx);
    assert_join_refused(&fx, &transport, |e| matches!(e, Error::SyncAlreadyEnabled));

    let fx = Fixture::with_transport(GENERATION, Some(REPLICA), transport.clone());
    let mut stopped = state(fx.id(), REPLICA, GENERATION);
    stopped.stopped_build = Some(BUILD_ID.to_string());
    fx.put(&stopped, &TestSigner::device());
    put_meta(&transport, &fx);
    assert_join_refused(&fx, &transport, |e| matches!(e, Error::SyncAlreadyEnabled));

    // A `leaving` sync state, with or without the replica id in the vault.
    for replica in [Some(REPLICA), None] {
        let generation = replica.map_or(0, |_| GENERATION);
        let fx = Fixture::with_transport(generation, replica, transport.clone());
        let mut leaving = state(fx.id(), REPLICA, GENERATION);
        leaving.leaving = true;
        fx.put(&leaving, &TestSigner::device());
        put_meta(&transport, &fx);
        assert_join_refused(&fx, &transport, |e| {
            matches!(e, Error::SyncDisableInProgress)
        });
    }
}
