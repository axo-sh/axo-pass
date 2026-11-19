use super::*;

#[test]
fn symlink_not_read_and_no_write_or_delete_reaches_its_target() {
    for folder in Folder::each() {
        let transport = &folder.transport;
        let outside = folder.dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let secret = outside.join("secret");
        fs::write(&secret, b"secret").unwrap();
        let own = folder.replica_dir(VAULT, WRITER);
        fs::create_dir_all(&own).unwrap();
        symlink(&secret, own.join("key.json")).unwrap();
        symlink(&secret, folder.vault_dir(VAULT).join("meta.json")).unwrap();
        let peer = ReplicaId(Uuid::from_u128(2));
        symlink(&outside, folder.replica_dir(VAULT, peer)).unwrap();

        assert_eq!(
            transport.read(VAULT, WRITER, FileName::Key).unwrap(),
            ReadResult::Missing
        );
        assert_eq!(transport.read_meta(VAULT).unwrap(), ReadResult::Missing);
        assert_eq!(transport.list_replicas(VAULT).unwrap(), vec![WRITER]);
        assert!(
            transport
                .write_own(VAULT, WRITER, FileName::Key, b"key")
                .is_err()
        );
        assert!(transport.write_meta(VAULT, b"meta").is_err());
        let state = FileName::State(StateHash::of(b"state"));
        assert!(transport.write_own(VAULT, peer, state, b"state").is_err());

        transport.delete_own(VAULT, WRITER, FileName::Key).unwrap();
        transport.delete_replica(VAULT, peer).unwrap();
        assert_eq!(fs::read(&secret).unwrap(), b"secret");
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 1);
        assert!(!own.join("key.json").exists());
        assert!(!folder.replica_dir(VAULT, peer).exists());
    }
}

#[test]
fn app_transports_resolve_folder_root_once_and_refuse_missing_folder_and_icloud() {
    let dir = tempfile::tempdir().unwrap();
    let transports = AppTransports::default();
    let root = TransportRoot::Folder {
        path: dir.path().to_path_buf(),
    };
    let first = transports.resolve(Some(&root)).unwrap().unwrap();
    let second = transports.resolve(Some(&root)).unwrap().unwrap();
    assert!(Arc::ptr_eq(&first, &second));

    let path = dir.path().join("Missing");
    let missing = TransportRoot::Folder { path: path.clone() };
    assert!(matches!(
        transports.resolve(Some(&missing)),
        Err(Error::SyncTransportError(_))
    ));
    // A root that failed is resolved again.
    fs::create_dir(&path).unwrap();
    assert!(transports.resolve(Some(&missing)).unwrap().is_some());

    assert!(matches!(
        transports.resolve(Some(&TransportRoot::ICloud {})),
        Err(Error::SyncTransportError(_))
    ));
}

// The transactions below resolve the folder with `AppTransports`, which uses
// `CoordinatedIo`. They run on macOS only until the Linux `CoordinatedIo`
// exists.

/// Synced vault with a valid sync state, whose sidecar holds the root of a
/// folder in a temp directory. The writer of the fixture resolves the root
/// with `AppTransports`, so the transport is a `FolderTransport` with
/// `CoordinatedIo`.
fn synced_in_folder() -> (Fixture, TempDir, PathBuf) {
    let fx = Fixture::synced();
    fx.put_state(GENERATION);
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("Vaults");
    fs::create_dir(&root).unwrap();
    let sidecar = Sidecar {
        transport: Some(TransportRoot::Folder { path: root.clone() }),
        ..Sidecar::default()
    };
    sidecar.save(&fx.root, fx.id()).unwrap();
    (fx, dir, root)
}

/// Own state files of `fx` in the folder `root`, in order.
fn published(root: &Path, fx: &Fixture) -> Vec<StateHash> {
    let dir = root
        .join(ShortId::encode_uuid(fx.id()))
        .join(ShortId::encode_uuid(REPLICA.0));
    let mut hashes: Vec<StateHash> = fs::read_dir(dir)
        .unwrap()
        .filter_map(|entry| {
            let name = entry.unwrap().file_name().into_string().unwrap();
            FileName::parse_state(fx.id(), &name)
        })
        .collect();
    hashes.sort();
    hashes
}

fn staged_bytes(fx: &Fixture) -> Vec<u8> {
    fs::read(LocalSyncState::staged_path(&fx.root, fx.id())).unwrap()
}

#[cfg(target_os = "macos")]
#[test]
fn transaction_through_folder_transport_copies_staged_file_and_next_moves_staged_context() {
    let (fx, _dir, root) = synced_in_folder();

    let committed = fx.add_item().unwrap();

    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    let staged = staged_bytes(&fx);
    let hash = StateHash::of(&staged);
    let (local, state) = saved(&fx);
    assert_eq!(local.staged_hash, Some(hash));
    assert_ne!(local.published_context, state.context);
    assert_eq!(last_publish(&fx), Some(hash));
    assert_eq!(published(&root, &fx), vec![hash]);
    let path = root
        .join(ShortId::encode_uuid(fx.id()))
        .join(ShortId::encode_uuid(REPLICA.0))
        .join(StateFile::name(fx.id(), hash));
    assert_eq!(fs::read(path).unwrap(), staged);

    fx.write(|_| Ok(())).unwrap();

    let (local, state) = saved(&fx);
    assert_eq!(local.staged_hash, None);
    assert_eq!(local.published_context, state.context);
    assert_eq!(published(&root, &fx), vec![hash]);
}

#[cfg(target_os = "macos")]
#[test]
fn root_removed_while_app_runs_pauses_sync_with_unreachable_and_next_transaction_publishes() {
    let (fx, dir, root) = synced_in_folder();
    fx.add_item().unwrap();
    let first = last_publish(&fx).unwrap();
    let away = dir.path().join("Vaults.away");
    fs::rename(&root, &away).unwrap();

    let committed = fx
        .write(|vh| vh.add_item("second", "Second").map(|_| ()))
        .unwrap();

    assert!(committed.changed);
    let Some(SyncStatus::Paused(causes)) = committed.sync_status else {
        panic!("sync is paused");
    };
    assert!(
        causes
            .iter()
            .any(|cause| matches!(cause, PausedCause::Unreachable { .. }))
    );
    assert_eq!(last_publish(&fx), Some(first));
    assert!(!root.exists());
    let staged = StateHash::of(&staged_bytes(&fx));

    fs::rename(&away, &root).unwrap();
    let committed = fx.write(|_| Ok(())).unwrap();

    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    assert_eq!(last_publish(&fx), Some(staged));
    assert!(published(&root, &fx).contains(&staged));
}

#[cfg(target_os = "macos")]
#[test]
fn sidecar_that_fails_to_parse_and_holds_valid_root_keeps_root_and_next_transaction_syncs_through_it()
 {
    let (fx, _dir, root) = synced_in_folder();
    let path = Sidecar::path(&fx.root, fx.id());
    let mut saved: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    saved["unknown"] = 1.into();
    fs::write(&path, saved.to_string()).unwrap();
    let kept = Some(TransportRoot::Folder { path: root.clone() });
    assert_eq!(Sidecar::load(&fx.root, fx.id()).transport, kept);

    let committed = fx.add_item().unwrap();

    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    let hash = last_publish(&fx).unwrap();
    assert_eq!(published(&root, &fx), vec![hash]);
    assert_eq!(Sidecar::load(&fx.root, fx.id()).transport, kept);
}
