use super::*;

/// Longest wait for a watch call. FSEvents delivers after a latency of one
/// second.
const WATCH_WAIT: Duration = Duration::from_secs(5);

/// Watch callback that sends the time of each call, and the receiver.
fn watch_calls() -> (Box<dyn Fn() + Send>, Receiver<Instant>) {
    let (sender, receiver) = mpsc::channel();
    let notify = Box::new(move || {
        let _ = sender.send(Instant::now());
    });
    (notify, receiver)
}

/// Wait past the FSEvents latency, then discard calls of `calls`. FSEvents can
/// deliver events of the folder setup to a stream that started afterwards, and
/// those events match every watch of the folder.
fn settle(calls: &[&Receiver<Instant>]) {
    std::thread::sleep(Duration::from_millis(2500));
    for calls in calls {
        while calls.try_recv().is_ok() {}
    }
}

/// Assert that the callback of `calls` is dropped, so no call can follow.
/// Calls sent before the drop are skipped.
fn assert_callback_dropped(calls: &Receiver<Instant>) {
    loop {
        match calls.try_recv() {
            Ok(_) => continue,
            Err(TryRecvError::Disconnected) => return,
            Err(TryRecvError::Empty) => panic!("watch callback is still held"),
        }
    }
}

#[test]
fn folder_transport_watch_fires_on_write_and_ends_on_drop() {
    for folder in Folder::each() {
        let (notify, calls) = watch_calls();
        let watch = folder.transport.watch(VAULT, notify).unwrap();

        // The vault directory is created after the watch starts.
        let peer = ReplicaId(Uuid::from_u128(2));
        folder.put(
            VAULT,
            peer,
            &StateFile::name(VAULT, StateHash::of(b"peer")),
            b"peer",
        );
        calls.recv_timeout(WATCH_WAIT).unwrap();

        drop(watch);
        assert_callback_dropped(&calls);
    }
}

#[test]
fn state_file_written_into_peer_directory_calls_watch_and_write_in_other_vault_directory_does_not()
{
    let folder = Folder::plain();
    let other = Uuid::from_u128(0x0123);
    let peer = ReplicaId(Uuid::from_u128(2));
    let (notify, calls) = watch_calls();
    let _watch = folder.transport.watch(VAULT, notify).unwrap();
    let (other_notify, other_calls) = watch_calls();
    let _other_watch = folder.transport.watch(other, other_notify).unwrap();
    settle(&[&calls, &other_calls]);

    // The watch of the other vault shows that FSEvents delivered the write.
    folder.put(
        other,
        peer,
        &StateFile::name(other, StateHash::of(b"other")),
        b"other",
    );
    other_calls.recv_timeout(WATCH_WAIT).unwrap();

    let written = Instant::now();
    folder.put(
        VAULT,
        peer,
        &StateFile::name(VAULT, StateHash::of(b"peer")),
        b"peer",
    );
    let first = calls.recv_timeout(WATCH_WAIT).unwrap();
    // A stream delivers events in order, so a call for the other write
    // would come first.
    assert!(first >= written);
}

#[test]
fn pairing_request_written_calls_pairing_watch() {
    let folder = Folder::plain();
    let (notify, calls) = watch_calls();
    let (vault_notify, vault_calls) = watch_calls();
    let _watch = folder.transport.watch_pairings(notify).unwrap();
    let _vault_watch = folder.transport.watch(VAULT, vault_notify).unwrap();
    settle(&[&calls, &vault_calls]);

    folder
        .transport
        .write_pairing(request(1), b"request")
        .unwrap();
    calls.recv_timeout(WATCH_WAIT).unwrap();
    assert!(vault_calls.try_recv().is_err());
}

#[test]
fn after_watch_handle_drops_no_call_follows() {
    let folder = Folder::plain();
    let peer = ReplicaId(Uuid::from_u128(2));
    let (notify, calls) = watch_calls();
    let watch = folder.transport.watch(VAULT, notify).unwrap();
    let (live_notify, live_calls) = watch_calls();
    let _live = folder.transport.watch(VAULT, live_notify).unwrap();

    drop(watch);
    assert_callback_dropped(&calls);

    // The live watch shows that FSEvents delivered a write after the drop.
    folder.put(
        VAULT,
        peer,
        &StateFile::name(VAULT, StateHash::of(b"peer")),
        b"peer",
    );
    live_calls.recv_timeout(WATCH_WAIT).unwrap();
}

#[test]
fn missing_root_gives_no_watch() {
    let folder = Folder::plain();
    let missing = folder.transport_at(&folder.dir.path().join("Missing"));
    let (notify, calls) = watch_calls();
    assert!(missing.watch(VAULT, notify).is_none());
    assert_callback_dropped(&calls);
    assert!(missing.watch_pairings(Box::new(|| {})).is_none());

    let file = folder.dir.path().join("File");
    fs::write(&file, b"file").unwrap();
    assert!(
        folder
            .transport_at(&file)
            .watch(VAULT, Box::new(|| {}))
            .is_none()
    );
}

#[test]
fn watch_of_root_reached_through_symlink_calls_notify() {
    let folder = Folder::plain();
    let link = folder.dir.path().join("Link");
    symlink(&folder.root, &link).unwrap();
    let (notify, calls) = watch_calls();
    let _watch = folder.transport_at(&link).watch(VAULT, notify).unwrap();

    let peer = ReplicaId(Uuid::from_u128(2));
    folder.put(
        VAULT,
        peer,
        &StateFile::name(VAULT, StateHash::of(b"peer")),
        b"peer",
    );
    calls.recv_timeout(WATCH_WAIT).unwrap();
}

#[test]
fn watch_matches_paths_under_directory_and_its_ancestors() {
    let dir = Path::new("/private/var/root/vault");
    assert!(FolderWatch::matches(dir, dir));
    assert!(FolderWatch::matches(
        dir,
        Path::new("/private/var/root/vault/replica/key.json")
    ));
    assert!(FolderWatch::matches(dir, Path::new("/private/var/root")));
    assert!(!FolderWatch::matches(
        dir,
        Path::new("/private/var/root/vault2/key.json")
    ));
    assert!(!FolderWatch::matches(
        dir,
        Path::new("/private/var/root/pairing/request.json")
    ));
    assert!(!FolderWatch::matches(
        dir,
        Path::new("/var/root/vault/key.json")
    ));
}
