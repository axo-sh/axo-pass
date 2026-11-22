#[cfg(macos)]
use objc2_core_services::{
    kFSEventStreamEventFlagItemCreated, kFSEventStreamEventFlagItemIsFile,
    kFSEventStreamEventFlagItemModified, kFSEventStreamEventFlagKernelDropped,
    kFSEventStreamEventFlagMustScanSubDirs, kFSEventStreamEventFlagRootChanged,
    kFSEventStreamEventFlagUserDropped,
};

use super::*;
use crate::secrets::vaults::sync::sync_log;
#[cfg(macos)]
use crate::secrets::vaults::sync::transport::folder::watch::FolderWatch;
use crate::secrets::vaults::sync::transport::folder::watch::matches;
#[cfg(macos)]
use crate::secrets::vaults::sync::transport::folder::watch::{Changes, metadata::MetadataWatch};

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
            &StateFile::name(StateHash::of(b"peer")),
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
        &StateFile::name(StateHash::of(b"other")),
        b"other",
    );
    other_calls.recv_timeout(WATCH_WAIT).unwrap();

    let written = Instant::now();
    folder.put(
        VAULT,
        peer,
        &StateFile::name(StateHash::of(b"peer")),
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
        &StateFile::name(StateHash::of(b"peer")),
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
        &StateFile::name(StateHash::of(b"peer")),
        b"peer",
    );
    calls.recv_timeout(WATCH_WAIT).unwrap();
}

#[test]
fn watch_matches_paths_under_directory_and_its_ancestors() {
    let dir = Path::new("/private/var/root/vault");
    assert!(matches(dir, dir));
    assert!(matches(
        dir,
        Path::new("/private/var/root/vault/replica/key.json")
    ));
    assert!(matches(dir, Path::new("/private/var/root")));
    assert!(!matches(
        dir,
        Path::new("/private/var/root/vault2/key.json")
    ));
    assert!(!matches(
        dir,
        Path::new("/private/var/root/pairing/request.json")
    ));
    assert!(!matches(dir, Path::new("/var/root/vault/key.json")));
}

#[test]
#[cfg(macos)]
fn lost_event_flags_make_watch_scan() {
    for flags in [
        kFSEventStreamEventFlagMustScanSubDirs,
        kFSEventStreamEventFlagUserDropped,
        kFSEventStreamEventFlagKernelDropped,
        kFSEventStreamEventFlagRootChanged,
        kFSEventStreamEventFlagRootChanged | kFSEventStreamEventFlagItemCreated,
    ] {
        assert!(FolderWatch::lost_events(flags), "flags {flags:#x}");
    }
    for flags in [
        0,
        kFSEventStreamEventFlagItemCreated,
        kFSEventStreamEventFlagItemModified | kFSEventStreamEventFlagItemIsFile,
    ] {
        assert!(!FolderWatch::lost_events(flags), "flags {flags:#x}");
    }
}

#[test]
fn finished_download_calls_watch_of_its_vault_and_logs_source() {
    let folder = Folder::plain();
    let other = Uuid::from_u128(0x0123);
    let peer = ReplicaId(Uuid::from_u128(2));
    folder.put_not_local(VAULT, peer, &StateFile::name(StateHash::of(b"peer")), None);
    let (notify, calls) = watch_calls();
    let _watch = folder.transport.watch(VAULT, notify).unwrap();
    let (other_notify, other_calls) = watch_calls();
    let _other_watch = folder.transport.watch(other, other_notify).unwrap();
    let (pairing_notify, pairing_calls) = watch_calls();
    let _pairing_watch = folder.transport.watch_pairings(pairing_notify).unwrap();
    settle(&[&calls, &other_calls, &pairing_calls]);

    folder.transport.request_download(VAULT).unwrap();
    assert!(calls.try_recv().is_err(), "the download did not end");
    assert_eq!(folder.plain_io().finish_downloads(), 1);

    calls.try_recv().unwrap();
    assert!(other_calls.try_recv().is_err());
    assert!(pairing_calls.try_recv().is_err());
    let logged = sync_log::entries().into_iter().any(|entry| {
        entry.vault_id == Some(VAULT) && entry.message == "Watch event from a finished download"
    });
    assert!(logged);
}

#[test]
fn finished_pairing_download_calls_pairing_watch_only() {
    let folder = Folder::plain();
    let (notify, calls) = watch_calls();
    let _watch = folder.transport.watch(VAULT, notify).unwrap();
    let (pairing_notify, pairing_calls) = watch_calls();
    let _pairing_watch = folder.transport.watch_pairings(pairing_notify).unwrap();
    folder
        .transport
        .write_pairing(request(1), b"request")
        .unwrap();
    folder
        .plain_io()
        .set_remote(&folder.pairing_path(request(1)), true);
    settle(&[&calls, &pairing_calls]);

    folder
        .transport
        .request_pairing_download(request(1))
        .unwrap();
    assert_eq!(folder.plain_io().finish_downloads(), 1);

    pairing_calls.try_recv().unwrap();
    assert!(calls.try_recv().is_err());
}

#[test]
fn download_finished_after_watch_drop_calls_nothing() {
    let folder = Folder::plain();
    let peer = ReplicaId(Uuid::from_u128(2));
    folder.put_not_local(VAULT, peer, &StateFile::name(StateHash::of(b"peer")), None);
    let (notify, calls) = watch_calls();
    let watch = folder.transport.watch(VAULT, notify).unwrap();
    folder.transport.request_download(VAULT).unwrap();

    drop(watch);
    assert_callback_dropped(&calls);

    assert_eq!(folder.plain_io().finish_downloads(), 1);
}

#[test]
#[cfg(macos)]
fn metadata_query_starts_and_ends_on_drop() {
    let folder = Folder::plain();
    let root = fs::canonicalize(&folder.root).unwrap();
    let (sender, calls) = mpsc::channel::<Changes>();
    let watch = MetadataWatch::start(
        &root,
        Box::new(move |changes| {
            let _ = sender.send(changes);
        }),
    )
    .unwrap();

    let dropped = Instant::now();
    drop(watch);

    // A stop that came before the run loop ran ends the thread within the
    // keep-alive timeout.
    assert!(dropped.elapsed() < Duration::from_secs(10));
    loop {
        match calls.try_recv() {
            Ok(_) => continue,
            Err(TryRecvError::Disconnected) => break,
            Err(TryRecvError::Empty) => panic!("query callback is still held"),
        }
    }
}

#[test]
fn signals_run_while_any_watch_of_root_is_live() {
    let folder = Folder::plain();
    assert!(!folder.transport.watching());

    let vault = folder.transport.watch(VAULT, Box::new(|| {})).unwrap();
    let pairings = folder.transport.watch_pairings(Box::new(|| {})).unwrap();
    assert!(folder.transport.watching());

    drop(vault);
    assert!(folder.transport.watching());
    drop(pairings);
    assert!(!folder.transport.watching());

    // A new watch starts the signals again.
    let (notify, calls) = watch_calls();
    let _watch = folder.transport.watch(VAULT, notify).unwrap();
    assert!(folder.transport.watching());
    let peer = ReplicaId(Uuid::from_u128(2));
    folder.put(
        VAULT,
        peer,
        &StateFile::name(StateHash::of(b"peer")),
        b"peer",
    );
    calls.recv_timeout(WATCH_WAIT).unwrap();
}

/// Wait until `io` has `count` download calls.
fn wait_for_downloads(io: &PlainIo, count: usize) {
    let start = Instant::now();
    while io.downloads().len() < count {
        assert!(start.elapsed() < WATCH_WAIT, "{count} downloads");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn failed_download_retried_and_calls_watch_when_it_ends() {
    let folder = Folder::plain();
    let peer = ReplicaId(Uuid::from_u128(2));
    folder.put_not_local(VAULT, peer, &StateFile::name(StateHash::of(b"peer")), None);
    let (notify, calls) = watch_calls();
    let _watch = folder.transport.watch(VAULT, notify).unwrap();
    settle(&[&calls]);

    folder.transport.request_download(VAULT).unwrap();
    assert_eq!(folder.plain_io().fail_downloads(), 1);
    assert!(calls.try_recv().is_err());

    wait_for_downloads(folder.plain_io(), 2);
    assert_eq!(folder.plain_io().finish_downloads(), 1);

    calls.try_recv().unwrap();
}

#[test]
fn download_retries_stop_after_last_delay() {
    let folder = Folder::plain();
    let peer = ReplicaId(Uuid::from_u128(2));
    folder.put_not_local(VAULT, peer, &StateFile::name(StateHash::of(b"peer")), None);

    folder.transport.request_download(VAULT).unwrap();
    for count in 2..=4 {
        assert_eq!(folder.plain_io().fail_downloads(), 1);
        wait_for_downloads(folder.plain_io(), count);
    }
    assert_eq!(folder.plain_io().fail_downloads(), 1);

    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(folder.plain_io().downloads().len(), 4);
}

#[test]
fn file_made_local_before_retry_is_not_downloaded_again() {
    let folder = Folder::plain();
    let peer = ReplicaId(Uuid::from_u128(2));
    let name = StateFile::name(StateHash::of(b"peer"));
    folder.put_not_local(VAULT, peer, &name, None);

    folder.transport.request_download(VAULT).unwrap();
    let path = folder.replica_dir(VAULT, peer).join(&name);
    folder.plain_io().set_remote(&path, false);
    assert_eq!(folder.plain_io().fail_downloads(), 1);

    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(folder.plain_io().downloads().len(), 1);
}
