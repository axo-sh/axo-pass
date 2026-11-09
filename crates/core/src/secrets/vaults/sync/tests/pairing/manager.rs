use std::sync::Arc;
use std::sync::atomic::Ordering;

use jiff::Timestamp;

use super::{
    NewMac, SharedUnwrap, folder, granted, peer, put_key_file, put_request, request_of, typed_key,
    vault, wrapping,
};
use crate::secrets::vaults::sync::keys::SyncKey;
use crate::secrets::vaults::sync::pairing::PairingCode;
use crate::secrets::vaults::sync::pairing::watcher::{PAIRING_EXPIRY, POLL_INTERVAL};
use crate::secrets::vaults::sync::tests::load::{Fixture, GENERATION};
use crate::secrets::vaults::sync::tests::manager::{Event, Managed, folder_root, set_root};
use crate::secrets::vaults::sync::tests::reads::put_peer;
use crate::secrets::vaults::sync::tests::transport::FakeTransport;
use crate::secrets::vaults::sync::tests::txn::synced;
use crate::secrets::vaults::sync::transport::SyncTransport;

// Pairing watcher of the new Mac (9.5). Each watcher runs in a manager on
// the test thread through `SyncManager::run_queued`, with watch events fired
// by `FakeTransport::fire_watch` and the clock moved by
// `SyncManager::advance_clock`.

/// Manager of a new Mac with no synced vault, with its start run. The
/// fixture holds the app data directory of the manager.
fn new_mac_manager() -> (Fixture, Managed) {
    let fx = Fixture::new(GENERATION, None);
    let managed = Managed::start(&fx, false);
    managed.run();
    (fx, managed)
}

#[test]
fn late_wrapping_accepted_on_next_event() {
    let mac = NewMac::new();
    let transport = Arc::new(folder(&[vault(1), vault(2)]));
    let pending = mac.start(&transport, &[]).unwrap();
    let request_id = pending.request().request_id;
    let sync_key = SyncKey::generate();
    let first = granted(&pending, vault(1), peer(1), &sync_key);
    let second = granted(&pending, vault(2), peer(2), &sync_key);
    let (unwrap, calls) = SharedUnwrap::boxed(Some(&sync_key));
    let (_fx, managed) = new_mac_manager();

    managed
        .manager
        .pair(pending, transport.clone(), unwrap, None);
    managed.run();

    // One watch per vault of the request map. The first poll finds nothing.
    assert_eq!(transport.watch_count(), 2);
    assert!(managed.events.taken().is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    put_key_file(&transport, vault(1), peer(1), vec![first]);
    assert_eq!(transport.fire_watch(vault(1)), 1);
    managed.run();

    let key = sync_key.as_bytes().to_vec();
    assert_eq!(
        managed.events.taken(),
        [Event::Paired(vault(1), key.clone())]
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // With no event, the next poll is 10 seconds after the last one.
    put_key_file(&transport, vault(2), peer(2), vec![second]);
    managed.manager.advance_clock(POLL_INTERVAL.as_secs() - 1);
    managed.run();
    assert!(managed.events.taken().is_empty());
    managed.manager.advance_clock(1);
    managed.run();

    assert_eq!(managed.events.taken(), [Event::Paired(vault(2), key)]);
    assert_eq!(calls.load(Ordering::SeqCst), 2, "one unwrap per vault");
    // The request stays until the user finishes.
    assert!(transport.pairing(request_id).is_some());
}

#[test]
fn request_deleted_on_quit_or_timeout() {
    for quit in [true, false] {
        let mac = NewMac::new();
        let transport = Arc::new(folder(&[vault(1)]));
        let pending = mac.start(&transport, &[]).unwrap();
        let request_id = pending.request().request_id;
        let (unwrap, _) = SharedUnwrap::boxed(None);
        let (_fx, managed) = new_mac_manager();
        managed
            .manager
            .pair(pending, transport.clone(), unwrap, None);
        managed.run();
        assert!(transport.pairing(request_id).is_some());
        assert_eq!(transport.watch_count(), 1);
        assert_eq!(transport.pairing_writes(), 1);

        if quit {
            managed.manager.shutdown();
        } else {
            managed.manager.advance_clock(PAIRING_EXPIRY.as_secs() - 1);
            managed.run();
            assert!(transport.pairing(request_id).is_some(), "quit {quit}");
            managed.manager.advance_clock(1);
            managed.run();
        }

        assert!(transport.pairing(request_id).is_none(), "quit {quit}");
        assert_eq!(transport.watch_count(), 0, "quit {quit}");
        assert_eq!(transport.pairing_writes(), 2, "quit {quit}");
        // The request is deleted once.
        managed.manager.shutdown();
        assert_eq!(transport.pairing_writes(), 2, "quit {quit}");
    }
}

#[test]
fn finished_pairing_ends_its_watches() {
    let mac = NewMac::new();
    let transport = Arc::new(folder(&[vault(1), vault(2)]));
    let pending = mac.start(&transport, &[]).unwrap();
    let request_id = pending.request().request_id;
    let (unwrap, _) = SharedUnwrap::boxed(None);
    let (_fx, managed) = new_mac_manager();
    managed
        .manager
        .pair(pending, transport.clone(), unwrap, None);
    managed.run();
    assert_eq!(transport.watch_count(), 2);

    managed.manager.finish_pairing();
    managed.run();

    assert_eq!(transport.watch_count(), 0);
    assert_eq!(transport.fire_watch(vault(1)), 0);
    assert!(transport.pairing(request_id).is_none());
    assert_eq!(transport.pairing_writes(), 2);

    // A second pairing finishes the one that runs.
    let first = mac.start(&transport, &[]).unwrap();
    let first_id = first.request().request_id;
    let (unwrap, _) = SharedUnwrap::boxed(None);
    managed.manager.pair(first, transport.clone(), unwrap, None);
    managed.run();
    let second = mac.start(&transport, &[]).unwrap();
    let second_id = second.request().request_id;
    let (unwrap, _) = SharedUnwrap::boxed(None);
    managed
        .manager
        .pair(second, transport.clone(), unwrap, None);
    managed.run();

    assert!(transport.pairing(first_id).is_none());
    assert!(transport.pairing(second_id).is_some());
    assert_eq!(transport.watch_count(), 2);
}

#[test]
fn only_pairing_watcher_writes_pairing_requests_and_manager_writes_none() {
    // Unlocked Mac: a synced vault whose root holds a request of another
    // Mac, with a peer change and a pairing event.
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    set_root(&fx, &folder_root());
    transport.set_now(Timestamp::now());
    put_request(
        &transport,
        &request_of(&PairingCode::generate(), &[fx.id()]),
    );
    let managed = Managed::start(&fx, true);
    managed.run();
    put_peer(&fx, &transport, peer(1), "joined");
    transport.fire_watch(fx.id());
    transport.fire_pairing_watch();
    managed.run();
    managed.manager.shutdown();

    assert_eq!(managed.unlock.transactions(), 1);
    assert_eq!(
        managed.events.taken(),
        [
            Event::Pairings(folder_root(), 1),
            Event::Synced(fx.id()),
            Event::Pairings(folder_root(), 1),
        ]
    );
    assert_eq!(transport.pairing_writes(), 0);
    assert_eq!(transport.list_pairings().unwrap().len(), 1);

    // New Mac: the request write of the start, and the one delete of the
    // watcher.
    let mac = NewMac::new();
    let new = Arc::new(folder(&[vault(1)]));
    let pending = mac.start(&new, &[]).unwrap();
    assert_eq!(new.pairing_writes(), 1);
    let (unwrap, _) = SharedUnwrap::boxed(None);
    let (_new_fx, new_managed) = new_mac_manager();
    new_managed.manager.pair(pending, new.clone(), unwrap, None);
    new_managed.run();
    new.fire_watch(vault(1));
    new_managed.run();
    new_managed.manager.advance_clock(POLL_INTERVAL.as_secs());
    new_managed.run();
    assert_eq!(new.pairing_writes(), 1);

    new_managed.manager.finish_pairing();
    new_managed.run();

    assert_eq!(new.pairing_writes(), 2);
    assert!(new.list_pairings().unwrap().is_empty());
}

#[test]
fn wrapping_whose_unwrap_fails_not_unwrapped_again_and_new_wrapping_is() {
    let mac = NewMac::new();
    let transport = Arc::new(folder(&[vault(1)]));
    let pending = mac.start(&transport, &[]).unwrap();
    let sync_key = SyncKey::generate();
    put_key_file(
        &transport,
        vault(1),
        peer(1),
        vec![granted(&pending, vault(1), peer(1), &sync_key)],
    );
    // A second wrapping with other wrapped bytes, from another replica.
    let request = pending.request().clone();
    let mut other = wrapping(&sync_key, request.replicas[&vault(1)]);
    other.wrapped = vec![0xd1, 0xd2];
    typed_key(&pending).seal_wrapping(&mut other, vault(1), peer(2), &request.keys());
    let (unwrap, calls) = SharedUnwrap::boxed(None);
    let (_fx, managed) = new_mac_manager();

    managed
        .manager
        .pair(pending, transport.clone(), unwrap, None);
    managed.run();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    transport.fire_watch(vault(1));
    managed.run();
    managed.manager.advance_clock(POLL_INTERVAL.as_secs());
    managed.run();

    assert_eq!(calls.load(Ordering::SeqCst), 1, "no second unwrap");
    assert!(managed.events.taken().is_empty());

    put_key_file(&transport, vault(1), peer(2), vec![other]);
    transport.fire_watch(vault(1));
    managed.run();

    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn pairing_handed_to_stopped_manager_deletes_its_request() {
    let mac = NewMac::new();
    let transport = Arc::new(folder(&[vault(1)]));
    let (_fx, managed) = new_mac_manager();
    managed.manager.shutdown();
    let pending = mac.start(&transport, &[]).unwrap();
    let request_id = pending.request().request_id;
    let (unwrap, _) = SharedUnwrap::boxed(None);

    managed
        .manager
        .pair(pending, transport.clone(), unwrap, None);

    assert!(transport.pairing(request_id).is_none());
    assert_eq!(transport.watch_count(), 0);
}
