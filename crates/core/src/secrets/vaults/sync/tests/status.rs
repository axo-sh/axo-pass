//! Sync status: stops found again at each load, and paused causes recorded in
//! the sidecar that clear when their condition clears.

use std::fs;
use std::sync::Arc;

use super::join::PEER;
use super::load::{Fixture, GENERATION, REPLICA, body, device_key, state};
use super::publish::last_publish;
use super::state_file::keyring;
use super::transport::FakeTransport;
use super::txn::{
    add_item_counting, new_write_ids, saved, saved_vault, state_file, synced, under_key_2,
};
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::storage::txn::Committed;
use crate::secrets::vaults::sync::load::SignatureFailure;
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::state_file::{StateFile, StateHash};
use crate::secrets::vaults::sync::status::{PausedCause, StopCause, SyncStatus};

fn status(committed: &Committed<()>) -> Option<SyncStatus> {
    committed.sync_status.clone()
}

fn paused(fx: &Fixture) -> Vec<PausedCause> {
    Sidecar::load(&fx.root, fx.id()).paused
}

#[test]
fn deleted_sync_state_stops_sync_as_missing() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let committed = fx.add_item().unwrap();
    assert_eq!(status(&committed), Some(SyncStatus::Active));

    fs::remove_file(fx.state_path()).unwrap();

    // The vault loads, and each transaction finds the stop again.
    fx.read().unwrap();
    for _ in 0..2 {
        let committed = fx
            .write(|vh| vh.add_item("second", "Second").map(|_| ()))
            .unwrap();
        assert_eq!(
            status(&committed),
            Some(SyncStatus::Stopped(StopCause::StateMissing))
        );
    }
    assert!(!fx.state_path().exists());
    assert!(saved_vault(&fx).get_item("second").is_ok());
}

#[test]
fn sync_state_with_planted_sync_keys_entry_fails_verification_stops_sync_and_vault_loads() {
    let fx = Fixture::synced();
    let contents = state(fx.id(), REPLICA, GENERATION)
        .to_file_contents(&TestSigner::device())
        .unwrap();
    let planted = contents.replacen(
        "\"sync_keys\": [",
        "\"sync_keys\": [\n    { \"key_id\": 9, \"wrapped\": \"AAAA\" },",
        1,
    );
    fx.put_text(&planted);

    fx.read().unwrap();
    let committed = fx.add_item().unwrap();

    let failed = SyncStatus::Stopped(StopCause::SignatureFailed(SignatureFailure::Signature));
    assert_eq!(status(&committed), Some(failed));
    assert_eq!(fs::read_to_string(fx.state_path()).unwrap(), planted);
    assert!(saved_vault(&fx).get_item("item").is_ok());
}

#[test]
fn unreachable_folder_and_failed_publish_pause_sync_and_clear_with_no_recovery_merge() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    transport.set_unavailable(true);

    let committed = fx.add_item().unwrap();

    let causes = paused(&fx);
    assert!(matches!(
        &causes[..],
        [
            PausedCause::Unreachable { .. },
            PausedCause::PublishFailed { .. }
        ]
    ));
    assert_eq!(status(&committed), Some(SyncStatus::Paused(causes)));
    // A paused sync records the edit.
    let (local, recorded) = saved(&fx);
    assert!(local.staged_hash.is_some());

    // A sidecar that fails to parse loses the causes, and the next
    // transaction finds them again.
    fs::write(Sidecar::path(&fx.root, fx.id()), "not json").unwrap();
    let committed = fx.write(|_| Ok(())).unwrap();
    assert_eq!(paused(&fx).len(), 2);
    assert_eq!(status(&committed), Some(SyncStatus::Paused(paused(&fx))));

    transport.set_unavailable(false);
    let committed = fx.write(|_| Ok(())).unwrap();

    // The recorded edit is published as it is, with no merge.
    assert_eq!(status(&committed), Some(SyncStatus::Active));
    assert!(paused(&fx).is_empty());
    let (local, state) = saved(&fx);
    assert_eq!(state, recorded);
    assert!(new_write_ids(&recorded, &state).is_empty());
    assert_eq!(local.stopped_build, None);
    assert_eq!(last_publish(&fx), local.staged_hash);
}

#[test]
fn failed_publish_pauses_sync_until_staged_file_copied() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    transport.set_failing_writes(true);

    let committed = fx.add_item().unwrap();

    let causes = paused(&fx);
    assert!(matches!(&causes[..], [PausedCause::PublishFailed { .. }]));
    assert_eq!(status(&committed), Some(SyncStatus::Paused(causes)));

    transport.set_failing_writes(false);
    let committed = fx.write(|_| Ok(())).unwrap();

    assert_eq!(status(&committed), Some(SyncStatus::Active));
    assert!(paused(&fx).is_empty());
    assert!(last_publish(&fx).is_some());
}

#[test]
fn quarantined_file_pauses_sync_while_listed_and_its_entry_kept() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let mut torn = state_file(&fx, PEER, &body(PEER, &[device_key()]));
    let name = StateFile::name(fx.id(), StateHash::of(&torn));
    torn.truncate(torn.len() - 1);
    transport.put(fx.id(), PEER, &name, &torn);

    let committed = fx.add_item().unwrap();

    let causes = vec![PausedCause::Quarantined { files: 1 }];
    assert_eq!(paused(&fx), causes);
    assert_eq!(status(&committed), Some(SyncStatus::Paused(causes.clone())));
    // A file quarantined by an earlier transaction still pauses sync.
    let committed = fx.write(|_| Ok(())).unwrap();
    assert_eq!(status(&committed), Some(SyncStatus::Paused(causes)));

    transport.remove(fx.id(), PEER, &name);
    let committed = fx.write(|_| Ok(())).unwrap();

    assert_eq!(status(&committed), Some(SyncStatus::Active));
    let sidecar = Sidecar::load(&fx.root, fx.id());
    assert!(sidecar.paused.is_empty());
    assert_eq!(sidecar.quarantined.len(), 1);
}

#[test]
fn second_miss_of_sync_state_key_pauses_sync_with_key_missing() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let own = body(REPLICA, &[device_key()]);
    fx.put_text(&under_key_2(&fx, &own, &keyring()));

    let committed = add_item_counting(&fx, |_| {});

    let cause = PausedCause::KeyMissing { key_id: 2 };
    assert_eq!(status(&committed), Some(SyncStatus::Paused(vec![cause])));
}

#[test]
fn vault_not_synced_has_no_sync_status() {
    let fx = Fixture::new(0, None);

    let committed = fx.add_item().unwrap();

    assert_eq!(status(&committed), None);
}
