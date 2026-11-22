//! Audit events of the sync transaction.

use std::fs;
use std::sync::Arc;

use super::guard::{add, drift, published_vault};
use super::join::PEER;
use super::load::{Fixture, GENERATION, REPLICA, body, device_key, state};
use super::simulator::Sim;
use super::transport::FakeTransport;
use super::txn::{saved_vault, state_file, synced};
use crate::audit::test_support::test_dir;
use crate::audit::{self, Action, AuditEvent, AuditFilter};
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::storage::txn::{Target, Unlock};
use crate::secrets::vaults::sync::repair::SyncOverride;
use crate::secrets::vaults::sync::sidecar::{Health, Sidecar};
use crate::secrets::vaults::sync::state_file::{StateFile, StateHash};

/// Recorded events of `action`, newest first.
fn events(action: Action) -> Vec<AuditEvent> {
    let filter = AuditFilter {
        actions: vec![action],
        ..AuditFilter::default()
    };
    audit::read(&filter).events
}

/// Run the user override on `fx`.
fn confirm(fx: &Fixture) {
    let key = || fx.vault.unlocked_key().unwrap();
    let target = Target::of(&fx.vault);
    SyncOverride::new(fx.catalog.files(), &target)
        .confirm(Unlock::Test(&key))
        .unwrap();
}

/// Check that no recorded event of the vault names any of `values`.
fn assert_not_recorded(values: &[&str]) {
    let all = audit::read(&AuditFilter::default()).events;
    for event in all {
        let text = serde_json::to_string(&event).unwrap();
        for value in values {
            assert!(!text.contains(value), "{value} recorded in {text}");
        }
    }
}

#[test]
fn peer_changes_recorded_as_applied() {
    let _audit = test_dir();
    let mut sim = Sim::new(2, None);
    sim.write(0, |vh| vh.add_item("mail", "Title-from-zero").map(|_| ()));
    sim.converge();

    let id = sim.macs[1].saved_vault().get_item("mail").unwrap().id;
    let applied = events(Action::SyncApplied);
    assert_eq!(applied.len(), 1);
    let detail = &applied[0].detail;
    assert_eq!(detail["source_replicas"], Sim::replica(0).0.to_string());
    assert_eq!(detail["item_ids"], id.to_string());
    assert!(!detail.contains_key("websites_added_item_ids"));
    assert!(!detail.contains_key("slots_changed_item_ids"));
    assert!(events(Action::SyncDeletedByPeer).is_empty());
    assert_not_recorded(&["Title-from-zero"]);
}

#[test]
fn purge_from_peer_recorded_with_source_mac() {
    let _audit = test_dir();
    let mut sim = Sim::new(2, None);
    sim.write(0, |vh| vh.add_item("mail", "Mail").map(|_| ()));
    sim.converge();
    let id = sim.macs[1].saved_vault().get_item("mail").unwrap().id;

    sim.write(0, |vh| vh.delete_item("mail"));
    sim.write(0, |vh| vh.purge_item(id));
    sim.converge();

    let deleted = events(Action::SyncDeletedByPeer);
    assert_eq!(deleted.len(), 1);
    let detail = &deleted[0].detail;
    assert_eq!(detail["source_replicas"], Sim::replica(0).0.to_string());
    assert_eq!(detail["item_ids"], id.to_string());
    assert_eq!(detail["purged"], "1");
}

#[test]
fn write_over_conflict_recorded_as_resolved() {
    let _audit = test_dir();
    let mut sim = Sim::new(2, None);
    sim.write(0, |vh| vh.add_item("mail", "Mail").map(|_| ()));
    sim.converge();
    sim.write(0, |vh| vh.add_item("mail", "Title-from-zero").map(|_| ()));
    sim.write(1, |vh| vh.add_item("mail", "Title-from-one").map(|_| ()));
    sim.converge();
    assert!(events(Action::SyncConflictResolved).is_empty());

    sim.write(0, |vh| vh.add_item("mail", "Title-resolved").map(|_| ()));

    let resolved = events(Action::SyncConflictResolved);
    assert_eq!(resolved.len(), 1);
    let detail = &resolved[0].detail;
    let id = sim.macs[0].saved_vault().get_item("mail").unwrap().id;
    assert_eq!(detail["register"], "title");
    assert_eq!(detail["item_ids"], id.to_string());
    assert_eq!(detail["superseded"], "2");
    let values = &detail["superseded_values"];
    assert!(values.contains(&Sim::replica(0).0.to_string()));
    assert!(values.contains(&Sim::replica(1).0.to_string()));
    assert_not_recorded(&["Title-from-zero", "Title-from-one", "Title-resolved"]);
}

#[test]
fn write_over_single_value_not_recorded_as_resolved() {
    let _audit = test_dir();
    let mut sim = Sim::new(2, None);
    sim.write(0, |vh| vh.add_item("mail", "Mail").map(|_| ()));
    sim.converge();

    sim.write(0, |vh| vh.add_item("mail", "Renamed").map(|_| ()));

    assert!(events(Action::SyncConflictResolved).is_empty());
}

#[test]
fn drift_stop_and_user_override_recorded() {
    let _audit = test_dir();
    let transport = Arc::new(FakeTransport::default());
    let fx = published_vault(&transport);
    drift(&fx, "item");

    fx.write(|_| Ok(())).unwrap();

    let stopped = events(Action::SyncStopped);
    assert_eq!(stopped.len(), 1);
    assert_eq!(stopped[0].detail["cause"], "drift");
    assert_eq!(stopped[0].detail["edits"], "1");
    assert!(events(Action::SyncRepair).is_empty());

    // A stopped transaction on the same build records nothing more.
    fx.write(|_| Ok(())).unwrap();
    assert_eq!(events(Action::SyncStopped).len(), 1);

    confirm(&fx);

    let repairs = events(Action::SyncRepair);
    assert_eq!(repairs.len(), 1);
    assert_eq!(repairs[0].detail["cause"], "user override");
    assert_eq!(repairs[0].detail["differences"], "1");
    assert_eq!(events(Action::SyncResumed).len(), 1);
    assert_not_recorded(&["Drifted"]);
}

#[test]
fn override_of_paused_sync_records_one_resume() {
    let _audit = test_dir();
    let transport = Arc::new(FakeTransport::default());
    let fx = published_vault(&transport);
    transport.set_failing_writes(true);
    add(&fx, "second").unwrap();
    assert_eq!(events(Action::SyncPaused).len(), 1);
    drift(&fx, "item");
    fx.write(|_| Ok(())).unwrap();
    assert_eq!(events(Action::SyncStopped).len(), 1);
    transport.set_failing_writes(false);

    confirm(&fx);

    assert_eq!(events(Action::SyncResumed).len(), 1);
}

#[test]
fn load_failure_cleared_while_stopped_records_no_resume() {
    let _audit = test_dir();
    let transport = Arc::new(FakeTransport::default());
    let fx = published_vault(&transport);
    drift(&fx, "item");
    fx.write(|_| Ok(())).unwrap();
    let state = fs::read(fx.state_path()).unwrap();
    fs::remove_file(fx.state_path()).unwrap();
    fx.write(|_| Ok(())).unwrap();
    assert_eq!(events(Action::SyncLocalFileMissing).len(), 1);

    fs::write(fx.state_path(), state).unwrap();
    fx.write(|_| Ok(())).unwrap();

    assert!(events(Action::SyncResumed).is_empty());
    assert_eq!(Sidecar::load(&fx.root, fx.id()).health, Health::Ok);
}

#[test]
fn paused_and_resumed_recorded_on_cause_change_only() {
    let _audit = test_dir();
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    transport.set_failing_writes(true);

    fx.add_item().unwrap();

    let paused = events(Action::SyncPaused);
    assert_eq!(paused.len(), 1);
    assert_eq!(paused[0].detail["causes"], "publish_failed");

    // The same cause found again records nothing.
    fx.write(|_| Ok(())).unwrap();
    assert_eq!(events(Action::SyncPaused).len(), 1);
    assert!(events(Action::SyncResumed).is_empty());

    transport.set_failing_writes(false);
    fx.write(|_| Ok(())).unwrap();

    assert_eq!(events(Action::SyncPaused).len(), 1);
    assert_eq!(events(Action::SyncResumed).len(), 1);
}

#[test]
fn quarantined_file_recorded_once() {
    let _audit = test_dir();
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let mut torn = state_file(&fx, PEER, &body(PEER, &[device_key()]));
    let name = StateFile::name(StateHash::of(&torn));
    torn.truncate(torn.len() - 1);
    transport.put(fx.id(), PEER, &name, &torn);

    fx.add_item().unwrap();
    fx.write(|_| Ok(())).unwrap();

    let quarantined = events(Action::SyncFileQuarantined);
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].detail["replica"], PEER.0.to_string());
    assert_eq!(quarantined[0].detail["file"], name);
    let paused = events(Action::SyncPaused);
    assert_eq!(paused.len(), 1);
    assert_eq!(paused[0].detail["causes"], "quarantined");
}

#[test]
fn missing_sync_state_recorded_as_missing_file() {
    let _audit = test_dir();
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    fs::remove_file(fx.state_path()).unwrap();

    fx.write(|vh| vh.add_item("second", "Second").map(|_| ()))
        .unwrap();

    let missing = events(Action::SyncLocalFileMissing);
    assert_eq!(missing.len(), 1);
    assert_eq!(missing[0].detail["file"], "sync state");
    assert!(saved_vault(&fx).get_item("second").is_ok());

    // The same failure found again records nothing.
    for _ in 0..2 {
        fx.write(|_| Ok(())).unwrap();
    }
    assert_eq!(events(Action::SyncLocalFileMissing).len(), 1);
}

#[test]
fn restored_sync_state_clears_failure_so_it_records_again() {
    let _audit = test_dir();
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let state = fs::read(fx.state_path()).unwrap();
    fs::remove_file(fx.state_path()).unwrap();
    fx.write(|_| Ok(())).unwrap();
    assert_eq!(events(Action::SyncLocalFileMissing).len(), 1);
    assert!(events(Action::SyncResumed).is_empty());

    fs::write(fx.state_path(), state).unwrap();
    fx.write(|_| Ok(())).unwrap();
    assert_eq!(events(Action::SyncResumed).len(), 1);

    fs::remove_file(fx.state_path()).unwrap();
    fx.write(|_| Ok(())).unwrap();
    assert_eq!(events(Action::SyncLocalFileMissing).len(), 2);
}

#[test]
fn failed_signature_recorded_as_stop() {
    let _audit = test_dir();
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

    fx.add_item().unwrap();

    let stopped = events(Action::SyncStopped);
    assert_eq!(stopped.len(), 1);
    assert_eq!(stopped[0].detail["cause"], "signature failed");

    // The same failure found again records nothing.
    fx.add_item().unwrap();
    assert_eq!(events(Action::SyncStopped).len(), 1);
}
