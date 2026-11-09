//! No-edit guard and the drift stop.

use std::fs;
use std::sync::Arc;

use super::join::{PEER, peer_state};
use super::load::{Fixture, GENERATION, REPLICA};
use super::publish::published;
use super::transport::FakeTransport;
use super::txn::{new_write_ids, saved, saved_vault, state_file, synced};
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::storage::txn::Committed;
use crate::secrets::vaults::sync::load::SyncLoad;
use crate::secrets::vaults::sync::local_state::LocalSyncState;
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::status::{BUILD_ID, StopCause, SyncStatus};
use crate::secrets::vaults::{Error, VaultHandle};

/// Status of a sync stopped by drift on this build, with the override
/// offered.
pub(super) fn stopped() -> Option<SyncStatus> {
    Some(SyncStatus::Stopped(StopCause::Drift {
        build: BUILD_ID.to_string(),
        override_offered: true,
    }))
}

/// Set the title of item `key` in the vault file of `fx` outside a
/// transaction, at the same generation, as a normalization that is not
/// stable would.
pub(super) fn drift(fx: &Fixture, key: &str) {
    let mut vault = saved_vault(fx);
    vault.add_or_update_item(key, "Drifted").unwrap();
    let vh = VaultHandle::unlocked(fx.vault.path.clone(), vault);
    let contents = vh.file_contents(&TestSigner::device()).unwrap();
    fs::write(&fx.vault.path, contents).unwrap();
}

/// Synced vault with item `item` published, and the staged context of the
/// publish moved.
pub(super) fn published_vault(transport: &Arc<FakeTransport>) -> Fixture {
    let fx = synced(transport);
    fx.add_item().unwrap();
    let committed = fx.write(|_| Ok(())).unwrap();
    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    fx
}

/// Add item `key` in a transaction.
pub(super) fn add(fx: &Fixture, key: &str) -> Result<Committed<()>, Error> {
    fx.write(|vh| vh.add_item(key, "Added").map(|_| ()))
}

#[test]
fn transaction_with_no_requested_change_that_finds_edits_mints_no_write_id_and_publishes_nothing() {
    let transport = Arc::new(FakeTransport::default());
    let fx = published_vault(&transport);
    let (before_local, before) = saved(&fx);
    let writes = transport.writes();
    drift(&fx, "item");
    let drifted = fs::read_to_string(&fx.vault.path).unwrap();

    let committed = fx.write(|_| Ok(())).unwrap();

    assert_eq!(committed.sync_status, stopped());
    assert!(!committed.changed);
    let (local, state) = saved(&fx);
    assert_eq!(state, before);
    assert_eq!(local.stopped_build.as_deref(), Some(BUILD_ID));
    // Only the header changed, so `s` is kept.
    assert_eq!(local.generation, before_local.generation);
    assert_eq!(local.published_context, before_local.published_context);
    assert_eq!(local.staged_hash, None);
    assert_eq!(transport.writes(), writes);
    // The drifted vault is kept as it is.
    assert_eq!(fs::read_to_string(&fx.vault.path).unwrap(), drifted);
    assert_eq!(fx.read_case(), SyncLoad::Current);
    fx.read().unwrap();

    // Sync stays stopped, and a transaction with no change saves nothing.
    let before = fx.on_disk();
    let committed = fx.write(|_| Ok(())).unwrap();
    assert_eq!(committed.sync_status, stopped());
    assert_eq!(fx.on_disk(), before);
}

#[test]
fn transaction_with_requested_change_on_drifted_vault_records_neither_and_saves_change_locally() {
    let transport = Arc::new(FakeTransport::default());
    let fx = published_vault(&transport);
    let (before_local, before) = saved(&fx);
    let files = published(&transport, &fx);
    let staged = fs::read(LocalSyncState::staged_path(&fx.root, fx.id())).ok();
    drift(&fx, "item");

    let committed = add(&fx, "second").unwrap();

    assert_eq!(committed.sync_status, stopped());
    assert!(committed.changed);
    let (local, state) = saved(&fx);
    // Neither the drift nor the change is recorded, and no write id is
    // minted.
    assert_eq!(state, before);
    assert!(new_write_ids(&before, &state).is_empty());
    assert_eq!(local.stopped_build.as_deref(), Some(BUILD_ID));
    // The change is saved locally with `v = s`, at the next generation.
    let vault = saved_vault(&fx);
    assert!(vault.get_item("second").is_ok());
    assert_eq!(vault.get_item("item").unwrap().title, "Drifted");
    assert_eq!(local.generation, before_local.generation + 1);
    assert_eq!(vault.generation(), local.generation);
    assert_eq!(fx.read_case(), SyncLoad::Current);
    // Nothing is staged or published.
    assert_eq!(published(&transport, &fx), files);
    assert_eq!(local.staged_hash, None);
    assert_eq!(
        fs::read(LocalSyncState::staged_path(&fx.root, fx.id())).ok(),
        staged
    );
}

#[test]
fn stopped_vault_saves_locally_joins_no_file_and_publishes_nothing() {
    let transport = Arc::new(FakeTransport::default());
    let fx = published_vault(&transport);
    drift(&fx, "item");
    fx.write(|_| Ok(())).unwrap();
    let (_, before) = saved(&fx);
    let sidecar = Sidecar::load(&fx.root, fx.id());
    let peer = peer_state(&fx, PEER, "joined");
    transport.put_state(fx.id(), PEER, &state_file(&fx, PEER, &peer));
    let writes = transport.writes();

    let committed = add(&fx, "second").unwrap();

    assert_eq!(committed.sync_status, stopped());
    assert_eq!(saved(&fx).1, before);
    let vault = saved_vault(&fx);
    assert!(vault.get_item("joined").is_err());
    assert!(vault.get_item("second").is_ok());
    assert_eq!(transport.writes(), writes);
    assert_eq!(Sidecar::load(&fx.root, fx.id()), sidecar);
}

#[test]
fn while_stopped_by_drift_each_save_advances_s_and_older_vault_copy_not_rebuilt() {
    let transport = Arc::new(FakeTransport::default());
    let fx = published_vault(&transport);
    drift(&fx, "item");
    fx.write(|_| Ok(())).unwrap();
    let (stopped_local, body) = saved(&fx);
    let s = stopped_local.generation;

    add(&fx, "first").unwrap();
    assert_eq!(saved(&fx).0.generation, s + 1);
    assert_eq!(saved_vault(&fx).generation(), s + 1);
    let older = fs::read_to_string(&fx.vault.path).unwrap();
    add(&fx, "second").unwrap();
    assert_eq!(saved(&fx).0.generation, s + 2);
    assert_eq!(saved_vault(&fx).generation(), s + 2);

    // An older copy of the vault from the stopped period is put in place.
    fs::write(&fx.vault.path, &older).unwrap();

    let case = SyncLoad::StoppedOlderVault {
        vault: s + 1,
        state: s + 2,
    };
    assert_eq!(fx.read_case(), case);
    assert_eq!(fx.write_case(), case);
    let vh = fx.read().unwrap();
    assert!(vh.get_item_overview("first").unwrap().is_some());

    let committed = add(&fx, "third").unwrap();

    // The vault is not rebuilt from the sync state, which holds none of the
    // edits saved while stopped. The save advances `s`.
    assert_eq!(committed.sync_status, stopped());
    let (local, state) = saved(&fx);
    assert_eq!(state, body);
    assert_eq!(local.generation, s + 3);
    let vault = saved_vault(&fx);
    assert_eq!(vault.generation(), s + 3);
    assert_eq!(vault.get_item("item").unwrap().title, "Drifted");
    assert!(vault.get_item("first").is_ok());
    assert!(vault.get_item("third").is_ok());
    // The older copy it replaced is retained.
    let versions = fx.catalog.files().list_versions(fx.id()).unwrap();
    let newest = fx
        .root
        .join("versions")
        .join(ShortId::encode_uuid(fx.id()))
        .join(&versions[0].name);
    assert_eq!(fs::read_to_string(newest).unwrap(), older);
    assert_eq!(fx.read_case(), SyncLoad::Current);
}

#[test]
fn after_join_that_changes_view_guard_finds_no_edits() {
    let transport = Arc::new(FakeTransport::default());
    let fx = published_vault(&transport);
    let peer = peer_state(&fx, PEER, "joined");
    transport.put_state(fx.id(), PEER, &state_file(&fx, PEER, &peer));

    let committed = fx.write(|_| Ok(())).unwrap();

    assert!(committed.changed);
    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    assert!(saved_vault(&fx).get_item("joined").is_ok());
    let committed = add(&fx, "second").unwrap();
    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    let (local, state) = saved(&fx);
    assert_eq!(local.stopped_build, None);
    assert_eq!(new_write_ids(&peer, &state).len(), 1);
    assert_eq!(local.generation, GENERATION + 3);
    assert_eq!(saved_vault(&fx).replica_id(), Some(REPLICA.0));
}
