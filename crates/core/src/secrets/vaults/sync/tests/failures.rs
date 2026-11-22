//! Apply failures, diff failures, and version skew as paused failures.
//!
//! A build whose view cannot apply a state is a writer with an apply fault
//! for items titled [`UNAPPLICABLE`]. The writer without the fault stands for
//! a later build with a fixed view, with no change to the state.

use std::fs;
use std::sync::Arc;

use uuid::Uuid;

use super::NOW;
use super::guard::add;
use super::join::{PEER, with_format_version};
use super::load::{Fixture, GENERATION, REPLICA};
use super::publish::{last_publish, published};
use super::transport::FakeTransport;
use super::txn::{
    joined_vault, new_write_ids, own_file, own_state, saved, saved_vault, state_file, synced,
};
use super::view::State;
use crate::secrets::vaults::autofill::item::{ItemAutofill, MatchKind, Website};
use crate::secrets::vaults::storage::txn::{Committed, Target, Unlock};
use crate::secrets::vaults::sync::crdt::{ReplicaId, Session, WriteId};
use crate::secrets::vaults::sync::diff::LocalEdits;
use crate::secrets::vaults::sync::load::SyncLoad;
use crate::secrets::vaults::sync::sidecar::{Health, Sidecar};
use crate::secrets::vaults::sync::state_file::StateFile;
use crate::secrets::vaults::sync::status::{PausedCause, SyncStatus};
use crate::secrets::vaults::sync::view::{ItemView, VaultView};
use crate::secrets::vaults::{Error, VaultHandle};

/// Replica of a third Mac.
const OTHER_PEER: ReplicaId = ReplicaId(Uuid::from_u128(3));

/// Title of the items that the faulty build cannot apply.
const UNAPPLICABLE: &str = "Unapplicable";

fn unapplicable(item: &ItemView) -> bool {
    item.title == UNAPPLICABLE
}

/// Run `f` in a transaction on the vault of `fx`, on a build that cannot
/// apply items titled [`UNAPPLICABLE`].
fn on_faulty_build(
    fx: &Fixture,
    f: impl FnOnce(&mut VaultHandle) -> Result<(), Error>,
) -> Result<Committed<()>, Error> {
    let key = || fx.vault.unlocked_key().unwrap();
    fx.catalog
        .files()
        .clone()
        .with_apply_fault(Some(unapplicable))
        .write(&Target::of(&fx.vault), Unlock::Test(&key), f)
}

/// State of a new session of `replica`: the saved sync state of `fx` with
/// the vault renamed and item `joined` titled `title` added.
fn peer_state(fx: &Fixture, replica: ReplicaId, title: &str) -> State {
    let mut state = saved(fx).1;
    let mut vault = saved_vault(fx);
    vault.name = Some("Renamed".to_string());
    vault.add_or_update_item("joined", title).unwrap();
    let edits = LocalEdits::find(&state, &vault, replica).unwrap();
    assert!(
        edits
            .record(&mut state, &mut Session::new(replica), NOW)
            .is_some()
    );
    state
}

fn sidecar(fx: &Fixture) -> Sidecar {
    Sidecar::load(&fx.root, fx.id())
}

fn paused(fx: &Fixture) -> Vec<PausedCause> {
    sidecar(fx).paused().to_vec()
}

fn apply_failed(fx: &Fixture) -> bool {
    matches!(&paused(fx)[..], [PausedCause::ApplyFailed { .. }])
}

/// Assert that `committed`, a transaction on the faulty build, paused sync on
/// an apply failure.
fn assert_apply_paused(fx: &Fixture, committed: &Committed<()>) {
    assert!(apply_failed(fx), "{:?}", paused(fx));
    assert_eq!(committed.sync_status, Some(SyncStatus::Paused(paused(fx))));
}

/// Run a transaction on a build with a fixed view, and assert that sync is
/// active with no paused cause.
fn fixed_build(fx: &Fixture) {
    let committed = fx.write(|_| Ok(())).unwrap();
    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    assert!(paused(fx).is_empty());
}

/// Write ids that `state` holds and `before` lacks, minted by `replica`.
fn minted_by(before: &State, state: &State, replica: ReplicaId) -> Vec<WriteId> {
    new_write_ids(before, state)
        .into_iter()
        .filter(|write_id| state.actors[&write_id.actor].replica == replica)
        .collect()
}

fn assert_no_edits(fx: &Fixture) {
    let (_, state) = saved(fx);
    let edits = LocalEdits::find(&state, &saved_vault(fx), REPLICA).unwrap();
    assert!(edits.is_empty(), "{:?}", edits.edits());
}

/// Give item `key` of `vh` the websites `urls`, with no check for a repeated
/// URL.
fn set_websites(vh: &mut VaultHandle, key: &str, urls: &[&str]) -> Result<(), Error> {
    let autofill = ItemAutofill {
        websites: urls
            .iter()
            .map(|url| Website::new(*url, MatchKind::Domain))
            .collect(),
        ..ItemAutofill::default()
    };
    vh.get_unlocked_vault_mut()?
        .set_item_autofill_unchecked_for_test(key, autofill);
    Ok(())
}

#[test]
fn apply_failure_saves_local_edit_and_requested_change_and_fixed_build_joins_with_no_merge() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let (_, loaded) = saved(&fx);
    let peer = peer_state(&fx, PEER, UNAPPLICABLE);
    let peer_hash = transport.put_state(fx.id(), PEER, &state_file(&fx, PEER, &peer));

    let committed = on_faulty_build(&fx, |vh| vh.add_item("mine", "Mine").map(|_| ())).unwrap();

    assert_apply_paused(&fx, &committed);
    // The requested change is saved on the vault as it was before the join.
    // The vault name that the failed apply wrote is not kept.
    let vault = saved_vault(&fx);
    assert!(vault.get_item("mine").is_ok());
    assert!(vault.get_item("joined").is_err());
    assert_eq!(vault.name, None);
    assert_eq!(vault.generation(), GENERATION + 1);
    // The sync state holds only the local edit, and the vault equals its
    // view.
    let (local, recorded) = saved(&fx);
    assert_eq!(local.generation, GENERATION + 1);
    assert_eq!(new_write_ids(&loaded, &recorded).len(), 1);
    assert_eq!(minted_by(&loaded, &recorded, REPLICA).len(), 1);
    assert_no_edits(&fx);
    // The discarded join is not recorded, and the local edit is published.
    assert!(!sidecar(&fx).is_joined(PEER, peer_hash));
    assert!(last_publish(&fx).is_some());
    assert_eq!(last_publish(&fx), local.staged_hash);

    // Each later transaction joins the file again.
    let reads = transport.reads();
    on_faulty_build(&fx, |_| Ok(())).unwrap();
    assert_eq!(transport.reads(), reads + 1);
    assert!(apply_failed(&fx), "{:?}", paused(&fx));
    assert_eq!(saved(&fx).1, recorded);
    assert!(saved_vault(&fx).get_item("joined").is_err());

    // A later build with a fixed view joins the file with no recovery merge.
    fixed_build(&fx);

    let vault = saved_vault(&fx);
    assert!(vault.get_item("mine").is_ok());
    assert!(vault.get_item("joined").is_ok());
    assert_eq!(vault.name.as_deref(), Some("Renamed"));
    let (local, state) = saved(&fx);
    assert_eq!(local.stopped_build, None);
    assert!(minted_by(&recorded, &state, REPLICA).is_empty());
    assert!(!new_write_ids(&recorded, &state).is_empty());
    assert!(VaultView::of(&state).conflicts().is_empty());
    assert_no_edits(&fx);
    assert!(sidecar(&fx).is_joined(PEER, peer_hash));
}

#[test]
fn apply_failure_after_recorded_edit_keeps_edit_and_saves_vault_as_change_left_it() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let (_, loaded) = saved(&fx);

    let committed =
        on_faulty_build(&fx, |vh| vh.add_item("mine", UNAPPLICABLE).map(|_| ())).unwrap();

    assert_apply_paused(&fx, &committed);
    assert!(saved_vault(&fx).get_item("mine").is_ok());
    let (local, recorded) = saved(&fx);
    assert_eq!(minted_by(&loaded, &recorded, REPLICA).len(), 1);
    assert_no_edits(&fx);
    assert_eq!(last_publish(&fx), local.staged_hash);

    // A later build finds no edits and records nothing.
    fixed_build(&fx);

    assert_eq!(saved(&fx).1, recorded);
}

#[test]
fn apply_failure_in_rebuild_uses_loaded_sync_state() {
    let transport = Arc::new(FakeTransport::default());
    let fx = Fixture::with_transport(GENERATION, Some(REPLICA), transport.clone());
    fx.put_state(GENERATION + 1);
    assert!(matches!(fx.write_case(), SyncLoad::OlderVault { .. }));
    let peer = peer_state(&fx, PEER, UNAPPLICABLE);
    let peer_hash = transport.put_state(fx.id(), PEER, &state_file(&fx, PEER, &peer));

    let committed = on_faulty_build(&fx, |vh| vh.add_item("mine", "Mine").map(|_| ())).unwrap();

    assert_apply_paused(&fx, &committed);
    let vault = saved_vault(&fx);
    assert!(vault.get_item("mine").is_ok());
    assert!(vault.get_item("joined").is_err());
    assert_eq!(vault.generation(), GENERATION + 2);
    assert_eq!(saved(&fx).0.generation, GENERATION + 2);
    assert_no_edits(&fx);
    assert!(!sidecar(&fx).is_joined(PEER, peer_hash));
}

#[test]
fn apply_failure_in_v_greater_than_s_repair_saves_vault_only_and_fixed_build_repairs() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    fx.add_item().unwrap();
    fx.write(|_| Ok(())).unwrap();
    let backup = fs::read_to_string(fx.state_path()).unwrap();
    let peer = peer_state(&fx, PEER, UNAPPLICABLE);
    transport.set_unavailable(true);
    add(&fx, "unpublished").unwrap();
    transport.set_unavailable(false);
    fx.put_text(&backup);
    let SyncLoad::NewerVault { vault: v, state: s } = fx.write_case() else {
        panic!("not a newer vault");
    };
    transport.put_state(fx.id(), PEER, &state_file(&fx, PEER, &peer));
    let on_disk = fx.on_disk();

    let committed = on_faulty_build(&fx, |_| Ok(())).unwrap();

    // The repair is discarded with the join, and nothing is saved.
    assert_apply_paused(&fx, &committed);
    assert!(!committed.changed);
    assert_eq!(fx.on_disk(), on_disk);

    // A change is saved in the vault only, which is still newer than the
    // sync state.
    on_faulty_build(&fx, |vh| vh.add_item("second", "Second").map(|_| ())).unwrap();

    assert!(apply_failed(&fx), "{:?}", paused(&fx));
    let case = SyncLoad::NewerVault {
        vault: v + 1,
        state: s,
    };
    assert_eq!(fx.write_case(), case);
    assert_eq!(fs::read_to_string(fx.state_path()).unwrap(), backup);

    // A later build runs the repair and joins the file.
    fixed_build(&fx);

    let vault = saved_vault(&fx);
    for key in ["item", "unpublished", "second", "joined"] {
        assert!(vault.get_item(key).is_ok(), "{key}");
    }
    assert_eq!(vault.generation(), v + 2);
    assert_eq!(saved(&fx).0.generation, v + 2);
    assert_no_edits(&fx);
}

#[test]
fn diff_failure_saves_change_in_vault_only_and_v_greater_than_s_repair_records_it_once_diff_succeeds()
 {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let loaded = fs::read_to_string(fx.state_path()).unwrap();

    let committed = fx
        .write(|vh| {
            vh.add_item("item", "Item")?;
            set_websites(vh, "item", &["a.com", "a.com"])
        })
        .unwrap();

    assert!(
        matches!(&paused(&fx)[..], [PausedCause::DiffFailed { .. }]),
        "{:?}",
        paused(&fx)
    );
    assert_eq!(committed.sync_status, Some(SyncStatus::Paused(paused(&fx))));
    // The vault is saved alone at the next generation, and nothing is
    // published.
    assert_eq!(fs::read_to_string(fx.state_path()).unwrap(), loaded);
    let case = SyncLoad::NewerVault {
        vault: GENERATION + 1,
        state: GENERATION,
    };
    assert_eq!(fx.write_case(), case);
    assert!(saved_vault(&fx).get_item("item").is_ok());
    assert!(last_publish(&fx).is_none());
    assert!(published(&transport, &fx).is_empty());

    // While the diff fails, the repair saves the vault only.
    fx.write(|vh| set_websites(vh, "item", &["a.com"])).unwrap();

    assert!(matches!(&paused(&fx)[..], [PausedCause::DiffFailed { .. }]));
    let case = SyncLoad::NewerVault {
        vault: GENERATION + 2,
        state: GENERATION,
    };
    assert_eq!(fx.write_case(), case);

    // Once the diff succeeds, the repair records the vault.
    fixed_build(&fx);

    assert_eq!(saved(&fx).0.generation, GENERATION + 3);
    assert_eq!(saved_vault(&fx).generation(), GENERATION + 3);
    assert_no_edits(&fx);
    assert!(last_publish(&fx).is_some());
}

#[test]
fn while_peer_file_has_newer_format_local_edits_recorded_other_peers_join_and_replica_publishes() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let (_, loaded) = saved(&fx);
    let peer = peer_state(&fx, PEER, "Joined");
    let newer = with_format_version(&state_file(&fx, PEER, &peer), 2);
    let newer_hash = transport.put_state(fx.id(), PEER, &newer);
    let other = super::join::peer_state(&fx, OTHER_PEER, "other");
    transport.put_state(fx.id(), OTHER_PEER, &state_file(&fx, OTHER_PEER, &other));

    let committed = fx.add_item().unwrap();

    let skew = vec![PausedCause::VersionSkew { files: 1 }];
    assert_eq!(paused(&fx), skew);
    assert_eq!(
        committed.sync_status,
        Some(SyncStatus::Paused(skew.clone()))
    );
    let vault = saved_vault(&fx);
    assert!(vault.get_item("item").is_ok());
    assert!(vault.get_item("other").is_ok());
    assert!(vault.get_item("joined").is_err());
    let first = last_publish(&fx).unwrap();
    assert!(published(&transport, &fx).contains(&first));

    let committed = add(&fx, "second").unwrap();

    assert_eq!(committed.sync_status, Some(SyncStatus::Paused(skew)));
    let (local, recorded) = saved(&fx);
    assert_eq!(minted_by(&loaded, &recorded, REPLICA).len(), 2);
    assert_ne!(last_publish(&fx), Some(first));
    assert_eq!(last_publish(&fx), local.staged_hash);

    // After the update, the newer file joins. The same state in this format
    // stands for the file as a build that reads the newer format sees it.
    transport.remove(fx.id(), PEER, &StateFile::name(newer_hash));
    transport.put_state(fx.id(), PEER, &state_file(&fx, PEER, &peer));

    fixed_build(&fx);

    let vault = saved_vault(&fx);
    for key in ["item", "second", "other", "joined"] {
        assert!(vault.get_item(key).is_ok(), "{key}");
    }
    let (_, state) = saved(&fx);
    assert!(minted_by(&recorded, &state, REPLICA).is_empty());
    assert!(VaultView::of(&state).conflicts().is_empty());
    assert_no_edits(&fx);
}

#[test]
fn own_file_of_newer_format_pauses_sync_and_not_deleted() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let own = own_state(&fx, &joined_vault(), &mut Session::new(REPLICA));
    let newer = with_format_version(&own_file(&fx, &own), 2);
    let newer_hash = transport.put_state(fx.id(), REPLICA, &newer);

    let committed = fx.add_item().unwrap();

    let skew = vec![PausedCause::VersionSkew { files: 1 }];
    assert_eq!(committed.sync_status, Some(SyncStatus::Paused(skew)));
    assert!(saved_vault(&fx).get_item("joined").is_err());
    // The edit is published, and the own file of the newer format is kept.
    let listed = published(&transport, &fx);
    assert_eq!(listed.len(), 2);
    assert!(listed.contains(&newer_hash));
    assert!(listed.contains(&last_publish(&fx).unwrap()));
}

#[test]
fn paused_causes_of_failures_have_tagged_form_and_earlier_sidecar_parses() {
    let causes = vec![
        PausedCause::VersionSkew { files: 2 },
        PausedCause::ApplyFailed {
            error: "apply".to_string(),
        },
        PausedCause::DiffFailed {
            error: "diff".to_string(),
        },
    ];
    let json = serde_json::to_value(&causes).unwrap();
    assert_eq!(
        json,
        serde_json::json!([
            { "cause": "version_skew", "files": 2 },
            { "cause": "apply_failed", "error": "apply" },
            { "cause": "diff_failed", "error": "diff" },
        ])
    );
    assert_eq!(
        serde_json::from_value::<Vec<PausedCause>>(json).unwrap(),
        causes
    );

    // A sidecar with paused causes parses, and a sidecar with no health is
    // `Ok`.
    let paused = r#"{
        "last_publish": null,
        "joined": {},
        "quarantined": [],
        "health": { "state": "paused", "causes": [{ "cause": "quarantined", "files": 1 }] }
    }"#;
    let sidecar: Sidecar = serde_json::from_str(paused).unwrap();
    assert_eq!(sidecar.paused(), [PausedCause::Quarantined { files: 1 }]);
    let bare = r#"{ "last_publish": null, "joined": {}, "quarantined": [] }"#;
    let sidecar: Sidecar = serde_json::from_str(bare).unwrap();
    assert_eq!(sidecar.health, Health::Ok);
}
