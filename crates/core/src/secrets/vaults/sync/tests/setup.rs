//! Sync setup: the kit before any write, the own registers, `meta.json`, the
//! first state, and `key.json` (10.1).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};

use tempfile::TempDir;

use super::load::{
    Fixture, GENERATION, REPLICA, assert_nothing_written, device_key, state, sync_files,
};
use super::manager::{Event, Managed};
use super::recovery::{ages, key_file};
use super::transport::FakeTransport;
use super::txn::{new_write_ids, saved_vault};
use super::view::State;
use crate::secrets::vaults::autofill::item::{ItemAutofill, MatchKind, Website};
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::storage::txn::{Committed, Target, Unlock};
use crate::secrets::vaults::sync::crdt::CausalStore;
use crate::secrets::vaults::sync::diff::LocalEdits;
use crate::secrets::vaults::sync::keys::{SyncKeyring, TestKeyWrapper};
use crate::secrets::vaults::sync::load::SyncLoad;
use crate::secrets::vaults::sync::local_state::LocalSyncState;
use crate::secrets::vaults::sync::meta::MetaFile;
use crate::secrets::vaults::sync::model::{ItemId, KeyId, PublicKey, ReplicaKeys};
use crate::secrets::vaults::sync::recovery::SETUP_KIT_LABEL;
use crate::secrets::vaults::sync::recovery::import::{RecoveryCheck, RecoveryImport};
use crate::secrets::vaults::sync::setup::{SetupStart, SyncSetup};
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::state_file::{StateFile, StateHash};
use crate::secrets::vaults::sync::status::{PausedCause, SyncStatus};
use crate::secrets::vaults::sync::transport::folder::FolderTransport;
use crate::secrets::vaults::sync::transport::folder::io::PlainIo;
use crate::secrets::vaults::sync::transport::{SyncTransport, TransportRoot};
use crate::secrets::vaults::sync::view::VaultView;
use crate::secrets::vaults::{Error, VaultHandle};

/// Display name of this Mac.
const MAC: &str = "Work Mac";

/// Root of the synced folder of the setup tests.
fn root() -> TransportRoot {
    TransportRoot::Folder {
        path: PathBuf::from("/setup/Vaults"),
    }
}

/// Vault that is not synced, with the synced folder `transport`.
fn unsynced(transport: Arc<dyn SyncTransport>) -> Fixture {
    Fixture::with_transport(0, None, transport)
}

/// Start the setup of the vault of `fx` with the synced folder `root`.
fn prepare(fx: &Fixture, root: TransportRoot) -> Result<SetupStart, Error> {
    SyncSetup::prepare(fx.catalog.files(), &Target::of(&fx.vault), root, MAC)
}

/// Setup of the vault of `fx` with [`root`], or a panic if it offers the
/// join.
fn prepared(fx: &Fixture) -> SyncSetup {
    match prepare(fx, root()).unwrap() {
        SetupStart::Kit(setup) => setup,
        SetupStart::Join(root) => panic!("setup offered the join of {root}"),
    }
}

/// Confirm `setup` on the vault of `fx`.
fn confirm(fx: &Fixture, setup: &SyncSetup) -> Result<Committed<Vec<ItemId>>, Error> {
    let unlock = || fx.vault.unlocked_key().unwrap();
    setup.confirm(
        fx.catalog.files(),
        &Target::of(&fx.vault),
        Unlock::Test(&unlock),
    )
}

/// Sync state of `fx` as saved, and its body, opened with the keyring it
/// holds.
fn opened(fx: &Fixture) -> (LocalSyncState, State) {
    let local = LocalSyncState::load(&fx.root, fx.id(), &TestSigner::device()).unwrap();
    let keyring = SyncKeyring::unwrap(&local.sync_keys, &TestKeyWrapper).unwrap();
    let state = local.open(&keyring).unwrap();
    (local, state)
}

/// Fill the vault of `fx` with live and trashed entries in a transaction.
fn fill(fx: &Fixture) {
    fx.write(|vh| {
        vh.get_unlocked_vault_mut()?.fill_for_test();
        Ok(())
    })
    .unwrap();
}

/// Autofill with a website of each of `urls`, matched as `kinds` gives.
fn websites(urls: &[(&str, MatchKind)]) -> ItemAutofill {
    ItemAutofill {
        websites: urls
            .iter()
            .map(|(url, kind)| Website::new(*url, *kind))
            .collect(),
        ..ItemAutofill::default()
    }
}

/// Names of the replica directory of vault `vault_id` after a publish of
/// the state file with hash `published`, in order: the state file and
/// `key.json`.
fn published_names(published: StateHash) -> Vec<String> {
    let mut names = vec![StateFile::name(published), "key.json".to_string()];
    names.sort();
    names
}

/// App data files of `fx` that a setup writes: the sync state, the staged
/// file, and the sidecar.
#[test]
fn enable_writes_meta_key_json_with_one_age_wrapping_and_one_state_file_at_generation_1() {
    let transport = Arc::new(FakeTransport::default());
    let fx = unsynced(transport.clone());
    fill(&fx);
    let setup = prepared(&fx);
    let committed = confirm(&fx, &setup).unwrap();
    let replica = setup.replica_id();

    assert!(committed.changed);
    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    assert!(!committed.recovery_kit_missing);
    assert_eq!(
        transport.meta(fx.id()),
        Some(MetaFile::new(fx.id()).to_bytes())
    );
    assert_eq!(
        ages(&transport, fx.id(), replica),
        [(setup.kit().recipient(), KeyId(1))]
    );
    assert_eq!(
        key_file(&transport, fx.id(), replica)
            .unwrap()
            .devices()
            .count(),
        0
    );

    let sidecar = Sidecar::load(&fx.root, fx.id());
    assert_eq!(sidecar.transport, Some(root()));
    let published = sidecar.last_publish.unwrap();
    let mut names = transport.names(fx.id(), replica);
    names.sort();
    assert_eq!(names, published_names(published));

    let (local, _) = opened(&fx);
    assert_eq!(local.generation, 1);
    assert_eq!(local.replica_id, replica);
    assert_eq!(local.key_id, KeyId(1));
    assert!(!local.leaving);
    let vault = saved_vault(&fx);
    assert_eq!(vault.generation(), 1);
    assert_eq!(vault.replica_id(), Some(replica.0));
}

#[test]
fn first_state_holds_own_name_keys_recipient_and_every_entry_under_one_write_id() {
    let transport = Arc::new(FakeTransport::default());
    let fx = unsynced(transport);
    fill(&fx);
    let setup = prepared(&fx);
    confirm(&fx, &setup).unwrap();
    let replica = setup.replica_id();
    let (_, state) = opened(&fx);

    assert_eq!(new_write_ids(&State::default(), &state).len(), 1);
    assert_eq!(state.actors.len(), 1);
    assert_eq!(
        state.store.replica_names.get(&replica).unwrap().shown(),
        Some(&MAC.to_string())
    );
    let keys = ReplicaKeys {
        encryption: TestKeyWrapper::public_key(),
        signing: PublicKey(device_key()),
    };
    assert_eq!(
        state.store.replica_keys.get(&replica).unwrap().shown(),
        Some(&keys)
    );
    assert_eq!(
        state
            .store
            .recovery
            .get(&setup.kit().recipient())
            .unwrap()
            .shown(),
        Some(&setup.kit().recipient_value())
    );
    assert_eq!(setup.kit().label.as_deref(), Some(SETUP_KIT_LABEL));
    assert!(state.store.left.is_empty());

    // The view holds every live and trashed entry of the vault.
    let vault = saved_vault(&fx);
    let view = VaultView::of(&state);
    let entries = vault.sync_entries().unwrap();
    assert_eq!(view.items.len(), entries.items.len());
    assert_eq!(view.credentials.len(), entries.credentials.len());
    assert!(view.items.values().any(|item| item.trashed.is_some()));
    assert!(
        LocalEdits::find(&state, &vault, replica)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn next_load_trusts_sync_state_and_next_transaction_finds_no_drift_and_publishes_nothing() {
    let transport = Arc::new(FakeTransport::default());
    let fx = unsynced(transport.clone());
    fill(&fx);
    let setup = prepared(&fx);
    confirm(&fx, &setup).unwrap();
    let names = transport.names(fx.id(), setup.replica_id());
    let writes = transport.writes();
    let (_, before) = opened(&fx);

    assert_eq!(fx.read_case(), SyncLoad::Current);
    assert_eq!(fx.write_case(), SyncLoad::Current);
    let committed = fx.write(|_| Ok(())).unwrap();

    assert!(!committed.changed);
    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    assert_eq!(transport.names(fx.id(), setup.replica_id()), names);
    assert_eq!(transport.writes(), writes);
    let (local, state) = opened(&fx);
    assert_eq!(state, before);
    assert_eq!(local.stopped_build, None);
    assert_eq!(local.generation, 1);
}

#[test]
fn kit_made_by_setup_opens_key_through_age_import() {
    let transport = Arc::new(FakeTransport::default());
    let fx = unsynced(transport.clone());
    let setup = prepared(&fx);
    confirm(&fx, &setup).unwrap();

    match RecoveryImport::check(setup.kit(), &*transport).unwrap() {
        RecoveryCheck::Recovered(recovered) => {
            assert_eq!(recovered.vault_id, fx.id());
            assert_eq!(recovered.key_id, KeyId(1));
            assert_eq!(recovered.key.as_bytes(), setup.key().as_bytes());
        },
        other => panic!("kit did not open the key: {other:?}"),
    }
    assert!(!fx.write(|_| Ok(())).unwrap().recovery_kit_missing);
}

#[test]
fn prepare_without_confirm_writes_nothing() {
    let transport = Arc::new(FakeTransport::default());
    let fx = unsynced(transport.clone());
    let on_disk = fx.on_disk();

    let setup = prepared(&fx);
    assert_eq!(setup.vault_id(), fx.id());
    assert_eq!(setup.kit().vault_id, fx.id());
    assert!(setup.kit().opens(setup.key()));
    drop(setup);

    assert_nothing_written(&fx, &on_disk);
    assert_eq!(transport.writes(), 0);
    assert_eq!(transport.meta(fx.id()), None);
    assert_eq!(fx.read_case(), SyncLoad::NotSynced);
}

#[test]
fn replica_or_leaving_state_vault_refused() {
    let transport = Arc::new(FakeTransport::default());
    let fx = Fixture::with_transport(GENERATION, Some(REPLICA), transport.clone());
    assert!(matches!(
        prepare(&fx, root()),
        Err(Error::SyncAlreadyEnabled)
    ));

    let fx = unsynced(transport.clone());
    fx.put_state(GENERATION);
    assert!(matches!(
        prepare(&fx, root()),
        Err(Error::SyncAlreadyEnabled)
    ));

    // A sync state that fails its signature is refused too.
    let fx = unsynced(transport.clone());
    fx.put_foreign_state();
    assert!(matches!(
        prepare(&fx, root()),
        Err(Error::SyncAlreadyEnabled)
    ));

    let fx = unsynced(transport.clone());
    let mut leaving = state(fx.id(), REPLICA, GENERATION);
    leaving.leaving = true;
    fx.put(&leaving, &TestSigner::device());
    assert!(matches!(
        prepare(&fx, root()),
        Err(Error::SyncDisableInProgress)
    ));
    assert_eq!(transport.writes(), 0);
}

#[test]
fn sync_state_written_after_prepare_refused_at_confirm_and_nothing_written() {
    let transport = Arc::new(FakeTransport::default());
    let fx = unsynced(transport.clone());
    let setup = prepared(&fx);
    let mut leaving = state(fx.id(), REPLICA, GENERATION);
    leaving.leaving = true;
    fx.put(&leaving, &TestSigner::device());
    let on_disk = fx.on_disk();

    assert!(matches!(
        confirm(&fx, &setup),
        Err(Error::SyncDisableInProgress)
    ));
    assert_eq!(fx.on_disk(), on_disk);
    assert_eq!(transport.writes(), 0);
}

#[test]
fn folder_that_holds_vault_gives_join_offer_and_one_that_gains_it_after_prepare_refused() {
    let transport = Arc::new(FakeTransport::default());
    let fx = unsynced(transport.clone());
    let setup = prepared(&fx);
    transport.put_meta(fx.id(), &MetaFile::new(fx.id()).to_bytes());

    match prepare(&fx, root()).unwrap() {
        SetupStart::Join(offered) => assert_eq!(offered, root()),
        SetupStart::Kit(_) => panic!("setup gave a kit for a folder that holds the vault"),
    }

    let on_disk = fx.on_disk();
    assert!(matches!(
        confirm(&fx, &setup),
        Err(Error::SyncFolderHasVault)
    ));
    assert_nothing_written(&fx, &on_disk);
    assert_eq!(transport.writes(), 0);
}

#[test]
fn malformed_meta_json_fails_setup_before_any_write() {
    let transport = Arc::new(FakeTransport::default());
    let fx = unsynced(transport.clone());
    transport.put_meta(fx.id(), b"{\"format_version\":1}");

    assert!(matches!(
        prepare(&fx, root()),
        Err(Error::SyncTransportError(_))
    ));
    assert_eq!(transport.writes(), 0);
    assert_eq!(sync_files(&fx), [false; 3]);
}

#[test]
fn failed_meta_json_write_fails_setup_before_any_local_save() {
    let transport = Arc::new(FakeTransport::default());
    let fx = unsynced(transport.clone());
    let setup = prepared(&fx);
    let on_disk = fx.on_disk();
    transport.set_failing_writes(true);

    assert!(matches!(
        confirm(&fx, &setup),
        Err(Error::SyncTransportError(_))
    ));
    assert_nothing_written(&fx, &on_disk);

    // The same kit enables sync once the folder takes writes.
    transport.set_failing_writes(false);
    confirm(&fx, &setup).unwrap();
    assert_eq!(fx.read_case(), SyncLoad::Current);
}

#[test]
fn failed_key_json_write_and_copy_after_saves_pause_sync_and_next_transaction_completes_them() {
    let transport = Arc::new(FakeTransport::default());
    let fx = unsynced(transport.clone());
    let setup = prepared(&fx);
    // Every write after `meta.json` fails.
    let weak: Weak<FakeTransport> = Arc::downgrade(&transport);
    let calls = AtomicUsize::new(0);
    transport.on_write(move |_| {
        if calls.fetch_add(1, Ordering::SeqCst) == 1
            && let Some(transport) = weak.upgrade()
        {
            transport.set_failing_writes(true);
        }
    });

    let committed = confirm(&fx, &setup).unwrap();
    assert!(matches!(
        committed.sync_status,
        Some(SyncStatus::Paused(ref causes))
            if matches!(causes[..], [PausedCause::PublishFailed { .. }])
    ));
    assert!(transport.meta(fx.id()).is_some());
    assert_eq!(
        transport.names(fx.id(), setup.replica_id()),
        Vec::<String>::new()
    );
    assert_eq!(fx.read_case(), SyncLoad::Current);
    assert_eq!(Sidecar::load(&fx.root, fx.id()).transport, Some(root()));

    transport.set_failing_writes(false);
    transport.on_write(|_| {});
    let committed = fx.write(|_| Ok(())).unwrap();
    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    assert_eq!(
        ages(&transport, fx.id(), setup.replica_id()),
        [(setup.kit().recipient(), KeyId(1))]
    );
    assert_eq!(transport.names(fx.id(), setup.replica_id()).len(), 2);
}

#[test]
fn single_url_websites_removed_at_enable() {
    let transport = Arc::new(FakeTransport::default());
    let fx = unsynced(transport);
    let duplicated = websites(&[
        ("a.com", MatchKind::Domain),
        ("b.com", MatchKind::Domain),
        ("a.com", MatchKind::Host),
    ]);
    fx.write(|vh| {
        vh.add_item("web", "Web")?;
        vh.add_item("old", "Old")?;
        vh.add_item("plain", "Plain")?;
        let vault = vh.get_unlocked_vault_mut()?;
        vault.set_item_autofill_unchecked_for_test("web", duplicated.clone());
        vault.set_item_autofill_unchecked_for_test("old", duplicated.clone());
        vh.delete_item("old")
    })
    .unwrap();
    let ids = |vh: &VaultHandle| -> Vec<ItemId> {
        let vault = vh.get_unlocked_vault().unwrap();
        let entries = vault.sync_entries().unwrap();
        let mut ids: Vec<ItemId> = entries
            .items
            .iter()
            .filter(|item| ["web", "old"].contains(&item.overview.key.as_str()))
            .map(|item| item.overview.id)
            .collect();
        ids.sort();
        ids
    };
    let expected = ids(&fx.read().unwrap());

    let setup = prepared(&fx);
    let committed = confirm(&fx, &setup).unwrap();

    assert_eq!(committed.value, expected);
    let kept = [("a.com", MatchKind::Domain), ("b.com", MatchKind::Domain)];
    let (_, state) = opened(&fx);
    let view = VaultView::of(&state);
    for id in &expected {
        let urls: Vec<(&str, MatchKind)> = view.items[id]
            .websites
            .iter()
            .map(|w| (w.url.as_str(), w.match_kind))
            .collect();
        assert_eq!(urls, kept);
    }
    let vault = saved_vault(&fx);
    assert_eq!(vault.get_item("web").unwrap().autofill, websites(&kept));
    assert!(
        LocalEdits::find(&state, &vault, setup.replica_id())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn manager_watches_vault_after_refresh() {
    let transport = Arc::new(FakeTransport::default());
    let fx = unsynced(transport.clone());
    let managed = Managed::start(&fx, false);
    managed.run();
    assert_eq!(transport.watch_count(), 0);

    let setup = prepared(&fx);
    confirm(&fx, &setup).unwrap();
    managed.manager.refresh();
    managed.run();

    // One watch of the vault and one of the pairing directory of its root.
    assert_eq!(transport.watch_count(), 2);
    assert!(managed.events.taken().contains(&Event::Pairings(root(), 0)));
}

/// Synced folder in a temp directory, read with `PlainIo`, and a vault that
/// is not synced whose transactions sync through it.
struct Folder {
    _dir: TempDir,
    root: PathBuf,
    fx: Fixture,
}

impl Folder {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Vaults");
        let temp = dir.path().join("temp");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&temp).unwrap();
        let transport = FolderTransport::new(&root, Arc::new(PlainIo::new(temp)));
        let fx = unsynced(Arc::new(transport));
        Self {
            _dir: dir,
            root,
            fx,
        }
    }

    fn transport_root(&self) -> TransportRoot {
        TransportRoot::Folder {
            path: self.root.clone(),
        }
    }

    fn vault_dir(&self) -> PathBuf {
        self.root.join(ShortId::encode_uuid(self.fx.id()))
    }

    /// File names in `dir`, in order.
    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }
}

#[test]
fn setup_through_folder_transport_with_plain_io_writes_meta_key_json_and_one_state_file() {
    let folder = Folder::new();
    fill(&folder.fx);
    let setup = match prepare(&folder.fx, folder.transport_root()).unwrap() {
        SetupStart::Kit(setup) => setup,
        SetupStart::Join(root) => panic!("setup offered the join of {root}"),
    };
    let committed = confirm(&folder.fx, &setup).unwrap();
    assert_eq!(committed.sync_status, Some(SyncStatus::Active));

    let replica = ShortId::encode_uuid(setup.replica_id().0);
    let mut names = vec!["meta.json".to_string(), replica.clone()];
    names.sort();
    assert_eq!(Folder::names(&folder.vault_dir()), names);
    assert_eq!(
        fs::read(folder.vault_dir().join("meta.json")).unwrap(),
        MetaFile::new(folder.fx.id()).to_bytes()
    );
    let published = Sidecar::load(&folder.fx.root, folder.fx.id())
        .last_publish
        .unwrap();
    assert_eq!(
        Folder::names(&folder.vault_dir().join(&replica)),
        published_names(published)
    );
    assert_eq!(
        Sidecar::load(&folder.fx.root, folder.fx.id()).transport,
        Some(folder.transport_root())
    );
    assert_eq!(folder.fx.read_case(), SyncLoad::Current);
    assert!(!folder.fx.write(|_| Ok(())).unwrap().changed);
}

#[test]
fn conflict_copy_of_meta_json_not_read_at_setup_and_gives_kit() {
    let folder = Folder::new();
    fs::create_dir(folder.vault_dir()).unwrap();
    fs::write(
        folder.vault_dir().join("meta 2.json"),
        MetaFile::new(folder.fx.id()).to_bytes(),
    )
    .unwrap();

    let setup = match prepare(&folder.fx, folder.transport_root()).unwrap() {
        SetupStart::Kit(setup) => setup,
        SetupStart::Join(root) => panic!("conflict copy gave the join of {root}"),
    };
    confirm(&folder.fx, &setup).unwrap();
    assert!(folder.vault_dir().join("meta.json").exists());
    assert_eq!(folder.fx.read_case(), SyncLoad::Current);
}
