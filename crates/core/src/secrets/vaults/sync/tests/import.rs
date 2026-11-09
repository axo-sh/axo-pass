//! Pairing import on the `SyncManager`, kit import, and import on new
//! hardware (10.3).
//!
//! Mac A enables sync of its vault through [`enable`]. Mac B is a [`Mac`] on
//! the same `FakeTransport`. Its pairing starts through
//! `VaultCatalog::start_pairing_with` with [`SharedUnwrap`] as the pairing
//! keys, and A's grant is a sealed `Device` wrapping added to A's `key.json`.
//! The manager of B runs on the test thread through `SyncManager::run_queued`,
//! with watch events fired by `FakeTransport::fire_watch`, downloads completed
//! by `FakeTransport::complete_downloads`, and the clock moved by
//! `SyncManager::advance_clock`.

use std::fs;
use std::sync::Arc;

use uuid::Uuid;

use super::join_sync::{Mac, enable, file_key, opened, root};
use super::load::{Fixture, GENERATION, REPLICA, device_key, state};
use super::manager::{Event, Managed};
use super::pairing::{SharedUnwrap, typed_key};
use super::transport::FakeTransport;
use super::txn::{saved, synced};
use crate::audit::test_support::test_dir;
use crate::core::auth::AuthContext;
use crate::secrets::vaults::VaultHandle;
use crate::secrets::vaults::format::encrypted_vault::EncryptedVault;
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::model::UnlockedKey;
use crate::secrets::vaults::storage::device_keys::KeyState;
use crate::secrets::vaults::storage::test_keys::TestKeys;
use crate::secrets::vaults::storage::txn::{Target, Unlock};
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::join_sync::{JoinInto, JoinKey};
use crate::secrets::vaults::sync::keys::{SyncKey, TestKeyWrapper};
use crate::secrets::vaults::sync::load::SyncLoad;
use crate::secrets::vaults::sync::local_state::{LocalSyncState, PinSource};
use crate::secrets::vaults::sync::model::{KeyId, PublicKey};
use crate::secrets::vaults::sync::pairing::PendingPairing;
use crate::secrets::vaults::sync::pairing::watcher::{PAIRING_EXPIRY, POLL_INTERVAL};
use crate::secrets::vaults::sync::recovery::import::{RecoveryCheck, RecoveryImport};
use crate::secrets::vaults::sync::setup::SyncSetup;
use crate::secrets::vaults::sync::state_file::{StateFile, StateHash};
use crate::secrets::vaults::sync::status::BUILD_ID;
use crate::secrets::vaults::sync::transport::{FileName, ReadResult, SyncTransport};
use crate::secrets::vaults::sync::wrapping::{DeviceWrapping, KeyFile};

/// Display name of the new Mac.
const MAC_B: &str = "Home Mac";

/// Vault key of a new vault imported from a vault with no name.
const NEW_KEY: &str = "vault";

/// Mac A with an item in its vault, which enables sync through `transport`.
/// Returns A and the setup, which holds the key and A's replica id.
fn enabled(transport: &Arc<FakeTransport>) -> (Fixture, SyncSetup) {
    let a = Fixture::with_transport(0, None, transport.clone());
    a.add_item().unwrap();
    let setup = enable(&a, root());
    (a, setup)
}

/// State files of `replica` in vault `vault_id`, with their bytes.
fn state_files(
    transport: &FakeTransport,
    vault_id: Uuid,
    replica: ReplicaId,
) -> Vec<(StateHash, Vec<u8>)> {
    transport
        .list_states(vault_id, replica)
        .unwrap()
        .into_iter()
        .map(|hash| {
            let ReadResult::Local(bytes) = transport
                .read(vault_id, replica, FileName::State(hash))
                .unwrap()
            else {
                panic!("state file {hash} is not local");
            };
            (hash, bytes)
        })
        .collect()
}

/// Mark the state files of `replica` in vault `vault_id` as not local yet,
/// holding their bytes until the download completes.
fn make_remote(transport: &FakeTransport, vault_id: Uuid, replica: ReplicaId) {
    for (hash, bytes) in state_files(transport, vault_id, replica) {
        transport.put_remote_with(vault_id, replica, &StateFile::name(vault_id, hash), &bytes);
    }
}

/// Start the pairing of `mac` as [`MAC_B`], with pairing keys that unwrap
/// `key` and join with the file key `file_key`.
fn start(mac: &Mac, key: &SyncKey, file_key: UnlockedKey) -> (PendingPairing, SharedUnwrap) {
    let file_key = Arc::new(file_key);
    mac.catalog
        .start_pairing_with(&root(), MAC_B, AuthContext::OneTime, |_| {
            let file_key = file_key.clone();
            Ok(Some(SharedUnwrap::new(Some(key), move || {
                file_key.duplicate_for_test()
            })))
        })
        .unwrap()
}

/// Add to the `key.json` of `from` a pairing wrapping of `key` to the
/// replica of vault `vault_id` in the request of `pending`, with the keys of
/// the Macs of the tests, as Mac A writes it at a grant. The wrapped bytes
/// are not a ciphertext, so the new Mac unwraps with [`SharedUnwrap`].
fn grant(
    transport: &FakeTransport,
    pending: &PendingPairing,
    vault_id: Uuid,
    from: ReplicaId,
    key: &SyncKey,
) {
    let request = pending.request();
    let mut wrapping = DeviceWrapping {
        key_id: KeyId(1),
        key_fingerprint: key.fingerprint(),
        to_replica: request.replicas[&vault_id],
        from_encryption: TestKeyWrapper::public_key(),
        from_signing: PublicKey(device_key()),
        wrapped: vec![0xc1, 0xc2, 0xc3],
        pairing_mac: None,
        signature: None,
        removed: None,
        remaining: None,
    };
    typed_key(pending).seal_wrapping(&mut wrapping, vault_id, from, &request.keys());
    let mut file = match transport.read(vault_id, from, FileName::Key).unwrap() {
        ReadResult::Local(bytes) => KeyFile::parse(&bytes).unwrap(),
        _ => KeyFile::default(),
    };
    file.put_device(wrapping);
    transport.put(vault_id, from, "key.json", &file.to_bytes());
}

/// Manager of `mac`, locked, with its start scan run.
fn manager_of(mac: &Mac, key: UnlockedKey) -> Managed {
    let managed = Managed::of(&mac.catalog, key, false);
    managed.run();
    managed
}

/// Paired Mac B of the vault of `a`, whose state files are not local yet,
/// with its manager, the pairing running with an import, and the first
/// batch run. Returns B, its manager, and the replica id of B in the vault.
fn waiting_import(
    transport: &Arc<FakeTransport>,
    a: &Fixture,
    setup: &SyncSetup,
) -> (Mac, Managed, ReplicaId) {
    make_remote(transport, a.id(), setup.replica_id());
    let b = Mac::new(transport.clone());
    let (pending, keys) = start(&b, setup.key(), file_key(a.id(), 2));
    grant(transport, &pending, a.id(), setup.replica_id(), setup.key());
    let replica = pending.request().replicas[&a.id()];
    let import = b.catalog.pairing_import(&pending, &root(), MAC_B);
    let managed = manager_of(&b, file_key(a.id(), 2));
    managed
        .manager
        .pair(pending, transport.clone(), Box::new(keys), Some(import));
    managed.run();
    assert_eq!(
        managed.events.taken(),
        [
            Event::Paired(a.id(), setup.key().as_bytes().to_vec()),
            Event::ImportWaiting(a.id()),
        ]
    );
    (b, managed, replica)
}

/// Whether `mac` holds a vault file or any sync file of vault `vault_id`.
fn holds_vault(mac: &Mac, vault_id: Uuid) -> bool {
    VaultHandle::file_path(&mac.vaults_dir, vault_id).exists()
        || mac.sync_files(vault_id) != [false; 3]
}

#[test]
fn pairing_import_with_no_peer_file_local_yet_waits_and_builds_vault_only_after_paired_mac_state_file_decrypts()
 {
    let transport = Arc::new(FakeTransport::default());
    let (a, setup) = enabled(&transport);

    let (b, managed, replica) = waiting_import(&transport, &a, &setup);

    // The import waits, and the download of the vault was requested.
    assert!(!holds_vault(&b, a.id()));
    assert!(transport.download_requests().contains(&a.id()));
    // The download completes with no event and no check due.
    assert!(transport.complete_downloads(a.id()) > 0);
    managed.run();
    assert!(managed.events.taken().is_empty());
    assert!(!holds_vault(&b, a.id()));

    // The watch of the pairing and the watch of the import both report it.
    assert_eq!(transport.fire_watch(a.id()), 2);
    managed.run();

    assert_eq!(
        managed.events.taken(),
        [Event::Imported(a.id(), NEW_KEY.to_string())]
    );
    let path = VaultHandle::file_path(&b.vaults_dir, a.id());
    let vault = EncryptedVault::load(&path, &TestSigner::device()).unwrap();
    assert_eq!(vault.replica_id, Some(replica.0));
    assert_eq!(vault.generation, 1);
    let (local, _) = opened(&b.root, a.id());
    assert_eq!(local.replica_id, replica);
    assert_eq!(
        local
            .pinned_keys
            .get(&setup.replica_id())
            .map(|pin| pin.source),
        Some(PinSource::Pairing)
    );

    // The next batch finds the imported vault and watches it.
    managed.run();
    managed.manager.finish_pairing();
    managed.run();
    assert_eq!(transport.fire_watch(a.id()), 1);
}

#[test]
fn torn_state_file_of_paired_mac_does_not_end_wait_and_good_later_file_does() {
    let transport = Arc::new(FakeTransport::default());
    let (a, setup) = enabled(&transport);
    let files = state_files(&transport, a.id(), setup.replica_id());
    assert_eq!(files.len(), 1);
    let (hash, bytes) = &files[0];
    let name = StateFile::name(a.id(), *hash);
    // A folder sync tool shows the first half of the file as local.
    transport.put(a.id(), setup.replica_id(), &name, &bytes[..bytes.len() / 2]);
    let b = Mac::new(transport.clone());
    let (pending, keys) = start(&b, setup.key(), file_key(a.id(), 2));
    grant(
        &transport,
        &pending,
        a.id(),
        setup.replica_id(),
        setup.key(),
    );
    let import = b.catalog.pairing_import(&pending, &root(), MAC_B);
    let managed = manager_of(&b, file_key(a.id(), 2));

    managed
        .manager
        .pair(pending, transport.clone(), Box::new(keys), Some(import));
    managed.run();
    managed.manager.advance_clock(POLL_INTERVAL.as_secs());
    managed.run();

    assert_eq!(
        managed.events.taken(),
        [
            Event::Paired(a.id(), setup.key().as_bytes().to_vec()),
            Event::ImportWaiting(a.id()),
        ]
    );
    assert!(!holds_vault(&b, a.id()));

    transport.put(a.id(), setup.replica_id(), &name, bytes);
    transport.fire_watch(a.id());
    managed.run();

    assert_eq!(
        managed.events.taken(),
        [Event::Imported(a.id(), NEW_KEY.to_string())]
    );
    assert!(VaultHandle::file_path(&b.vaults_dir, a.id()).exists());
}

#[test]
fn finished_pairing_imports_vault_with_earlier_key() {
    for finish in [true, false] {
        let transport = Arc::new(FakeTransport::default());
        let (a, setup) = enabled(&transport);
        let (b, managed, replica) = waiting_import(&transport, &a, &setup);
        let request_id = transport.list_pairings().unwrap()[0].id;

        if finish {
            managed.manager.finish_pairing();
        } else {
            managed.manager.advance_clock(PAIRING_EXPIRY.as_secs());
        }
        managed.run();

        assert!(transport.pairing(request_id).is_none(), "finish {finish}");
        assert!(managed.events.taken().is_empty(), "finish {finish}");
        assert!(!holds_vault(&b, a.id()), "finish {finish}");

        transport.complete_downloads(a.id());
        // Only the watch of the import is left.
        assert_eq!(transport.fire_watch(a.id()), 1, "finish {finish}");
        managed.run();

        assert_eq!(
            managed.events.taken(),
            [Event::Imported(a.id(), NEW_KEY.to_string())],
            "finish {finish}"
        );
        assert_eq!(
            opened(&b.root, a.id()).0.replica_id,
            replica,
            "finish {finish}"
        );
    }
}

#[test]
fn wait_without_event_polls_every_interval() {
    let transport = Arc::new(FakeTransport::default());
    let (a, setup) = enabled(&transport);
    let (b, managed, _) = waiting_import(&transport, &a, &setup);
    managed.manager.finish_pairing();
    managed.run();
    transport.complete_downloads(a.id());

    managed.manager.advance_clock(POLL_INTERVAL.as_secs() - 1);
    managed.run();
    assert!(managed.events.taken().is_empty());
    managed.manager.advance_clock(1);
    managed.run();

    assert_eq!(
        managed.events.taken(),
        [Event::Imported(a.id(), NEW_KEY.to_string())]
    );
    assert!(holds_vault(&b, a.id()));
}

#[test]
fn shutdown_ends_wait() {
    let transport = Arc::new(FakeTransport::default());
    let (a, setup) = enabled(&transport);
    let (b, managed, _) = waiting_import(&transport, &a, &setup);
    let writes = transport.writes();

    managed.manager.shutdown();
    transport.complete_downloads(a.id());

    assert_eq!(transport.watch_count(), 0);
    assert_eq!(transport.fire_watch(a.id()), 0);
    managed.run();
    assert!(managed.events.taken().is_empty());
    assert!(!holds_vault(&b, a.id()));
    assert!(b.catalog.list().is_empty());
    assert_eq!(transport.writes(), writes);
    assert!(transport.list_pairings().unwrap().is_empty());
}

#[test]
fn pairing_import_joins_existing_local_vault() {
    let transport = Arc::new(FakeTransport::default());
    let a = Fixture::with_transport(0, None, transport.clone());
    a.add_item().unwrap();
    // Mac B holds a copy of the vault of A, as an import of one export.
    let b = Mac::new(transport.clone());
    let b_vault = b.copy_of(&a);
    let setup = enable(&a, root());
    let (pending, keys) = start(&b, setup.key(), b_vault.unlocked_key().unwrap());
    grant(
        &transport,
        &pending,
        a.id(),
        setup.replica_id(),
        setup.key(),
    );
    let replica = pending.request().replicas[&a.id()];
    let import = b.catalog.pairing_import(&pending, &root(), MAC_B);
    assert!(matches!(
        import.into.get(&a.id()),
        Some(JoinInto::Existing(target)) if target.path == b_vault.path
    ));
    let managed = manager_of(&b, b_vault.unlocked_key().unwrap());

    managed
        .manager
        .pair(pending, transport.clone(), Box::new(keys), Some(import));
    managed.run();

    // A's state file is local, so the import runs in the same batch.
    assert_eq!(
        managed.events.taken(),
        [
            Event::Paired(a.id(), setup.key().as_bytes().to_vec()),
            Event::ImportWaiting(a.id()),
            Event::Imported(a.id(), b_vault.key.clone()),
        ]
    );
    let vault = b.saved(&b_vault);
    assert_eq!(vault.replica_id(), Some(replica.0));
    assert!(vault.get_item("item").is_ok());
    assert_eq!(opened(&b.root, a.id()).0.replica_id, replica);
    assert_eq!(b.catalog.list().len(), 1);
}

/// Fixture of one case of the request map, synced through the folder.
type BuildCase = fn(&Arc<FakeTransport>) -> Fixture;

#[test]
fn vault_stopped_by_failed_signature_is_in_request_map_and_vault_that_syncs_not() {
    // Each case with whether the request map holds the vault.
    let cases: Vec<(&str, BuildCase, bool)> = vec![
        ("syncs", |transport| synced(transport), false),
        (
            "stopped by drift",
            |transport| {
                let fx = Fixture::with_transport(GENERATION, Some(REPLICA), transport.clone());
                let mut stopped = state(fx.id(), REPLICA, GENERATION);
                stopped.stopped_build = Some(BUILD_ID.to_string());
                fx.put(&stopped, &TestSigner::device());
                fx
            },
            false,
        ),
        (
            "leaving",
            |transport| {
                let fx = Fixture::with_transport(GENERATION, Some(REPLICA), transport.clone());
                let mut leaving = state(fx.id(), REPLICA, GENERATION);
                leaving.leaving = true;
                fx.put(&leaving, &TestSigner::device());
                fx
            },
            false,
        ),
        (
            "failed signature",
            |transport| {
                let fx = synced(transport);
                let (local, _) = saved(&fx);
                fx.put(&local, &TestSigner::random());
                fx
            },
            true,
        ),
        (
            "missing sync state",
            |transport| Fixture::with_transport(GENERATION, Some(REPLICA), transport.clone()),
            true,
        ),
        (
            "sync state left by a disable",
            |transport| {
                let fx = Fixture::with_transport(0, None, transport.clone());
                fx.put_state(GENERATION);
                fx
            },
            true,
        ),
        (
            "not synced",
            |transport| Fixture::with_transport(0, None, transport.clone()),
            true,
        ),
    ];
    for (name, build, in_map) in cases {
        let transport = Arc::new(FakeTransport::default());
        let fx = build(&transport);
        // Another vault of the folder, so no request map is empty.
        let other = Uuid::new_v4();
        for vault_id in [fx.id(), other] {
            transport.put_meta(vault_id, b"{}");
        }

        let (pending, _) = fx
            .catalog
            .start_pairing_with(&root(), MAC_B, AuthContext::OneTime, |_| {
                Ok(Some(SharedUnwrap::new(None, || panic!("no join"))))
            })
            .unwrap();

        let replicas = &pending.request().replicas;
        assert_eq!(replicas.contains_key(&fx.id()), in_map, "{name}");
        assert!(replicas.contains_key(&other), "{name}");
        // The join check agrees with the request map.
        let signer = TestSigner::device();
        let vault = EncryptedVault::load(&fx.vault.path, &signer).unwrap();
        let keyring = SyncLoad::keyring(&fx.root, &vault, &signer, &TestKeyWrapper);
        let joinable =
            SyncSetup::check_joinable(&fx.root, fx.id(), Some(&vault), keyring.as_ref(), &signer);
        assert_eq!(joinable.is_ok(), in_map, "{name}: {joinable:?}");
    }
}

#[test]
fn kit_import_on_new_hardware_moves_files_to_unreadable_and_takes_new_replica_id() {
    let _audit = test_dir();
    let transport = Arc::new(FakeTransport::default());
    let (a, setup) = enabled(&transport);
    // Mac B synced the vault as replica R1, then moved to new hardware with
    // its files restored and both Secure Enclave keys missing.
    let b = Mac::new(transport.clone());
    let RecoveryCheck::Recovered(key) = RecoveryImport::check(setup.kit(), &*transport).unwrap()
    else {
        panic!("kit did not open the key");
    };
    let r1 = key.replica_id;
    let first_key = || file_key(a.id(), 2);
    let committed = b
        .catalog
        .join_sync(
            &JoinKey::recovered(key),
            JoinInto::New,
            &root(),
            MAC_B,
            Unlock::Test(&first_key),
        )
        .unwrap();
    let path = committed.vault.path.clone();
    let keys = Arc::new(TestKeys::neither());
    let catalog = b.catalog.clone().with_keys(keys.clone());

    // The app offers pairing or the kit for the synced vault.
    assert_eq!(catalog.key_state(), KeyState::NewHardware);
    assert!(
        catalog
            .unverified_synced_vaults()
            .iter()
            .any(|synced| synced.vault_id == a.id() && synced.replica_id == r1)
    );

    let RecoveryCheck::Recovered(key) = RecoveryImport::check(setup.kit(), &*transport).unwrap()
    else {
        panic!("kit did not open the key");
    };
    let replica = key.replica_id;
    let new_key = || file_key(a.id(), 3);
    let committed = catalog
        .import_recovered_with(
            key,
            &root(),
            MAC_B,
            JoinInto::Existing(Target::of(&committed.vault)),
            AuthContext::OneTime,
            Unlock::Test(&new_key),
        )
        .unwrap();

    // The files of R1 moved to `unreadable/` before the keys were created.
    assert_eq!(keys.created(), 2);
    let moved: Vec<_> = fs::read_dir(b.root.join("unreadable"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(moved.len(), 1);
    let moved = &moved[0];
    assert!(
        moved
            .join("vaults")
            .join(path.file_name().unwrap())
            .exists()
    );
    let old = LocalSyncState::load(moved, a.id(), &TestSigner::device()).unwrap();
    assert_eq!(old.replica_id, r1);
    // The import built a new vault under a new replica id.
    assert_ne!(replica, r1);
    assert_eq!(committed.vault.path, path);
    let vault = EncryptedVault::load(&path, &TestSigner::device()).unwrap();
    assert_eq!(vault.replica_id, Some(replica.0));
    assert_eq!(vault.generation, 1);
    assert_eq!(opened(&b.root, a.id()).0.replica_id, replica);
    assert_eq!(catalog.key_state(), KeyState::Normal);
}

#[test]
fn kit_import_on_mac_with_no_vault_file_creates_both_keys() {
    let transport = Arc::new(FakeTransport::default());
    let (a, setup) = enabled(&transport);
    let b = Mac::new(transport.clone());
    let keys = Arc::new(TestKeys::neither());
    let catalog = b.catalog.clone().with_keys(keys.clone());
    assert_eq!(catalog.key_state(), KeyState::NoVaultFiles);
    let RecoveryCheck::Recovered(key) = RecoveryImport::check(setup.kit(), &*transport).unwrap()
    else {
        panic!("kit did not open the key");
    };
    let replica = key.replica_id;

    let file_key = || file_key(a.id(), 2);
    let committed = catalog
        .import_recovered_with(
            key,
            &root(),
            MAC_B,
            JoinInto::New,
            AuthContext::OneTime,
            Unlock::Test(&file_key),
        )
        .unwrap();

    assert_eq!(keys.created(), 2);
    assert_eq!(committed.vault.key, NEW_KEY);
    let vault = EncryptedVault::load(&committed.vault.path, &TestSigner::device()).unwrap();
    assert_eq!(vault.replica_id, Some(replica.0));
    assert!(!b.root.join("unreadable").exists());
    assert_eq!(catalog.key_state(), KeyState::Normal);
}
