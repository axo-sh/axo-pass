//! Two Macs that enabled sync separately (10.5).
//!
//! T2 runs Mac A as a [`Fixture`] and Mac B as a [`Mac`] on one
//! `FakeTransport`, each enabled with its own key through `SyncSetup`. The
//! other tests plant a peer file under another key in the folder of a
//! [`synced`] vault, whose sync state holds the test keyring under key id 1.

use std::fs;
use std::sync::Arc;

use uuid::Uuid;

use super::import::start;
use super::join::{PEER, peer_state};
use super::join_sync::{Mac, enable, opened, recovered, root};
use super::load::{Fixture, GENERATION, REPLICA, body, device_key, state_of, sync_files};
use super::publish::published;
use super::transport::FakeTransport;
use super::txn::{saved_vault, synced};
use crate::secrets::vaults::format::encrypted_vault::EncryptedVault;
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::storage::txn::{Committed, Disabled, Target, Unlock};
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::join_sync::{JoinInto, JoinKey};
use crate::secrets::vaults::sync::keys::{SyncKey, TestKeyWrapper};
use crate::secrets::vaults::sync::load::SyncLoad;
use crate::secrets::vaults::sync::local_state::{PinSource, PinnedKeys};
use crate::secrets::vaults::sync::model::{KeyId, PublicKey};
use crate::secrets::vaults::sync::pairing::PairedVault;
use crate::secrets::vaults::sync::setup::{SetupStart, SyncSetup};
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::state_file::StateFile;
use crate::secrets::vaults::sync::state_file::padded::PaddedBody;
use crate::secrets::vaults::sync::status::{PausedCause, SyncStatus};
use crate::secrets::vaults::sync::transport::SyncTransport;
use crate::secrets::vaults::sync::view::VaultView;
use crate::secrets::vaults::{Error, VaultHandle};

/// Display name of Mac B.
const MAC_B: &str = "Home Mac";

/// Replica of a Mac that enabled sync separately.
const SEPARATE: ReplicaId = ReplicaId(Uuid::from_u128(3));

/// Replica in `replica_keys` of the state, with no pin.
const KNOWN: ReplicaId = ReplicaId(Uuid::from_u128(4));

/// Sync key of a Mac that enabled sync separately.
fn other_key() -> SyncKey {
    SyncKey::from_bytes([9; 32])
}

/// Status of one paused cause, `SeparateKey` of `replicas` replicas.
fn separate(replicas: usize) -> Option<SyncStatus> {
    Some(SyncStatus::Paused(vec![PausedCause::SeparateKey {
        replicas,
    }]))
}

/// Put a state file of `replica` with item `item_key`, under key id `key_id`
/// and `key`, in the folder of `fx`.
fn put_under(
    fx: &Fixture,
    transport: &FakeTransport,
    replica: ReplicaId,
    key_id: KeyId,
    key: &SyncKey,
    item_key: &str,
) {
    let padded = PaddedBody::of(&peer_state(fx, replica, item_key)).unwrap();
    let bytes = StateFile::encode(&padded, fx.id(), replica, key_id, key).unwrap();
    transport.put_state(fx.id(), replica, &bytes);
}

/// Disable sync of the vault of `fx` with its file key.
fn disable(fx: &Fixture) -> Result<Committed<Disabled>, Error> {
    let key = || fx.vault.unlocked_key().unwrap();
    fx.catalog
        .files()
        .disable_sync(&Target::of(&fx.vault), Unlock::Test(&key))
}

/// Whether the sync state, the staged file, and the sidecar of `fx` exist.
/// Replica id of the vault file at `vh`, verified.
fn vault_replica(vh: &VaultHandle) -> Option<Uuid> {
    EncryptedVault::load(&vh.path, &TestSigner::device())
        .unwrap()
        .replica_id
}

/// Run `f` in a transaction on the vault `vh` of `mac`.
fn write_on(
    mac: &Mac,
    vh: &VaultHandle,
    f: impl FnOnce(&mut VaultHandle) -> Result<(), Error>,
) -> Committed<()> {
    let key = || vh.unlocked_key().unwrap();
    mac.catalog
        .files()
        .write(&Target::of(vh), Unlock::Test(&key), f)
        .unwrap()
}

#[test]
fn two_macs_that_enable_sync_at_once_show_separate_key_and_converge_after_one_turns_sync_off_and_on()
 {
    let transport = Arc::new(FakeTransport::default());
    let a = Fixture::with_transport(0, None, transport.clone());
    a.add_item().unwrap();
    // Both Macs import one export.
    let b = Mac::new(transport.clone());
    let b_vault = b.copy_of(&a);
    let vault_id = a.id();
    let setup = enable(&a, root());
    // Mac B enables before the directory of A reaches it, with its own key.
    transport.remove_meta(vault_id);
    let b_target = Target::of(&b_vault);
    let b_setup = match SyncSetup::prepare(b.catalog.files(), &b_target, root(), MAC_B).unwrap() {
        SetupStart::Kit(setup) => setup,
        SetupStart::Join(root) => panic!("setup offered the join of {root}"),
    };
    let b_key = || b_vault.unlocked_key().unwrap();
    b_setup
        .confirm(b.catalog.files(), &b_target, Unlock::Test(&b_key))
        .unwrap();
    let b_replica = b_setup.replica_id();
    assert_ne!(b_setup.key().fingerprint(), setup.key().fingerprint());
    write_on(&b, &b_vault, |vh| vh.add_item("local", "Local").map(|_| ()));

    // Each Mac reports the separate enable and quarantines nothing.
    let a_committed = a.write(|_| Ok(())).unwrap();
    let b_committed = write_on(&b, &b_vault, |_| Ok(()));

    assert_eq!(a_committed.sync_status, separate(1));
    assert_eq!(b_committed.sync_status, separate(1));
    let a_sidecar = Sidecar::load(&a.root, vault_id);
    assert_eq!(
        a_sidecar.paused(),
        [PausedCause::SeparateKey { replicas: 1 }]
    );
    assert!(a_sidecar.quarantined.is_empty());
    assert!(Sidecar::load(&b.root, vault_id).quarantined.is_empty());
    assert!(saved_vault(&a).get_item("local").is_err());

    // Mac B turns sync off, which deletes its directory.
    let disabled = b
        .catalog
        .files()
        .disable_sync(&b_target, Unlock::Test(&b_key))
        .unwrap();

    assert_eq!(disabled.value, Disabled::DirectoryDeleted);
    assert!(transport.names(vault_id, b_replica).is_empty());
    assert!(!transport.names(vault_id, setup.replica_id()).is_empty());
    assert_eq!(b.sync_files(vault_id), [false; 3]);
    assert_eq!(vault_replica(&b_vault), None);

    // Mac B turns sync on again, which offers the join, and joins with the
    // kit of A.
    let start = SyncSetup::prepare(b.catalog.files(), &b_target, root(), MAC_B).unwrap();
    assert!(matches!(start, SetupStart::Join(r) if r == root()));
    let join = recovered(&setup, &*transport);
    let joined = b
        .catalog
        .join_sync(
            &join,
            JoinInto::Existing(b_target),
            &root(),
            MAC_B,
            Unlock::Test(&b_key),
        )
        .unwrap();

    assert_eq!(joined.sync_status, Some(SyncStatus::Active));
    assert_ne!(join.replica_id(), b_replica);
    let a_committed = a.write(|_| Ok(())).unwrap();
    let b_committed = write_on(&b, &b_vault, |_| Ok(()));

    // Both Macs converge, the local entry of B is in the view of A, and the
    // cause of A clears.
    assert_eq!(a_committed.sync_status, Some(SyncStatus::Active));
    assert_eq!(b_committed.sync_status, Some(SyncStatus::Active));
    assert!(Sidecar::load(&a.root, vault_id).paused().is_empty());
    let (_, a_state) = opened(&a.root, vault_id);
    let (_, b_state) = opened(&b.root, vault_id);
    let view = VaultView::of(&a_state);
    assert_eq!(view, VaultView::of(&b_state));
    let a_vault = saved_vault(&a);
    let b_saved = b.saved(&b_vault);
    for key in ["item", "local"] {
        assert!(a_vault.get_item(key).is_ok(), "{key}");
        assert!(b_saved.get_item(key).is_ok(), "{key}");
    }
}

#[test]
fn pairing_merges_separately_enabled_macs_and_deletes_old_directory() {
    let transport = Arc::new(FakeTransport::default());
    let a = Fixture::with_transport(0, None, transport.clone());
    a.add_item().unwrap();
    let b = Mac::new(transport.clone());
    let b_vault = b.copy_of(&a);
    let vault_id = a.id();
    let setup = enable(&a, root());
    transport.remove_meta(vault_id);
    let b_target = Target::of(&b_vault);
    let b_setup = match SyncSetup::prepare(b.catalog.files(), &b_target, root(), MAC_B).unwrap() {
        SetupStart::Kit(setup) => setup,
        SetupStart::Join(root) => panic!("setup offered the join of {root}"),
    };
    let b_key = || b_vault.unlocked_key().unwrap();
    b_setup
        .confirm(b.catalog.files(), &b_target, Unlock::Test(&b_key))
        .unwrap();
    let b_replica = b_setup.replica_id();
    write_on(&b, &b_vault, |vh| vh.add_item("local", "Local").map(|_| ()));
    assert_eq!(write_on(&b, &b_vault, |_| Ok(())).sync_status, separate(1));
    assert_eq!(a.write(|_| Ok(())).unwrap().sync_status, separate(1));

    // Only a pairing merges the Macs. A recovery kit does not, since the
    // vault of B syncs.
    let by_kit = b.catalog.join_sync(
        &recovered(&setup, &*transport),
        JoinInto::Existing(b_target.clone()),
        &root(),
        MAC_B,
        Unlock::Test(&b_key),
    );
    assert!(matches!(by_kit, Err(Error::SyncAlreadyEnabled)));

    // The request of B holds the vault, and A pairs with it.
    let (pending, _keys) = start(&b, setup.key(), b_vault.unlocked_key().unwrap());
    assert!(pending.request().replicas.contains_key(&vault_id));
    let new_replica = pending.request().replicas[&vault_id];
    let join = JoinKey::paired(PairedVault {
        vault_id,
        replica_id: new_replica,
        key_id: KeyId(1),
        key: setup.key().clone(),
        peer: setup.replica_id(),
        pin: PinnedKeys {
            source: PinSource::Pairing,
            encryption: TestKeyWrapper::public_key(),
            signing: PublicKey(device_key()),
            revoked: false,
        },
    });

    let joined = b
        .catalog
        .join_sync(
            &join,
            JoinInto::Existing(b_target),
            &root(),
            MAC_B,
            Unlock::Test(&b_key),
        )
        .unwrap();

    // B takes the new replica id and deletes its old directory.
    assert_eq!(joined.sync_status, Some(SyncStatus::Active));
    assert_eq!(vault_replica(&b_vault), Some(new_replica.0));
    assert!(transport.names(vault_id, b_replica).is_empty());
    assert!(!transport.names(vault_id, new_replica).is_empty());
    let (b_local, _) = opened(&b.root, vault_id);
    assert_eq!(b_local.replica_id, new_replica);
    assert_eq!(
        b_local
            .pinned_keys
            .get(&setup.replica_id())
            .map(|pin| pin.source),
        Some(PinSource::Pairing)
    );

    // Both Macs converge on the merged vault.
    let a_committed = a.write(|_| Ok(())).unwrap();
    let b_committed = write_on(&b, &b_vault, |_| Ok(()));
    assert_eq!(a_committed.sync_status, Some(SyncStatus::Active));
    assert_eq!(b_committed.sync_status, Some(SyncStatus::Active));
    assert!(Sidecar::load(&a.root, vault_id).paused().is_empty());
    let (_, a_state) = opened(&a.root, vault_id);
    let (_, b_state) = opened(&b.root, vault_id);
    assert_eq!(VaultView::of(&a_state), VaultView::of(&b_state));
    let a_vault = saved_vault(&a);
    let b_saved = b.saved(&b_vault);
    for key in ["item", "local"] {
        assert!(a_vault.get_item(key).is_ok(), "{key}");
        assert!(b_saved.get_item(key).is_ok(), "{key}");
    }
}

#[test]
fn other_fingerprint_file_not_counted() {
    let transport = Arc::new(FakeTransport::default());
    let fx = Fixture::with_transport(GENERATION, Some(REPLICA), transport.clone());
    // KNOWN is in `replica_keys` with no pin, and PEER is pinned.
    let mut initial = body(REPLICA, &[device_key()]);
    initial.join(body(KNOWN, &[device_key()]));
    let mut local = state_of(fx.id(), REPLICA, GENERATION, &initial);
    local.pinned_keys.insert(
        PEER,
        PinnedKeys {
            source: PinSource::Pairing,
            encryption: PublicKey(vec![4, 1]),
            signing: PublicKey(device_key()),
            revoked: false,
        },
    );
    fx.put(&local, &TestSigner::device());
    for (replica, item_key) in [(PEER, "pinned"), (KNOWN, "known"), (SEPARATE, "separate")] {
        put_under(&fx, &transport, replica, KeyId(1), &other_key(), item_key);
    }

    let committed = fx.add_item().unwrap();

    // Only the file of SEPARATE is counted.
    assert_eq!(committed.sync_status, separate(1));
    let sidecar = Sidecar::load(&fx.root, fx.id());
    assert!(sidecar.quarantined.is_empty());
    let vault = saved_vault(&fx);
    for key in ["pinned", "known", "separate"] {
        assert!(vault.get_item(key).is_err(), "{key}");
    }

    // The cause clears once the file is gone.
    transport.delete_replica(fx.id(), SEPARATE).unwrap();

    let committed = fx.write(|_| Ok(())).unwrap();

    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    assert!(Sidecar::load(&fx.root, fx.id()).paused().is_empty());
}

#[test]
fn file_under_key_id_keyring_lacks_not_counted() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    put_under(&fx, &transport, SEPARATE, KeyId(2), &other_key(), "waiting");

    let committed = fx.add_item().unwrap();

    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    let sidecar = Sidecar::load(&fx.root, fx.id());
    assert!(sidecar.paused().is_empty());
    assert!(sidecar.quarantined.is_empty());
    assert!(saved_vault(&fx).get_item("waiting").is_err());
}

#[test]
fn separate_disable_while_folder_cannot_be_reached_refused() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    put_under(
        &fx,
        &transport,
        SEPARATE,
        KeyId(1),
        &other_key(),
        "separate",
    );
    assert_eq!(fx.add_item().unwrap().sync_status, separate(1));
    assert_eq!(published(&transport, &fx).len(), 1);
    transport.set_unavailable(true);
    let on_disk = fx.on_disk();
    let sidecar = fs::read(Sidecar::path(&fx.root, fx.id())).unwrap();
    let writes = transport.writes();

    assert!(matches!(disable(&fx), Err(Error::SyncFolderUnreachable(_))));

    assert_eq!(fx.on_disk(), on_disk);
    assert_eq!(fs::read(Sidecar::path(&fx.root, fx.id())).unwrap(), sidecar);
    assert_eq!(sync_files(&fx), [true; 3]);
    assert_eq!(transport.writes(), writes);

    // Once the folder can be reached, the disable deletes the own directory
    // in place of the final file.
    transport.set_unavailable(false);

    let disabled = disable(&fx).unwrap();

    assert_eq!(disabled.value, Disabled::DirectoryDeleted);
    assert!(published(&transport, &fx).is_empty());
    assert!(transport.names(fx.id(), REPLICA).is_empty());
    assert_eq!(transport.names(fx.id(), SEPARATE).len(), 1);
    assert_eq!(transport.writes(), writes);
    assert_eq!(vault_replica(&fx.vault), None);
    assert_eq!(sync_files(&fx), [false; 3]);
    assert_eq!(fx.read_case(), SyncLoad::NotSynced);
    assert!(saved_vault(&fx).get_item("item").is_ok());
}

#[test]
fn disable_with_other_replica_key_writes_final_file() {
    let transport = Arc::new(FakeTransport::default());
    let fx = Fixture::with_transport(GENERATION, Some(REPLICA), transport.clone());
    let mut initial = body(REPLICA, &[device_key()]);
    initial.join(body(KNOWN, &[device_key()]));
    fx.put(
        &state_of(fx.id(), REPLICA, GENERATION, &initial),
        &TestSigner::device(),
    );
    put_under(
        &fx,
        &transport,
        SEPARATE,
        KeyId(1),
        &other_key(),
        "separate",
    );
    assert_eq!(fx.add_item().unwrap().sync_status, separate(1));
    let before = published(&transport, &fx);

    let disabled = disable(&fx).unwrap();

    // KNOWN reads the own files, so the final file is copied as in any
    // disable.
    assert_eq!(disabled.value, Disabled::Left);
    let after = published(&transport, &fx);
    assert!(after.iter().any(|hash| !before.contains(hash)));
    assert_eq!(vault_replica(&fx.vault), None);
    assert_eq!(sync_files(&fx), [false; 3]);
}
