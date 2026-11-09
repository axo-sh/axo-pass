//! Disable sync and delete a synced vault (10.4).
//!
//! Mac A enables sync through `enable`, and Macs B and C join it with the
//! kit of A on the same `FakeTransport`. Other tests disable a [`synced`]
//! vault, whose sync state holds the test keyring. The folder is made
//! unreachable with `FakeTransport::set_unavailable`. The manager runs on the
//! test thread through `SyncManager::run_queued`, and its retry clock is
//! moved with `SyncManager::advance_clock`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use uuid::Uuid;

use super::join::PEER;
use super::join_sync::{Mac, enable, file_key, opened, recovered, root};
use super::load::{Fixture, GENERATION, REPLICA, state};
use super::manager::{Managed, assert_locked_writes, check_locks_on_write, folder_root, set_root};
use super::publish::{decode, published};
use super::reads::put_peer;
use super::state_file::key;
use super::transport::FakeTransport;
use super::txn::{new_write_ids, saved, saved_vault, synced};
use super::view::State;
use crate::core::auth::AuthContext;
use crate::secrets::vaults::format::encrypted_vault::EncryptedVault;
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::model::UnlockedKey;
use crate::secrets::vaults::storage::txn::{Committed, Disabled, StagedCopy, Target, Unlock};
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::join_sync::{JoinInto, JoinKey};
use crate::secrets::vaults::sync::keys::SyncKeyring;
use crate::secrets::vaults::sync::load::SyncLoad;
use crate::secrets::vaults::sync::local_state::LocalSyncState;
use crate::secrets::vaults::sync::manager::RETRY_INTERVAL;
use crate::secrets::vaults::sync::meta::MetaFile;
use crate::secrets::vaults::sync::model::KeyId;
use crate::secrets::vaults::sync::recovery::import::{RecoveredKey, RecoveryCheck, RecoveryImport};
use crate::secrets::vaults::sync::setup::{SetupStart, SyncSetup};
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::state_file::{StateFile, StateHash, StateSource};
use crate::secrets::vaults::sync::status::BUILD_ID;
use crate::secrets::vaults::sync::transport::{FileName, ReadResult, SyncTransport};
use crate::secrets::vaults::sync::view::VaultView;
use crate::secrets::vaults::{Error, VaultHandle};

/// Display name of the Mac that enables sync.
const MAC_A: &str = "Work Mac";

/// Display name of the Mac that joins.
const MAC_B: &str = "Home Mac";

/// Display name of a third Mac.
const MAC_C: &str = "Studio Mac";

/// File key of a test that reads none.
fn no_key() -> UnlockedKey {
    panic!("no file key is read")
}

/// Remove the vault file at `path`, in place of the move to the Trash.
fn remove_file(path: &Path) -> Result<(), Error> {
    fs::remove_file(path).map_err(Error::VaultDeleteError)
}

/// Disable sync of the vault of `fx` with its file key.
fn disable(fx: &Fixture) -> Result<Committed<Disabled>, Error> {
    let key = || fx.vault.unlocked_key().unwrap();
    fx.catalog
        .files()
        .disable_sync(&Target::of(&fx.vault), Unlock::Test(&key))
}

/// Whether the sync state, the staged file, and the sidecar of `fx` exist.
fn sync_files(fx: &Fixture) -> [bool; 3] {
    [
        LocalSyncState::path(&fx.root, fx.id()),
        LocalSyncState::staged_path(&fx.root, fx.id()),
        Sidecar::path(&fx.root, fx.id()),
    ]
    .map(|path| path.exists())
}

/// Replica id and generation of the vault file of `fx`, verified.
fn vault_sync(fx: &Fixture) -> (Option<Uuid>, u64) {
    let file = EncryptedVault::load(&fx.vault.path, &TestSigner::device()).unwrap();
    (file.replica_id, file.generation)
}

/// State files of `replica` in vault `vault_id`.
fn state_files(
    transport: &FakeTransport,
    vault_id: Uuid,
    replica: ReplicaId,
) -> BTreeSet<StateHash> {
    transport
        .list_states(vault_id, replica)
        .unwrap()
        .into_iter()
        .collect()
}

/// State of the state file `hash` of the Mac of `setup`, opened with the key
/// of `setup`.
fn state_of_file(transport: &FakeTransport, setup: &SyncSetup, hash: StateHash) -> State {
    let vault_id = setup.vault_id();
    let replica = setup.replica_id();
    let ReadResult::Local(bytes) = transport
        .read(vault_id, replica, FileName::State(hash))
        .unwrap()
    else {
        panic!("state file {hash} is not local");
    };
    let source = StateSource {
        vault_id,
        replica_id: replica,
        hash,
    };
    let keyring = SyncKeyring::new(vec![(KeyId(1), setup.key().clone())]).unwrap();
    StateFile::decode(&bytes, &source, &keyring).unwrap().1
}

/// Mac A with an item, which enables sync through the folder, and Mac B,
/// which joins it with the kit of A.
struct Pair {
    a: Fixture,
    setup: SyncSetup,
    b: Mac,
    /// Vault of B as joined.
    b_vault: VaultHandle,
}

impl Pair {
    fn new(transport: &Arc<FakeTransport>) -> Self {
        let a = Fixture::with_transport(0, None, transport.clone());
        a.add_item().unwrap();
        let setup = enable(&a, root());
        let b = Mac::new(transport.clone());
        let b_vault = Self::join(&b, &setup, transport, MAC_B);
        Self {
            a,
            setup,
            b,
            b_vault,
        }
    }

    /// Replica of A.
    fn replica(&self) -> ReplicaId {
        self.setup.replica_id()
    }

    /// Join the vault of `setup` into a new vault of `mac` with the kit of
    /// `setup`, as the Mac named `name`.
    fn join(mac: &Mac, setup: &SyncSetup, transport: &FakeTransport, name: &str) -> VaultHandle {
        let key = || file_key(setup.vault_id(), 2);
        mac.catalog
            .join_sync(
                &recovered(setup, transport),
                JoinInto::New,
                &root(),
                name,
                Unlock::Test(&key),
            )
            .unwrap()
            .vault
    }

    /// Run a transaction with no requested change on `vault` of `mac`, and
    /// return the `left` view of its sync state.
    fn left_of(mac: &Mac, vault: &VaultHandle) -> BTreeMap<ReplicaId, bool> {
        let key = || vault.unlocked_key().unwrap();
        mac.catalog
            .files()
            .write(&Target::of(vault), Unlock::Test(&key), |_| {
                Ok::<_, Error>(())
            })
            .unwrap();
        VaultView::of(&opened(&mac.root, vault.vault_id().unwrap()).1).left
    }
}

#[test]
fn disabling_sync_while_folder_is_missing_holds_final_file_in_leaving_state_and_manager_copies_it_when_folder_returns()
 {
    let transport = Arc::new(FakeTransport::default());
    let pair = Pair::new(&transport);
    let a = &pair.a;
    let replica = pair.replica();
    transport.set_unavailable(true);

    let disabled = disable(a).unwrap();

    assert_eq!(disabled.value, Disabled::Waiting);
    let vault = disabled.vault.get_unlocked_vault().unwrap();
    assert_eq!(vault.replica_id(), None);
    assert_eq!(vault_sync(a).0, None);
    let (local, _) = opened(&a.root, a.id());
    assert!(local.leaving);
    let staged = local.staged_hash.unwrap();
    assert_eq!(sync_files(a), [true; 3]);
    let managed = Managed::start(a, false);
    managed.run();
    assert_eq!(sync_files(a), [true; 3]);

    // The folder returns, and the retry copies the final file.
    transport.set_unavailable(false);
    let checks = check_locks_on_write(&transport, a);
    managed.manager.advance_clock(RETRY_INTERVAL.as_secs());
    managed.run();

    assert!(state_files(&transport, a.id(), replica).contains(&staged));
    assert_locked_writes(&checks, 1);
    assert_eq!(sync_files(a), [false; 3]);
    assert_eq!(managed.unlock.transactions(), 0);
    assert!(managed.events.taken().is_empty());
    assert_eq!(transport.watch_count(), 0);
    assert_eq!(
        Pair::left_of(&pair.b, &pair.b_vault).get(&replica),
        Some(&true)
    );
}

#[test]
fn deleting_synced_vault_while_folder_is_missing_delivers_final_file_when_folder_returns_and_vault_is_not_listed_as_missing()
 {
    let transport = Arc::new(FakeTransport::default());
    let pair = Pair::new(&transport);
    let a = &pair.a;
    let replica = pair.replica();
    transport.set_unavailable(true);
    let key = || a.vault.unlocked_key().unwrap();

    a.catalog
        .delete_with("personal", Unlock::Test(&key), remove_file)
        .unwrap();

    assert!(!a.vault.path.exists());
    assert_eq!(sync_files(a), [true; 3]);
    let staged = opened(&a.root, a.id()).0.staged_hash.unwrap();
    assert!(a.catalog.scan().missing.is_empty());
    let managed = Managed::start(a, false);
    managed.run();
    assert_eq!(sync_files(a), [true; 3]);

    transport.set_unavailable(false);
    managed.manager.advance_clock(RETRY_INTERVAL.as_secs());
    managed.run();

    assert!(state_files(&transport, a.id(), replica).contains(&staged));
    assert_eq!(sync_files(a), [false; 3]);
    assert!(a.catalog.scan().missing.is_empty());
    assert_eq!(
        Pair::left_of(&pair.b, &pair.b_vault).get(&replica),
        Some(&true)
    );
}

#[test]
fn age_import_with_kit_succeeds_after_kit_maker_disables_sync_and_its_directory_is_deleted() {
    let transport = Arc::new(FakeTransport::default());
    let pair = Pair::new(&transport);
    let replica = pair.replica();
    assert_eq!(disable(&pair.a).unwrap().value, Disabled::Left);
    // Cleanup of the directory of a Mac that left is milestone 13. The fake
    // deletes it.
    transport.delete_replica(pair.a.id(), replica).unwrap();
    assert!(transport.names(pair.a.id(), replica).is_empty());

    let RecoveryCheck::Recovered(key) =
        RecoveryImport::check(pair.setup.kit(), &*transport).unwrap()
    else {
        panic!("kit did not open the key");
    };
    let c = Mac::new(transport.clone());
    let file_key = || file_key(pair.a.id(), 3);
    let committed = c
        .catalog
        .import_recovered_with(
            key,
            &root(),
            MAC_C,
            JoinInto::New,
            AuthContext::OneTime,
            Unlock::Test(&file_key),
        )
        .unwrap();

    let vault = committed.vault.get_unlocked_vault().unwrap();
    assert!(vault.get_item("item").is_ok());
    assert_ne!(vault.replica_id(), Some(replica.0));
}

#[test]
fn reenabling_disabled_vault_offers_join_and_joins_with_recovered_key() {
    let transport = Arc::new(FakeTransport::default());
    let a = Fixture::with_transport(0, None, transport.clone());
    a.add_item().unwrap();
    let setup = enable(&a, root());
    assert_eq!(disable(&a).unwrap().value, Disabled::Left);
    assert_eq!(sync_files(&a), [false; 3]);
    let target = Target::of(&a.vault);

    // The folder holds the vault, so the setup offers the join in place of a
    // new key. The join takes the key by pairing or a kit.
    let start = SyncSetup::prepare(a.catalog.files(), &target, root(), MAC_A).unwrap();
    assert!(matches!(start, SetupStart::Join(r) if r == root()));
    let join = recovered(&setup, &*transport);
    let replica = join.replica_id;
    let key = || a.vault.unlocked_key().unwrap();
    a.catalog
        .join_sync(
            &join,
            JoinInto::Existing(target),
            &root(),
            MAC_A,
            Unlock::Test(&key),
        )
        .unwrap();

    assert_ne!(replica, setup.replica_id());
    assert_eq!(vault_sync(&a).0, Some(replica.0));
    assert_eq!(opened(&a.root, a.id()).0.replica_id, replica);
    assert!(saved_vault(&a).get_item("item").is_ok());
    assert_eq!(a.read_case(), SyncLoad::Current);
}

#[test]
fn disabling_and_enabling_sync_again_takes_new_replica_id() {
    let transport = Arc::new(FakeTransport::default());
    let a = Fixture::with_transport(0, None, transport.clone());
    a.add_item().unwrap();
    let setup = enable(&a, root());
    let mut replicas = vec![setup.replica_id()];

    for _ in 0..2 {
        assert_eq!(disable(&a).unwrap().value, Disabled::Left);
        assert_eq!(vault_sync(&a).0, None);
        let key = || a.vault.unlocked_key().unwrap();
        a.catalog
            .join_sync(
                &recovered(&setup, &*transport),
                JoinInto::Existing(Target::of(&a.vault)),
                &root(),
                MAC_A,
                Unlock::Test(&key),
            )
            .unwrap();

        let replica = opened(&a.root, a.id()).0.replica_id;
        assert!(!replicas.contains(&replica), "{replicas:?}");
        assert_eq!(vault_sync(&a).0, Some(replica.0));
        replicas.push(replica);
    }
}

#[test]
fn disable_interrupted_after_vault_save_leaves_no_sync_state_after_next_launch() {
    // A disable whose copy did not run, as when the app quits before it.
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    transport.set_unavailable(true);
    assert_eq!(disable(&fx).unwrap().value, Disabled::Waiting);
    transport.set_unavailable(false);

    let managed = Managed::start(&fx, false);
    managed.run();

    assert_eq!(sync_files(&fx), [false; 3]);
    assert_eq!(fx.read_case(), SyncLoad::NotSynced);

    // A sync state restored after a disable finished is not `leaving`. The
    // unlock writes nothing, and the manager deletes it at its start.
    let fx = Fixture::with_transport(GENERATION, None, transport.clone());
    fx.put_state(GENERATION);
    let before = fx.on_disk();
    fx.read().unwrap();
    assert_eq!(fx.on_disk(), before);

    let managed = Managed::start(&fx, false);
    managed.run();

    assert_eq!(sync_files(&fx), [false; 3]);
    assert_eq!(fx.read_case(), SyncLoad::NotSynced);
    assert_eq!(fx.on_disk().0, before.0);
    assert_eq!(managed.unlock.transactions(), 0);
}

#[test]
fn after_disable_no_transaction_joins_records_or_publishes_and_read_listing_lists_nothing() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let files = fx.catalog.files();
    put_peer(&fx, &transport, PEER, "joined");
    assert!(files.read_joins(fx.id()));
    transport.set_unavailable(true);
    assert_eq!(disable(&fx).unwrap().value, Disabled::Waiting);
    transport.set_unavailable(false);
    let leaving = fs::read(fx.state_path()).unwrap();
    let writes = transport.writes();

    // While the final file waits.
    fx.add_item().unwrap();
    // Past the minute between two read listings.
    files.advance_listing_clock(61);

    assert!(!files.read_joins(fx.id()));
    assert_eq!(fs::read(fx.state_path()).unwrap(), leaving);
    assert_eq!(transport.writes(), writes);
    assert!(saved_vault(&fx).get_item("item").is_ok());
    assert!(saved_vault(&fx).get_item("joined").is_err());

    // After the final file is copied.
    assert_eq!(
        files.copy_staged(fx.id(), Some(&fx.vault.path)).unwrap(),
        StagedCopy::Left
    );
    let writes = transport.writes();
    fx.write(|vh| vh.add_item("second", "Second").map(|_| ()))
        .unwrap();
    // Past the minute between two read listings.
    files.advance_listing_clock(61);

    assert!(!files.read_joins(fx.id()));
    assert_eq!(sync_files(&fx), [false; 3]);
    assert_eq!(transport.writes(), writes);
    assert!(saved_vault(&fx).get_item("joined").is_err());
}

#[test]
fn final_file_holds_own_left_entry_and_every_peer_view_holds_it() {
    let transport = Arc::new(FakeTransport::default());
    let pair = Pair::new(&transport);
    let c = Mac::new(transport.clone());
    let c_vault = Pair::join(&c, &pair.setup, &transport, MAC_C);
    let a = &pair.a;
    let replica = pair.replica();
    let before = state_files(&transport, a.id(), replica);

    assert_eq!(disable(a).unwrap().value, Disabled::Left);

    let added: Vec<StateHash> = state_files(&transport, a.id(), replica)
        .difference(&before)
        .copied()
        .collect();
    assert_eq!(added.len(), 1);
    let state = state_of_file(&transport, &pair.setup, added[0]);
    assert_eq!(
        VaultView::of(&state).left,
        BTreeMap::from([(replica, true)])
    );
    for (mac, vault) in [(&pair.b, &pair.b_vault), (&c, &c_vault)] {
        assert_eq!(Pair::left_of(mac, vault).get(&replica), Some(&true));
    }
}

#[test]
fn disable_while_stopped_by_drift_writes_left_only_and_diffs_nothing() {
    let transport = Arc::new(FakeTransport::default());
    let fx = Fixture::with_transport(GENERATION, Some(REPLICA), transport.clone());
    let mut stopped = state(fx.id(), REPLICA, GENERATION);
    stopped.stopped_build = Some(BUILD_ID.to_string());
    fx.put(&stopped, &TestSigner::device());
    // A stopped sync saves the edit locally and records nothing.
    fx.add_item().unwrap();
    let (_, before) = saved(&fx);
    assert!(VaultView::of(&before).items.is_empty());

    assert_eq!(disable(&fx).unwrap().value, Disabled::Left);

    let hashes = published(&transport, &fx);
    assert_eq!(hashes.len(), 1);
    let state = decode(&transport, &fx, hashes[0]);
    assert_eq!(new_write_ids(&before, &state).len(), 1);
    let mut view = VaultView::of(&state);
    assert_eq!(view.left.remove(&REPLICA), Some(true));
    assert_eq!(view, VaultView::of(&before));
    // The vault still holds the edit saved while stopped.
    assert!(saved_vault(&fx).get_item("item").is_ok());
    assert_eq!(vault_sync(&fx).0, None);
    assert_eq!(sync_files(&fx), [false; 3]);
}

#[test]
fn disable_of_sync_state_that_fails_its_signature_or_is_missing_saves_vault_and_deletes_three_files()
 {
    for name in ["signed by another key", "missing"] {
        let transport = Arc::new(FakeTransport::default());
        let fx = Fixture::with_transport(GENERATION, Some(REPLICA), transport.clone());
        if name == "signed by another key" {
            fx.put(&state(fx.id(), REPLICA, GENERATION), &TestSigner::random());
        }
        let staged = LocalSyncState::staged_path(&fx.root, fx.id());
        fs::create_dir_all(staged.parent().unwrap()).unwrap();
        fs::write(&staged, b"staged").unwrap();
        set_root(&fx, &folder_root());
        let writes = transport.writes();

        let disabled = disable(&fx).unwrap();

        assert_eq!(disabled.value, Disabled::Deleted, "{name}");
        assert_eq!(vault_sync(&fx), (None, GENERATION), "{name}");
        assert_eq!(sync_files(&fx), [false; 3], "{name}");
        assert_eq!(transport.writes(), writes, "{name}");
        assert_eq!(fx.read_case(), SyncLoad::NotSynced, "{name}");
    }
}

#[test]
fn crash_after_leaving_save_loads_as_leaving_and_next_transaction_finishes_disable_without_rebuild()
{
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    fx.add_item().unwrap();
    let (_, generation) = vault_sync(&fx);
    // The vault write fails after the `leaving` sync state is saved.
    let set_mode = |mode| fs::set_permissions(&fx.vaults_dir, fs::Permissions::from_mode(mode));
    set_mode(0o555).unwrap();
    let result = disable(&fx);
    set_mode(0o755).unwrap();

    assert!(matches!(result, Err(Error::VaultWriteError(_))));
    let (local, _) = saved(&fx);
    assert!(local.leaving);
    assert_eq!(vault_sync(&fx), (Some(REPLICA.0), generation));
    assert_eq!(fx.read_case(), SyncLoad::Leaving);
    assert_eq!(fx.write_case(), SyncLoad::Leaving);
    let before = fx.on_disk();
    fx.read().unwrap();
    assert_eq!(fx.on_disk(), before, "unlock writes nothing");

    fx.write(|_| Ok(())).unwrap();

    // The vault is saved without the replica id, at its generation, and is
    // not rebuilt from the sync state.
    assert_eq!(vault_sync(&fx), (None, generation));
    assert!(saved_vault(&fx).get_item("item").is_ok());
    assert_eq!(saved(&fx).0, local);
    assert_eq!(fx.read_case(), SyncLoad::DisableInProgress);
    assert_eq!(
        fx.catalog
            .files()
            .copy_staged(fx.id(), Some(&fx.vault.path))
            .unwrap(),
        StagedCopy::Left
    );
    assert!(published(&transport, &fx).contains(&local.staged_hash.unwrap()));
    assert_eq!(sync_files(&fx), [false; 3]);
}

#[test]
fn leaving_sync_state_with_no_vault_file_is_copied_and_deleted_by_manager() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    transport.set_unavailable(true);
    assert_eq!(disable(&fx).unwrap().value, Disabled::Waiting);
    transport.set_unavailable(false);
    let staged = saved(&fx).0.staged_hash.unwrap();
    fs::remove_file(&fx.vault.path).unwrap();
    assert!(fx.catalog.scan().missing.is_empty());

    let managed = Managed::start(&fx, false);
    managed.run();

    assert_eq!(published(&transport, &fx), [staged]);
    assert_eq!(sync_files(&fx), [false; 3]);
    assert_eq!(transport.watch_count(), 0);
    assert!(managed.events.taken().is_empty());
    assert!(fx.catalog.scan().missing.is_empty());
}

#[test]
fn disable_of_missing_vault_writes_final_file_from_trusted_state_and_deletes_untrusted_one() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    // A vault file holds the vault id.
    assert!(matches!(
        fx.catalog.disable_missing(fx.id(), Unlock::Test(&no_key)),
        Err(Error::VaultIdExists(_))
    ));
    fs::remove_file(&fx.vault.path).unwrap();
    assert_eq!(fx.catalog.scan().missing.len(), 1);
    let (_, before) = saved(&fx);

    let disabled = fx
        .catalog
        .disable_missing(fx.id(), Unlock::Test(&no_key))
        .unwrap();

    assert_eq!(disabled, Disabled::Left);
    let hashes = published(&transport, &fx);
    assert_eq!(hashes.len(), 1);
    let state = decode(&transport, &fx, hashes[0]);
    assert_eq!(new_write_ids(&before, &state).len(), 1);
    assert_eq!(VaultView::of(&state).left.get(&REPLICA), Some(&true));
    assert_eq!(sync_files(&fx), [false; 3]);
    assert!(fx.catalog.scan().missing.is_empty());
    assert!(matches!(
        fx.catalog.disable_missing(fx.id(), Unlock::Test(&no_key)),
        Err(Error::SyncNotEnabled)
    ));

    // A sync state that fails its signature writes no final file.
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let (local, _) = saved(&fx);
    fx.put(&local, &TestSigner::random());
    fs::remove_file(&fx.vault.path).unwrap();

    let disabled = fx
        .catalog
        .disable_missing(fx.id(), Unlock::Test(&no_key))
        .unwrap();

    assert_eq!(disabled, Disabled::Deleted);
    assert!(published(&transport, &fx).is_empty());
    assert_eq!(sync_files(&fx), [false; 3]);
    assert!(fx.catalog.scan().missing.is_empty());
}

#[test]
fn enable_join_and_disable_refuse_while_sync_state_is_leaving() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    transport.put_meta(fx.id(), &MetaFile::new(fx.id()).to_bytes());
    transport.set_unavailable(true);
    assert_eq!(disable(&fx).unwrap().value, Disabled::Waiting);
    transport.set_unavailable(false);
    let on_disk = fx.on_disk();
    let writes = transport.writes();
    let target = Target::of(&fx.vault);
    let join = JoinKey::recovered(RecoveredKey {
        vault_id: fx.id(),
        key_id: KeyId(1),
        key: key(),
        replica_id: ReplicaId::generate(),
    });
    let vault_key = || fx.vault.unlocked_key().unwrap();

    assert!(matches!(
        SyncSetup::prepare(fx.catalog.files(), &target, root(), MAC_A),
        Err(Error::SyncDisableInProgress)
    ));
    assert!(matches!(
        fx.catalog.join_sync(
            &join,
            JoinInto::Existing(target),
            &root(),
            MAC_A,
            Unlock::Test(&vault_key),
        ),
        Err(Error::SyncDisableInProgress)
    ));
    assert!(matches!(disable(&fx), Err(Error::SyncDisableInProgress)));
    assert_eq!(fx.on_disk(), on_disk);
    assert_eq!(transport.writes(), writes);

    // With no vault file, the import of a new vault is refused too.
    fs::remove_file(&fx.vault.path).unwrap();
    let new_key = || file_key(fx.id(), 2);
    assert!(matches!(
        fx.catalog
            .join_sync(&join, JoinInto::New, &root(), MAC_A, Unlock::Test(&new_key),),
        Err(Error::SyncDisableInProgress)
    ));
    assert_eq!(fs::read_to_string(fx.state_path()).ok(), on_disk.1);
    assert_eq!(transport.writes(), writes);
}

#[test]
fn delete_of_vault_that_is_not_synced_reads_no_key() {
    let fx = Fixture::new(0, None);

    fx.catalog
        .delete_with("personal", Unlock::Test(&no_key), remove_file)
        .unwrap();

    assert!(!fx.vault.path.exists());
    assert!(fx.catalog.list().is_empty());
}
