//! Join of a sync key into a local vault or a new one, with the recovery
//! merge (10.2).

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use jiff::Zoned;
use tempfile::TempDir;
use uuid::Uuid;

use super::load::{Fixture, GENERATION, REPLICA, device_key, state};
use super::state_file::key;
use super::transport::FakeTransport;
use super::txn::{saved, saved_vault, synced};
use super::view::State;
use crate::secrets::vaults::format::encrypted_vault::{EncryptedVault, VaultFileKey};
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::format::vault_cipher::VaultCipher;
use crate::secrets::vaults::model::{UnlockedKey, Vault};
use crate::secrets::vaults::storage::test_unlocker::KeyUnlocker;
use crate::secrets::vaults::storage::txn::{Committed, Target, Unlock, VaultWriter};
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::diff::LocalEdits;
use crate::secrets::vaults::sync::join_sync::{JoinInto, JoinKey};
use crate::secrets::vaults::sync::keys::{SyncKeyring, TestKeyWrapper};
use crate::secrets::vaults::sync::load::SyncLoad;
use crate::secrets::vaults::sync::local_state::{LocalSyncState, PinSource, PinnedKeys};
use crate::secrets::vaults::sync::meta::{MetaFile, MetaFileError};
use crate::secrets::vaults::sync::model::{ItemId, KeyId, PublicKey, ReplicaKeys};
use crate::secrets::vaults::sync::pairing::PairedVault;
use crate::secrets::vaults::sync::recovery::import::{RecoveredKey, RecoveryCheck, RecoveryImport};
use crate::secrets::vaults::sync::setup::{SetupStart, SyncSetup};
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::state_file::StateFile;
use crate::secrets::vaults::sync::status::{BUILD_ID, SyncStatus};
use crate::secrets::vaults::sync::transport::folder::FolderTransport;
use crate::secrets::vaults::sync::transport::folder::io::PlainIo;
use crate::secrets::vaults::sync::transport::{FileName, ReadResult, SyncTransport, TransportRoot};
use crate::secrets::vaults::sync::view::{AskRegister, Conflict, Entity, VaultView};
use crate::secrets::vaults::{Error, VaultCatalog, VaultHandle};

/// Display name of the Mac that enables sync.
const MAC_A: &str = "Work Mac";

/// Display name of the Mac that joins.
const MAC_B: &str = "Home Mac";

/// Display name of a third Mac.
const MAC_C: &str = "Studio Mac";

/// Root of the synced folder of the join tests.
pub(super) fn root() -> TransportRoot {
    TransportRoot::Folder {
        path: PathBuf::from("/join/Vaults"),
    }
}

/// Enable sync of the vault of `fx` with the synced folder `root`, as
/// [`MAC_A`]. Returns the setup, which holds the kit.
pub(super) fn enable(fx: &Fixture, root: TransportRoot) -> SyncSetup {
    let target = Target::of(&fx.vault);
    let setup = match SyncSetup::prepare(fx.catalog.files(), &target, root, MAC_A).unwrap() {
        SetupStart::Kit(setup) => setup,
        SetupStart::Join(root) => panic!("setup offered the join of {root}"),
    };
    let key = || fx.vault.unlocked_key().unwrap();
    setup
        .confirm(fx.catalog.files(), &target, Unlock::Test(&key))
        .unwrap();
    setup
}

/// Key opened with the kit of `setup` from the folder `transport`.
pub(super) fn recovered(setup: &SyncSetup, transport: &dyn SyncTransport) -> JoinKey {
    match RecoveryImport::check(setup.kit(), transport).unwrap() {
        RecoveryCheck::Recovered(key) => JoinKey::recovered(key),
        other => panic!("kit did not open the key: {other:?}"),
    }
}

/// Key of the vault of `fx`, a [`synced`] vault, under a new replica id.
fn relink_key(fx: &Fixture) -> JoinKey {
    JoinKey::recovered(RecoveredKey {
        vault_id: fx.id(),
        key_id: KeyId(1),
        key: key(),
        replica_id: ReplicaId::generate(),
    })
}

/// Write `meta.json` of the vault of `fx` in the folder `transport`, as a
/// setup writes it.
fn put_meta(transport: &FakeTransport, fx: &Fixture) {
    transport.put_meta(fx.id(), &MetaFile::new(fx.id()).to_bytes());
}

/// Join `join` into the vault of `fx` as [`MAC_A`].
fn join_fx(fx: &Fixture, join: &JoinKey) -> Result<Committed<Vec<ItemId>>, Error> {
    let key = || fx.vault.unlocked_key().unwrap();
    fx.catalog.join_sync(
        join,
        JoinInto::Existing(Target::of(&fx.vault)),
        &root(),
        MAC_A,
        Unlock::Test(&key),
    )
}

/// New file key of vault `vault_id`, whose wrapped form is `wrapped` in every
/// byte.
pub(super) fn file_key(vault_id: Uuid, wrapped: u8) -> UnlockedKey {
    UnlockedKey::for_test(
        VaultFileKey::new(vec![wrapped; 32]),
        VaultCipher::new(vault_id),
    )
}

/// Sync state of vault `vault_id` under the app data directory `root`, and
/// its body, opened with the keyring it holds.
pub(super) fn opened(root: &Path, vault_id: Uuid) -> (LocalSyncState, State) {
    let local = LocalSyncState::load(root, vault_id, &TestSigner::device()).unwrap();
    let keyring = SyncKeyring::unwrap(&local.sync_keys, &TestKeyWrapper).unwrap();
    let state = local.open(&keyring).unwrap();
    (local, state)
}

/// Conflict in the title of item `item`.
fn title_conflict(item: ItemId) -> Conflict {
    Conflict {
        entity: Entity::Item(item),
        register: AskRegister::Title,
    }
}

/// Values of the title register of item `item` in `state`.
fn titles(state: &State, item: ItemId) -> BTreeSet<String> {
    state
        .store
        .items
        .get(&item)
        .unwrap()
        .title
        .values()
        .map(|(_, v)| v.value.clone())
        .collect()
}

/// Mac with its own app data directory and vaults directory, that syncs
/// through the folder `transport`.
pub(super) struct Mac {
    _dir: TempDir,
    pub(super) root: PathBuf,
    pub(super) vaults_dir: PathBuf,
    pub(super) catalog: VaultCatalog,
}

impl Mac {
    pub(super) fn new(transport: Arc<dyn SyncTransport>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("data");
        let vaults_dir = dir.path().join("vaults");
        fs::create_dir_all(&vaults_dir).unwrap();
        let files = VaultWriter::isolated(&root).with_transport(transport);
        let catalog = VaultCatalog::with_unlocker(
            vaults_dir.clone(),
            files,
            Vec::new(),
            Arc::new(KeyUnlocker(HashMap::new())),
        );
        Self {
            _dir: dir,
            root,
            vaults_dir,
            catalog,
        }
    }

    /// Copy of the vault file of `fx` on this Mac, unlocked, as an import of
    /// one export on both Macs. It holds the vault id and the file key of
    /// `fx`.
    pub(super) fn copy_of(&self, fx: &Fixture) -> VaultHandle {
        let path = VaultHandle::file_path(&self.vaults_dir, fx.id());
        fs::copy(&fx.vault.path, &path).unwrap();
        VaultHandle::unlocked(path, saved_vault(fx))
    }

    /// Run `f` in a transaction on the vault `vh` of this Mac.
    fn write(
        &self,
        vh: &VaultHandle,
        f: impl FnOnce(&mut VaultHandle) -> Result<(), Error>,
    ) -> Result<Committed<()>, Error> {
        let key = || vh.unlocked_key().unwrap();
        self.catalog
            .files()
            .write(&Target::of(vh), Unlock::Test(&key), f)
    }

    /// Join `join` into `into` as the Mac named `name`, with the file key
    /// `file_key`.
    fn join(
        &self,
        join: &JoinKey,
        into: JoinInto,
        name: &str,
        file_key: &UnlockedKey,
    ) -> Result<Committed<Vec<ItemId>>, Error> {
        let key = || file_key.duplicate_for_test();
        self.catalog
            .join_sync(join, into, &root(), name, Unlock::Test(&key))
    }

    /// Vault file of `vh` as saved, verified.
    pub(super) fn saved(&self, vh: &VaultHandle) -> Vault {
        let file = EncryptedVault::load(&vh.path, &TestSigner::device()).unwrap();
        Vault::from_unlocked_key(&vh.unlocked_key().unwrap(), file).unwrap()
    }

    /// App data files of vault `vault_id` that a join writes: the sync state,
    /// the staged file, and the sidecar.
    pub(super) fn sync_files(&self, vault_id: Uuid) -> [bool; 3] {
        [
            LocalSyncState::path(&self.root, vault_id),
            LocalSyncState::staged_path(&self.root, vault_id),
            Sidecar::path(&self.root, vault_id),
        ]
        .map(|path| path.exists())
    }
}

/// Synced folder in a temp directory, read with `PlainIo`.
struct Folder {
    _dir: TempDir,
    root: PathBuf,
    transport: Arc<FolderTransport>,
}

impl Folder {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Vaults");
        let temp = dir.path().join("temp");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&temp).unwrap();
        let transport = Arc::new(FolderTransport::new(&root, Arc::new(PlainIo::new(temp))));
        Self {
            _dir: dir,
            root,
            transport,
        }
    }

    fn transport_root(&self) -> TransportRoot {
        TransportRoot::Folder {
            path: self.root.clone(),
        }
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

/// Join `fx` under a new replica id, and assert that the join fails as
/// `refused` holds and writes nothing.
fn assert_join_refused(fx: &Fixture, transport: &FakeTransport, refused: impl Fn(&Error) -> bool) {
    let on_disk = fx.on_disk();
    let sidecar = fs::read(Sidecar::path(&fx.root, fx.id())).ok();
    let staged = fs::read(LocalSyncState::staged_path(&fx.root, fx.id())).ok();
    let writes = transport.writes();

    match join_fx(fx, &relink_key(fx)) {
        Err(e) => assert!(refused(&e), "{e:?}"),
        Ok(_) => panic!("join was not refused"),
    }
    assert_eq!(fx.on_disk(), on_disk);
    assert_eq!(fs::read(Sidecar::path(&fx.root, fx.id())).ok(), sidecar);
    assert_eq!(
        fs::read(LocalSyncState::staged_path(&fx.root, fx.id())).ok(),
        staged
    );
    assert_eq!(transport.writes(), writes);
}

#[test]
fn joining_folder_from_vault_imported_from_export_adds_local_entries_and_shows_title_as_conflict() {
    let transport = Arc::new(FakeTransport::default());
    let a = Fixture::with_transport(0, None, transport.clone());
    a.write(|vh| {
        vh.add_item("shared", "Shared")?;
        vh.add_item("kept", "Kept").map(|_| ())
    })
    .unwrap();
    // Both Macs import one export.
    let b = Mac::new(transport.clone());
    let b_vault = b.copy_of(&a);
    let setup = enable(&a, root());
    // Mac B edits a title and adds an item, then joins with the kit of A.
    b.write(&b_vault, |vh| {
        vh.add_item("shared", "Home")?;
        vh.add_item("local", "Local").map(|_| ())
    })
    .unwrap();
    let join = recovered(&setup, &*transport);
    let committed = b
        .join(
            &join,
            JoinInto::Existing(Target::of(&b_vault)),
            MAC_B,
            &b_vault.unlocked_key().unwrap(),
        )
        .unwrap();

    assert!(committed.changed);
    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    assert!(committed.value.is_empty());
    let (local, state) = opened(&b.root, a.id());
    assert_eq!(local.replica_id, join.replica_id());
    let vault = b.saved(&b_vault);
    let shared = vault.get_item("shared").unwrap().id;
    let view = VaultView::of(&state);
    // The differing title is a conflict. The joined value is shown, and the
    // local value is kept in the register.
    assert_eq!(view.conflicts(), [title_conflict(shared)]);
    assert_eq!(
        titles(&state, shared),
        BTreeSet::from(["Home".to_string(), "Shared".to_string()])
    );
    assert_eq!(vault.get_item("shared").unwrap().title, "Shared");
    // No local entry is lost.
    for key in ["kept", "local"] {
        assert!(vault.get_item(key).is_ok(), "{key}");
    }
    assert!(
        LocalEdits::find(&state, &vault, join.replica_id())
            .unwrap()
            .is_empty()
    );

    // Mac A joins the published state of Mac B.
    a.write(|_| Ok(())).unwrap();
    let (_, a_state) = opened(&a.root, a.id());
    assert_eq!(VaultView::of(&a_state), view);
    assert!(saved_vault(&a).get_item("local").is_ok());
}

#[test]
fn relink_after_failed_sync_state_signature_shows_edits_saved_while_stopped_as_conflicts() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    put_meta(&transport, &fx);
    fx.write(|vh| vh.add_item("item", "Item").map(|_| ()))
        .unwrap();
    // The sync state fails its signature, and edits are saved while sync is
    // stopped.
    let (local, _) = saved(&fx);
    fx.put(&local, &TestSigner::random());
    assert!(matches!(fx.write_case(), SyncLoad::SignatureFailed(_)));
    fx.write(|vh| {
        vh.add_item("item", "Local")?;
        vh.add_item("added", "Added").map(|_| ())
    })
    .unwrap();
    let v = saved_vault(&fx).generation();

    let join = relink_key(&fx);
    let committed = join_fx(&fx, &join).unwrap();

    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    let (local, state) = saved(&fx);
    assert_eq!(local.replica_id, join.replica_id());
    assert_ne!(local.replica_id, REPLICA);
    assert_eq!(local.generation, v + 1);
    let vault = saved_vault(&fx);
    assert_eq!(vault.generation(), v + 1);
    assert_eq!(vault.replica_id(), Some(join.replica_id().0));
    // The published title of the old replica is shown, and the edit saved
    // while stopped is a conflict.
    let item = vault.get_item("item").unwrap().id;
    assert_eq!(VaultView::of(&state).conflicts(), [title_conflict(item)]);
    assert_eq!(
        titles(&state, item),
        BTreeSet::from(["Item".to_string(), "Local".to_string()])
    );
    assert_eq!(vault.get_item("item").unwrap().title, "Item");
    assert!(vault.get_item("added").is_ok());
    assert_eq!(fx.read_case(), SyncLoad::Current);
}

#[test]
fn relink_of_vault_whose_sync_state_is_missing_takes_new_replica_id_and_merges() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    put_meta(&transport, &fx);
    fx.add_item().unwrap();
    fs::remove_file(fx.state_path()).unwrap();
    assert_eq!(fx.write_case(), SyncLoad::StateMissing);
    fx.write(|vh| vh.add_item("item", "Local").map(|_| ()))
        .unwrap();

    let join = relink_key(&fx);
    join_fx(&fx, &join).unwrap();

    let (local, state) = saved(&fx);
    assert_eq!(local.replica_id, join.replica_id());
    assert_ne!(local.replica_id, REPLICA);
    // The files of the old replica are joined as those of a peer.
    assert_eq!(
        local.pinned_keys.get(&REPLICA).map(|pin| pin.source),
        Some(PinSource::FirstUse)
    );
    let vault = saved_vault(&fx);
    let item = vault.get_item("item").unwrap().id;
    assert_eq!(VaultView::of(&state).conflicts(), [title_conflict(item)]);
    assert_eq!(vault.replica_id(), Some(join.replica_id().0));
    assert_eq!(fx.read_case(), SyncLoad::Current);
}

#[test]
fn join_of_vault_whose_sync_runs_is_stopped_or_is_leaving_is_refused_and_writes_nothing() {
    let transport = Arc::new(FakeTransport::default());

    let fx = synced(&transport);
    fx.add_item().unwrap();
    put_meta(&transport, &fx);
    assert_join_refused(&fx, &transport, |e| matches!(e, Error::SyncAlreadyEnabled));

    let fx = Fixture::with_transport(GENERATION, Some(REPLICA), transport.clone());
    let mut stopped = state(fx.id(), REPLICA, GENERATION);
    stopped.stopped_build = Some(BUILD_ID.to_string());
    fx.put(&stopped, &TestSigner::device());
    put_meta(&transport, &fx);
    assert_join_refused(&fx, &transport, |e| matches!(e, Error::SyncAlreadyEnabled));

    // A `leaving` sync state, with or without the replica id in the vault.
    for replica in [Some(REPLICA), None] {
        let generation = replica.map_or(0, |_| GENERATION);
        let fx = Fixture::with_transport(generation, replica, transport.clone());
        let mut leaving = state(fx.id(), REPLICA, GENERATION);
        leaving.leaving = true;
        fx.put(&leaving, &TestSigner::device());
        put_meta(&transport, &fx);
        assert_join_refused(&fx, &transport, |e| {
            matches!(e, Error::SyncDisableInProgress)
        });
    }
}

#[test]
fn import_of_vault_id_held_on_this_mac_or_with_leaving_sync_state_is_refused() {
    let transport = Arc::new(FakeTransport::default());
    let a = Fixture::with_transport(0, None, transport.clone());
    let setup = enable(&a, root());

    // A vault file of the id makes the join an `Existing` one.
    let b = Mac::new(transport.clone());
    b.copy_of(&a);
    let join = recovered(&setup, &*transport);
    assert!(matches!(
        b.join(&join, JoinInto::New, MAC_B, &file_key(a.id(), 2)),
        Err(Error::VaultIdExists(_))
    ));
    assert_eq!(b.sync_files(a.id()), [false; 3]);

    let b = Mac::new(transport.clone());
    let mut leaving = state(a.id(), REPLICA, GENERATION);
    leaving.leaving = true;
    leaving.save(&b.root, &TestSigner::device()).unwrap();
    let writes = transport.writes();
    assert!(matches!(
        b.join(&join, JoinInto::New, MAC_B, &file_key(a.id(), 2)),
        Err(Error::SyncDisableInProgress)
    ));
    assert!(!VaultHandle::file_path(&b.vaults_dir, a.id()).exists());
    assert_eq!(b.sync_files(a.id()), [true, false, false]);
    assert_eq!(transport.writes(), writes);
}

#[test]
fn import_builds_vault_as_view_with_new_file_key_and_vault_key_from_view_name_made_unique() {
    let transport = Arc::new(FakeTransport::default());
    let a = Fixture::with_transport(0, None, transport.clone());
    a.write(|vh| {
        vh.get_unlocked_vault_mut()?.name = Some("Family".to_string());
        vh.add_item("item", "Item").map(|_| ())
    })
    .unwrap();
    let setup = enable(&a, root());
    // Mac B holds another vault with the key of the view name.
    let b = Mac::new(transport.clone());
    let other = Vault::with_unlocked_key("family".to_string(), &file_key(Uuid::new_v4(), 3));
    b.catalog
        .files()
        .create(&VaultHandle::new_in(&b.vaults_dir, other))
        .unwrap();

    let join = recovered(&setup, &*transport);
    let committed = b
        .join(&join, JoinInto::New, MAC_B, &file_key(a.id(), 2))
        .unwrap();

    let date = Zoned::now().date().strftime("%Y%m%d");
    assert_eq!(committed.vault.key, format!("family-{date}-1"));
    assert_eq!(
        committed.vault.path,
        VaultHandle::file_path(&b.vaults_dir, a.id())
    );
    assert!(committed.changed);
    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    let (local, state) = opened(&b.root, a.id());
    let vault = b.saved(&committed.vault);
    assert_eq!(local.generation, 1);
    assert_eq!(vault.generation(), 1);
    assert_eq!(vault.replica_id(), Some(join.replica_id().0));
    assert_eq!(vault.name.as_deref(), Some("Family"));
    assert_eq!(vault.get_item("item").unwrap().title, "Item");
    assert!(
        LocalEdits::find(&state, &vault, join.replica_id())
            .unwrap()
            .is_empty()
    );
    // The vault file is under the new file key of Mac B, not that of Mac A.
    let file = EncryptedVault::load(&committed.vault.path, &TestSigner::device()).unwrap();
    assert!(matches!(
        Vault::from_unlocked_key(&a.vault.unlocked_key().unwrap(), file),
        Err(Error::VaultFileKeyChanged)
    ));
    assert!(b.catalog.list().contains_key(&committed.vault.key));
}

#[test]
fn first_state_of_join_holds_own_name_and_keys_and_pins_paired_mac_and_other_peers_at_first_use() {
    let transport = Arc::new(FakeTransport::default());
    let a = Fixture::with_transport(0, None, transport.clone());
    let setup = enable(&a, root());
    let c = Mac::new(transport.clone());
    let c_join = recovered(&setup, &*transport);
    c.join(&c_join, JoinInto::New, MAC_C, &file_key(a.id(), 3))
        .unwrap();
    // Mac B pairs with Mac A. Every Mac has the test keys.
    let keys = ReplicaKeys {
        encryption: TestKeyWrapper::public_key(),
        signing: PublicKey(device_key()),
    };
    let paired = PairedVault {
        vault_id: a.id(),
        replica_id: ReplicaId::generate(),
        key_id: KeyId(1),
        key: setup.key().clone(),
        peer: setup.replica_id(),
        pin: PinnedKeys {
            source: PinSource::Pairing,
            encryption: keys.encryption.clone(),
            signing: keys.signing.clone(),
            revoked: false,
        },
    };
    let join = JoinKey::paired(paired);
    let b = Mac::new(transport.clone());
    b.join(&join, JoinInto::New, MAC_B, &file_key(a.id(), 2))
        .unwrap();

    let (local, state) = opened(&b.root, a.id());
    let own = join.replica_id();
    assert_eq!(
        state.store.replica_names.get(&own).unwrap().shown(),
        Some(&MAC_B.to_string())
    );
    assert_eq!(
        state.store.replica_keys.get(&own).unwrap().shown(),
        Some(&keys)
    );
    // A new vault adds no difference, so the own registers are the one
    // write of the one actor of Mac B.
    let actors: Vec<_> = state
        .actors
        .iter()
        .filter(|(_, info)| info.replica == own)
        .map(|(actor, _)| *actor)
        .collect();
    assert_eq!(actors.len(), 1);
    assert_eq!(state.context.get(actors[0]), 1);
    assert_eq!(
        local
            .pinned_keys
            .get(&setup.replica_id())
            .map(|pin| pin.source),
        Some(PinSource::Pairing)
    );
    assert_eq!(
        local
            .pinned_keys
            .get(&c_join.replica_id())
            .map(|pin| pin.source),
        Some(PinSource::FirstUse)
    );
    assert_eq!(local.pinned_keys.len(), 2);
}

#[test]
fn next_transaction_after_join_finds_no_drift_and_publishes_nothing_and_macs_converge() {
    let transport = Arc::new(FakeTransport::default());
    let a = Fixture::with_transport(0, None, transport.clone());
    a.write(|vh| vh.add_item("item", "Item").map(|_| ()))
        .unwrap();
    let setup = enable(&a, root());
    let b = Mac::new(transport.clone());
    let join = recovered(&setup, &*transport);
    let b_vault = b
        .join(&join, JoinInto::New, MAC_B, &file_key(a.id(), 2))
        .unwrap()
        .vault;
    let writes = transport.writes();
    let (_, before) = opened(&b.root, a.id());

    let committed = b.write(&b_vault, |_| Ok(())).unwrap();

    assert!(!committed.changed);
    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    assert_eq!(transport.writes(), writes);
    let (local, state) = opened(&b.root, a.id());
    assert_eq!(state, before);
    assert_eq!(local.stopped_build, None);

    // An edit on Mac B reaches Mac A, and both Macs hold one view.
    b.write(&b_vault, |vh| vh.add_item("home", "Home").map(|_| ()))
        .unwrap();
    a.write(|_| Ok(())).unwrap();
    b.write(&b_vault, |_| Ok(())).unwrap();
    let (_, a_state) = opened(&a.root, a.id());
    let (_, b_state) = opened(&b.root, a.id());
    assert_eq!(VaultView::of(&a_state), VaultView::of(&b_state));
    assert!(saved_vault(&a).get_item("home").is_ok());
    assert!(b.saved(&b_vault).get_item("item").is_ok());
    assert_eq!(a.write_case(), SyncLoad::Current);
}

#[test]
fn peer_file_that_is_remote_at_join_is_requested_and_joined_by_later_transaction() {
    let transport = Arc::new(FakeTransport::default());
    let a = Fixture::with_transport(0, None, transport.clone());
    a.write(|vh| vh.add_item("item", "Item").map(|_| ()))
        .unwrap();
    let setup = enable(&a, root());
    let join = recovered(&setup, &*transport);
    // The state file of Mac A is not local on Mac B yet.
    let published = Sidecar::load(&a.root, a.id()).last_publish.unwrap();
    let a_replica = setup.replica_id();
    let ReadResult::Local(bytes) = transport
        .read(a.id(), a_replica, FileName::State(published))
        .unwrap()
    else {
        panic!("published state file is not local");
    };
    transport.put_remote_with(
        a.id(),
        a_replica,
        &StateFile::name(a.id(), published),
        &bytes,
    );
    let b = Mac::new(transport.clone());

    let committed = b
        .join(&join, JoinInto::New, MAC_B, &file_key(a.id(), 2))
        .unwrap();

    let b_vault = committed.vault;
    assert!(b.saved(&b_vault).get_item("item").is_err());
    assert_eq!(transport.download_requests(), [a.id()]);

    assert_eq!(transport.complete_downloads(a.id()), 1);
    let committed = b.write(&b_vault, |_| Ok(())).unwrap();
    assert!(committed.changed);
    assert!(b.saved(&b_vault).get_item("item").is_ok());
}

#[test]
fn folder_with_no_meta_json_for_vault_or_newer_one_fails_join_and_writes_nothing() {
    let transport = Arc::new(FakeTransport::default());
    let b = Mac::new(transport.clone());
    let vault_id = Uuid::new_v4();
    let join = JoinKey::recovered(RecoveredKey {
        vault_id,
        key_id: KeyId(1),
        key: key(),
        replica_id: ReplicaId::generate(),
    });

    assert!(matches!(
        b.join(&join, JoinInto::New, MAC_B, &file_key(vault_id, 2)),
        Err(Error::SyncFolderLacksVault)
    ));
    let newer = format!(r#"{{"format_version":2,"vault_id":"{vault_id}"}}"#);
    transport.put_meta(vault_id, newer.as_bytes());
    assert!(matches!(
        b.join(&join, JoinInto::New, MAC_B, &file_key(vault_id, 2)),
        Err(Error::SyncMetaFileError(MetaFileError::VersionSkew(_)))
    ));
    assert_eq!(b.sync_files(vault_id), [false; 3]);
    assert!(!VaultHandle::file_path(&b.vaults_dir, vault_id).exists());
    assert_eq!(transport.writes(), 0);

    // A local vault of the id is not joined either.
    let fx = Fixture::with_transport(0, None, transport.clone());
    let on_disk = fx.on_disk();
    assert!(matches!(
        join_fx(&fx, &relink_key(&fx)),
        Err(Error::SyncFolderLacksVault)
    ));
    assert_eq!(fx.on_disk(), on_disk);
    assert_eq!(transport.writes(), 0);
}

#[test]
fn join_through_folder_transport_with_plain_io_writes_own_state_file_and_key_json() {
    let folder = Folder::new();
    let a = Fixture::with_transport(0, None, folder.transport.clone());
    a.write(|vh| vh.add_item("item", "Item").map(|_| ()))
        .unwrap();
    let setup = enable(&a, folder.transport_root());
    let join = recovered(&setup, &*folder.transport);
    let b = Mac::new(folder.transport.clone());
    let b_key = file_key(a.id(), 2);
    let key = || b_key.duplicate_for_test();

    let committed = b
        .catalog
        .join_sync(
            &join,
            JoinInto::New,
            &folder.transport_root(),
            MAC_B,
            Unlock::Test(&key),
        )
        .unwrap();

    assert_eq!(committed.sync_status, Some(SyncStatus::Active));
    let sidecar = Sidecar::load(&b.root, a.id());
    assert_eq!(sidecar.transport, Some(folder.transport_root()));
    let replica_dir = folder
        .root
        .join(ShortId::encode_uuid(a.id()))
        .join(ShortId::encode_uuid(join.replica_id().0));
    let mut names = vec![
        StateFile::name(a.id(), sidecar.last_publish.unwrap()),
        "key.json".to_string(),
    ];
    names.sort();
    assert_eq!(Folder::names(&replica_dir), names);
    assert!(b.saved(&committed.vault).get_item("item").is_ok());

    // Mac A joins the state of Mac B.
    a.write(|_| Ok(())).unwrap();
    let (_, a_state) = opened(&a.root, a.id());
    assert_eq!(
        a_state
            .store
            .replica_names
            .get(&join.replica_id())
            .unwrap()
            .shown(),
        Some(&MAC_B.to_string())
    );
}

#[test]
fn conflict_copy_of_meta_json_is_not_read_at_import() {
    let folder = Folder::new();
    let vault_id = Uuid::new_v4();
    let vault_dir = folder.root.join(ShortId::encode_uuid(vault_id));
    fs::create_dir(&vault_dir).unwrap();
    fs::write(
        vault_dir.join("meta 2.json"),
        MetaFile::new(vault_id).to_bytes(),
    )
    .unwrap();
    let b = Mac::new(folder.transport.clone());
    let join = JoinKey::recovered(RecoveredKey {
        vault_id,
        key_id: KeyId(1),
        key: key(),
        replica_id: ReplicaId::generate(),
    });

    assert!(matches!(
        b.join(&join, JoinInto::New, MAC_B, &file_key(vault_id, 2)),
        Err(Error::SyncFolderLacksVault)
    ));
    assert_eq!(Folder::names(&vault_dir), ["meta 2.json"]);
    assert_eq!(b.sync_files(vault_id), [false; 3]);
    assert!(!VaultHandle::file_path(&b.vaults_dir, vault_id).exists());
}
