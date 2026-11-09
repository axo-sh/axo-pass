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

mod first_state;
mod import;
mod relink;

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
