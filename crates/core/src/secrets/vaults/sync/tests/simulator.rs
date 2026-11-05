//! Simulator of Macs that sync one vault through encoded state files.
//!
//! Each Mac holds a vault file, a local sync state, and a sidecar under its
//! own app data directory, and runs every edit as a `VaultWriter` transaction
//! with the view applied to its vault. Each Mac reads its own copy of the
//! synced folder, a `FakeTransport`. A file a Mac publishes enters the folder
//! of every Mac only by delivery. As in the milestone 4 simulator, a delivery
//! hands a Mac any past file of a peer, so files arrive in any order, some
//! twice or never, and each Mac joins a different subset of the files.
//!
//! After each transaction the vault shows the view of the saved state, and a
//! transaction with no edit mints no write id. A Mac publishes if and only if
//! its context moved past the context of its last published file.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use proptest::collection::vec;
use proptest::prelude::*;
use proptest::sample::select;
use secrecy::SecretString;
use tempfile::TempDir;
use uuid::Uuid;

use super::load::{GENERATION, body, device_key, state_of};
use super::state_file::keyring;
use super::transport::FakeTransport;
use super::txn::new_write_ids;
use super::view::State;
use crate::secrets::vaults::format::encrypted_vault::EncryptedVault;
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::model::Vault;
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::storage::handle::normalized_key;
use crate::secrets::vaults::storage::txn::{Committed, Target, Unlock, VaultWriter};
use crate::secrets::vaults::sync::crdt::{Ask, CausalContext, MvRegister, ReplicaId, WriteId};
use crate::secrets::vaults::sync::diff::LocalEdits;
use crate::secrets::vaults::sync::local_state::LocalSyncState;
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::state_file::{StateFile, StateHash};
use crate::secrets::vaults::sync::status::SyncStatus;
use crate::secrets::vaults::sync::transport::{FileName, ReadResult, SyncTransport};
use crate::secrets::vaults::sync::view::VaultView;
use crate::secrets::vaults::{Error, VaultHandle};

/// Item keys of generated edits. Few, so Macs create one key concurrently.
const ITEM_KEYS: &[&str] = &["mail", "bank"];
const CREDENTIAL_KEYS: &[&str] = &["password", "pin"];
const TITLES: &[&str] = &["Mail", "Bank"];

/// Edit of one transaction. An index picks a live entry, or a trashed item,
/// in id order, modulo their number. An edit with nothing to pick changes
/// nothing.
#[derive(Clone, Debug)]
enum Edit {
    /// Add an item, or set its title if the vault holds the key.
    Item {
        key: &'static str,
        title: &'static str,
    },
    /// Add a credential to a live item, or set its value if the item holds
    /// the key.
    Credential {
        item: u8,
        key: &'static str,
    },
    TrashItem(u8),
    /// Restore a trashed item with its key. Nothing changes if the key is
    /// taken.
    RestoreItem(u8),
    TrashCredential {
        item: u8,
        credential: u8,
    },
}

impl Edit {
    fn strategy() -> impl Strategy<Value = Self> {
        prop_oneof![
            3 => (select(ITEM_KEYS), select(TITLES))
                .prop_map(|(key, title)| Self::Item { key, title }),
            2 => (any::<u8>(), select(CREDENTIAL_KEYS))
                .prop_map(|(item, key)| Self::Credential { item, key }),
            1 => any::<u8>().prop_map(Self::TrashItem),
            1 => any::<u8>().prop_map(Self::RestoreItem),
            1 => (any::<u8>(), any::<u8>())
                .prop_map(|(item, credential)| Self::TrashCredential { item, credential }),
        ]
    }

    /// Entry of `entries` picked by `index`.
    fn pick<T: Clone>(entries: &[T], index: u8) -> Option<T> {
        match entries.len() {
            0 => None,
            len => Some(entries[usize::from(index) % len].clone()),
        }
    }

    /// Keys of the live items of `vh`, in id order.
    fn live_items(vh: &VaultHandle) -> Result<Vec<String>, Error> {
        let mut items: Vec<_> = vh
            .list_items()?
            .into_iter()
            .map(|item| (item.id, item.key.clone()))
            .collect();
        items.sort();
        Ok(items.into_iter().map(|(_, key)| key).collect())
    }

    fn apply(&self, vh: &mut VaultHandle) -> Result<(), Error> {
        match self {
            Self::Item { key, title } => vh.add_item(key, title).map(|_| ()),
            Self::Credential { item, key } => {
                let Some(item) = Self::pick(&Self::live_items(vh)?, *item) else {
                    return Ok(());
                };
                let value = SecretString::from("value".to_string());
                vh.add_secret(&item, key, "Field", FieldKind::default(), value)
            },
            Self::TrashItem(item) => match Self::pick(&Self::live_items(vh)?, *item) {
                Some(item) => vh.delete_item(&item),
                None => Ok(()),
            },
            Self::RestoreItem(item) => {
                let mut trashed: Vec<Uuid> = vh
                    .list_deleted_items()?
                    .iter()
                    .map(|deleted| deleted.item.id)
                    .collect();
                trashed.sort();
                let Some(id) = Self::pick(&trashed, *item) else {
                    return Ok(());
                };
                match vh.restore_item(id, None) {
                    Err(Error::DuplicateItemKey(_)) => Ok(()),
                    other => other,
                }
            },
            Self::TrashCredential { item, credential } => {
                let Some(item) = Self::pick(&Self::live_items(vh)?, *item) else {
                    return Ok(());
                };
                let overview = vh.get_item_overview(&item)?.expect("picked item is live");
                let mut credentials: Vec<_> = overview
                    .credentials
                    .values()
                    .map(|c| (c.id, c.key.clone()))
                    .collect();
                credentials.sort();
                let keys: Vec<String> = credentials.into_iter().map(|(_, key)| key).collect();
                match Self::pick(&keys, *credential) {
                    Some(key) => vh.delete_item_credential(&item, &key),
                    None => Ok(()),
                }
            },
        }
    }
}

/// Step of a simulator run. `mac` is the index of the Mac that takes it.
#[derive(Clone, Debug)]
enum Step {
    /// One transaction with an edit.
    Edit { mac: usize, edit: Edit },
    /// Delivery of a past file of a peer picked by `from`, then one
    /// transaction with no edit. Only the transaction runs if the peer has
    /// published no file.
    Deliver { mac: usize, from: u8, file: u8 },
}

impl Step {
    fn strategy(macs: usize) -> impl Strategy<Value = Self> {
        prop_oneof![
            3 => (0..macs, Edit::strategy()).prop_map(|(mac, edit)| Self::Edit { mac, edit }),
            2 => (0..macs, any::<u8>(), any::<u8>())
                .prop_map(|(mac, from, file)| Self::Deliver { mac, from, file }),
        ]
    }

    /// Up to 15 steps of `macs` Macs.
    fn steps(macs: usize) -> impl Strategy<Value = Vec<Self>> {
        vec(Self::strategy(macs), 0..16)
    }
}

/// State file in the synced folder.
struct Published {
    /// Index of the Mac that wrote it.
    mac: usize,
    hash: StateHash,
    bytes: Vec<u8>,
    /// Deleted by its Mac after a later publish. A removed file is still
    /// delivered, as a stale copy.
    removed: bool,
}

/// One Mac with its app data directory and its copy of the synced folder.
pub(super) struct Mac {
    _dir: TempDir,
    root: PathBuf,
    pub(super) replica: ReplicaId,
    /// Vault as created, for its path and file key.
    pub(super) vault: VaultHandle,
    writer: VaultWriter,
    /// Copy of the synced folder that this Mac reads and writes.
    transport: Arc<FakeTransport>,
    /// Context of the last file this Mac published.
    published: CausalContext,
}

impl Mac {
    fn vault_id(&self) -> Uuid {
        self.vault.vault_id().unwrap()
    }

    /// Run `f` in a transaction on the vault.
    fn write(&self, f: impl FnOnce(&mut VaultHandle) -> Result<(), Error>) -> Committed<()> {
        let key = || self.vault.unlocked_key().unwrap();
        self.writer
            .write(&Target::of(&self.vault), Unlock::Test(&key), f)
            .unwrap()
    }

    /// Body of the saved sync state.
    pub(super) fn state(&self) -> State {
        let local =
            LocalSyncState::load(&self.root, self.vault_id(), &TestSigner::device()).unwrap();
        local.open(&keyring()).unwrap()
    }

    /// Vault file as saved, verified.
    pub(super) fn saved_vault(&self) -> Vault {
        let file = EncryptedVault::load(&self.vault.path, &TestSigner::device()).unwrap();
        Vault::from_unlocked_key(&self.vault.unlocked_key().unwrap(), file).unwrap()
    }

    /// Vault file, sync state, sidecar, and staged file as they are on disk.
    fn on_disk(&self) -> Vec<Option<Vec<u8>>> {
        let id = self.vault_id();
        [
            self.vault.path.clone(),
            LocalSyncState::path(&self.root, id),
            Sidecar::path(&self.root, id),
            LocalSyncState::staged_path(&self.root, id),
        ]
        .iter()
        .map(|path| fs::read(path).ok())
        .collect()
    }
}

/// Macs of one vault, with every file they published.
pub(super) struct Sim {
    vault_id: Uuid,
    pub(super) macs: Vec<Mac>,
    files: Vec<Published>,
    /// Context of the saved state after each mint, by write id of the mint.
    observed: BTreeMap<WriteId, CausalContext>,
}

impl Sim {
    /// Replica id of Mac `n`.
    pub(super) fn replica(n: usize) -> ReplicaId {
        ReplicaId(Uuid::from_u128(n as u128 + 1))
    }

    /// `macs` Macs of one vault at [`GENERATION`], each with a sync state
    /// that holds the `replica_keys` entry of every Mac. Mac `n` of `slow`
    /// mints with its clock off by `seconds`.
    pub(super) fn new(macs: usize, slow: Option<(usize, i64)>) -> Self {
        let mut initial = State::default();
        for n in 0..macs {
            initial.join(body(Self::replica(n), &[device_key()]));
        }
        let file_key = Vault::new_for_test().unlocked_key();
        let vault_id = file_key.vault_id();
        let macs = (0..macs)
            .map(|n| {
                let dir = tempfile::tempdir().unwrap();
                let root = dir.path().join("data");
                let replica = Self::replica(n);
                let transport = Arc::new(FakeTransport::default());
                let mut writer = VaultWriter::isolated(&root).with_transport(transport.clone());
                if let Some((_, seconds)) = slow.filter(|(slow, _)| *slow == n) {
                    writer = writer.with_clock_offset(seconds);
                }
                let mut vault = Vault::with_unlocked_key("personal".to_string(), &file_key);
                vault.set_sync(GENERATION, Some(replica.0));
                let vh = VaultHandle::new_in(&dir.path().join("vaults"), vault);
                writer.create(&vh).unwrap();
                state_of(vault_id, replica, GENERATION, &initial)
                    .save(&root, &TestSigner::device())
                    .unwrap();
                Mac {
                    _dir: dir,
                    root,
                    replica,
                    vault: vh,
                    writer,
                    transport,
                    published: CausalContext::default(),
                }
            })
            .collect();
        Self {
            vault_id,
            macs,
            files: Vec::new(),
            observed: BTreeMap::new(),
        }
    }

    fn apply_all(&mut self, steps: &[Step]) {
        for step in steps {
            self.apply(step);
        }
    }

    fn apply(&mut self, step: &Step) {
        match step {
            Step::Edit { mac, edit } => {
                self.transaction(*mac, Some(edit));
            },
            Step::Deliver { mac, from, file } => {
                let macs = self.macs.len();
                let peer = (mac + 1 + usize::from(*from) % (macs - 1)) % macs;
                let files = self.files_of(peer);
                if let Some(hash) = Edit::pick(&files, *file) {
                    self.deliver(*mac, hash);
                }
                self.transaction(*mac, None);
            },
        }
    }

    /// Indexes in [`Self::files`] of every file Mac `n` published, oldest
    /// first.
    fn files_of(&self, n: usize) -> Vec<usize> {
        (0..self.files.len())
            .filter(|i| self.files[*i].mac == n)
            .collect()
    }

    /// Put file `index` in the folder copy of Mac `n`.
    fn deliver(&self, n: usize, index: usize) {
        let file = &self.files[index];
        let transport = &self.macs[n].transport;
        transport.put_state(self.vault_id, Self::replica(file.mac), &file.bytes);
    }

    /// Put the latest file of Mac `from` in the folder copy of Mac `n`.
    pub(super) fn deliver_latest(&self, n: usize, from: usize) {
        let latest = *self.files_of(from).last().expect("Mac has published");
        self.deliver(n, latest);
    }

    /// Make the folder copy of every Mac hold exactly the files that each
    /// peer directory holds: every latest file, with stale copies removed.
    fn sync_folders(&self) {
        for (n, mac) in self.macs.iter().enumerate() {
            for m in (0..self.macs.len()).filter(|m| *m != n) {
                let replica = Self::replica(m);
                let present: BTreeSet<StateHash> = self
                    .files
                    .iter()
                    .filter(|file| file.mac == m && !file.removed)
                    .map(|file| file.hash)
                    .collect();
                for hash in mac.transport.list_states(self.vault_id, replica).unwrap() {
                    if !present.contains(&hash) {
                        let name = StateFile::name(self.vault_id, hash);
                        mac.transport.remove(self.vault_id, replica, &name);
                    }
                }
                for file in self.files.iter().filter(|f| f.mac == m && !f.removed) {
                    mac.transport.put_state(self.vault_id, replica, &file.bytes);
                }
            }
        }
    }

    /// Record the files that Mac `n` published and deleted in its directory.
    fn collect(&mut self, n: usize) {
        let mac = &self.macs[n];
        let listed = mac
            .transport
            .list_states(self.vault_id, mac.replica)
            .unwrap();
        for file in self.files.iter_mut().filter(|file| file.mac == n) {
            file.removed = !listed.contains(&file.hash);
        }
        for hash in listed {
            if self.files.iter().any(|f| f.mac == n && f.hash == hash) {
                continue;
            }
            let read = mac
                .transport
                .read(self.vault_id, mac.replica, FileName::State(hash))
                .unwrap();
            let ReadResult::Local(bytes) = read else {
                panic!("own file {hash} is not local");
            };
            self.files.push(Published {
                mac: n,
                hash,
                bytes,
                removed: false,
            });
        }
    }

    /// Transaction of Mac `n` with `edit`, if any. Returns whether the Mac
    /// published.
    ///
    /// Panics if the vault does not show the view of the saved state, if a
    /// transaction with no edit mints, or if the Mac publishes when its
    /// context did not move past its last published file, or does not
    /// publish when it did.
    fn transaction(&mut self, n: usize, edit: Option<&Edit>) -> bool {
        self.transaction_with(n, edit.map(|edit| |vh: &mut VaultHandle| edit.apply(vh)))
    }

    /// Transaction of Mac `n` that runs `f`, with the checks of
    /// [`Self::transaction`]. Returns whether the Mac published.
    pub(super) fn write(
        &mut self,
        n: usize,
        f: impl FnOnce(&mut VaultHandle) -> Result<(), Error>,
    ) -> bool {
        self.transaction_with(n, Some(f))
    }

    /// [`Self::transaction`] with `edit` as a vault mutation.
    fn transaction_with(
        &mut self,
        n: usize,
        edit: Option<impl FnOnce(&mut VaultHandle) -> Result<(), Error>>,
    ) -> bool {
        let mac = &self.macs[n];
        let before = mac.state();
        let writes = mac.transport.writes();
        let allowed = usize::from(edit.is_some());

        let committed = mac.write(|vh| edit.map_or(Ok(()), |edit| edit(vh)));

        // The guard finds no drift, so sync stays active.
        assert_eq!(
            committed.sync_status,
            Some(SyncStatus::Active),
            "Mac {n} sync is not active"
        );
        let after = mac.state();
        let edits = LocalEdits::find(&after, &mac.saved_vault(), mac.replica).unwrap();
        assert!(
            edits.is_empty(),
            "Mac {n} vault differs from view: {edits:?}"
        );
        let minted: Vec<WriteId> = new_write_ids(&before, &after)
            .into_iter()
            .filter(|id| after.actors[&id.actor].replica == mac.replica)
            .collect();
        assert!(minted.len() <= allowed, "Mac {n} minted {minted:?}");
        let published = match mac.transport.writes() - writes {
            0 => false,
            1 => true,
            count => panic!("Mac {n} published {count} files"),
        };
        assert_eq!(
            published,
            after.context != mac.published,
            "Mac {n} publish does not follow its context"
        );

        if published {
            self.macs[n].published = after.context.clone();
        }
        for id in minted {
            self.observed.insert(id, after.context.clone());
        }
        self.collect(n);
        published
    }

    /// Give every Mac every latest file and run a transaction with no edit on
    /// each, in rounds, until a round publishes nothing.
    ///
    /// Panics if publishing has not stopped after one round per Mac and two
    /// more.
    pub(super) fn converge(&mut self) {
        let rounds = self.macs.len() + 2;
        for _ in 0..rounds {
            self.sync_folders();
            let mut published = false;
            for n in 0..self.macs.len() {
                published |= self.transaction(n, None);
            }
            if !published {
                return;
            }
        }
        panic!("publishing did not stop after {rounds} rounds");
    }

    /// Check that a transaction with no edit on each Mac changes no file and
    /// publishes nothing.
    pub(super) fn check_quiet(&self) {
        self.sync_folders();
        for (n, mac) in self.macs.iter().enumerate() {
            let before = mac.on_disk();
            let writes = mac.transport.writes();

            let committed = mac.write(|_| Ok(()));

            assert!(!committed.changed, "Mac {n} saved its vault");
            assert_eq!(
                committed.sync_status,
                Some(SyncStatus::Active),
                "Mac {n} sync is not active"
            );
            assert!(mac.on_disk() == before, "Mac {n} changed a local file");
            assert_eq!(mac.transport.writes(), writes, "Mac {n} published");
        }
    }

    /// Check that every Mac holds the same state, and that every vault shows
    /// the view of that state and its keys. Returns the state.
    pub(super) fn check_converged(&self) -> State {
        let state = self.macs[0].state();
        let view = VaultView::of(&state);
        let keys = view_keys(&view);
        for (n, mac) in self.macs.iter().enumerate() {
            assert!(mac.state() == state, "Mac {n} state differs");
            let vault = mac.saved_vault();
            let edits = LocalEdits::find(&state, &vault, mac.replica).unwrap();
            assert!(
                edits.is_empty(),
                "Mac {n} vault differs from view: {edits:?}"
            );
            assert_eq!(vault_keys(&vault), keys, "Mac {n} shows other keys");
        }
        state
    }

    /// Check that no live entry whose key was written after its writer
    /// joined another entry with the same key takes the bare key from it.
    /// Each key register holds the one value written at creation.
    fn check_established_keys(&self, state: &State) {
        let view = VaultView::of(state);
        // Live entries by group and normalized stored key, with the write id
        // of the key value and the shown key. The group of a credential is
        // its item.
        type Group = (Option<Uuid>, String);
        let mut groups: BTreeMap<Group, Vec<(WriteId, String)>> = BTreeMap::new();
        for (id, item) in state.store.items.iter() {
            let shown = &view.items[id];
            if shown.trashed.is_none() {
                let (write_id, key) = key_write(&item.key);
                let entry = (write_id, shown.key.clone());
                groups.entry((None, key)).or_default().push(entry);
            }
        }
        for (id, credential) in state.store.credentials.iter() {
            let shown = &view.credentials[id];
            if shown.trashed.is_none() {
                let (write_id, key) = key_write(&credential.key);
                let entry = (write_id, shown.key.clone());
                groups
                    .entry((Some(shown.item), key))
                    .or_default()
                    .push(entry);
            }
        }
        for ((_, key), entries) in &groups {
            for (established, _) in entries {
                for (later, shown) in entries {
                    let joined = later != established
                        && self
                            .observed
                            .get(later)
                            .is_some_and(|context| context.covers(*established));
                    assert!(
                        !joined || shown != key,
                        "{later:?} took key {key} from {established:?}"
                    );
                }
            }
        }
    }
}

/// Write id and normalized value of the one value of a key register.
fn key_write(register: &MvRegister<String, Ask>) -> (WriteId, String) {
    let values: Vec<_> = register.values().collect();
    assert_eq!(
        values.len(),
        1,
        "key register holds {} values",
        values.len()
    );
    let (write_id, value) = values[0];
    (
        write_id,
        normalized_key(&value.value).expect("generated keys are valid"),
    )
}

/// Shown keys of the live items of `view` and of their live credentials, by
/// id.
fn view_keys(view: &VaultView) -> BTreeMap<Uuid, String> {
    let live = |id: &Uuid| view.items.get(id).is_some_and(|i| i.trashed.is_none());
    let items = view
        .items
        .values()
        .filter(|item| item.trashed.is_none())
        .map(|item| (item.id, item.key.clone()));
    let credentials = view
        .credentials
        .values()
        .filter(|c| c.trashed.is_none() && live(&c.item))
        .map(|c| (c.id, c.key.clone()));
    items.chain(credentials).collect()
}

/// Keys of the live items of `vault` and of their live credentials, by id.
fn vault_keys(vault: &Vault) -> BTreeMap<Uuid, String> {
    vault
        .list_items()
        .into_iter()
        .flat_map(|item| {
            let credentials = item.credentials.values().map(|c| (c.id, c.key.clone()));
            std::iter::once((item.id, item.key.clone())).chain(credentials)
        })
        .collect()
}

/// Keys of the live items of Mac `n` that start with `mail`, sorted.
fn mail_keys(sim: &Sim, n: usize) -> Vec<String> {
    let mut keys: Vec<String> = sim.macs[n]
        .saved_vault()
        .list_items()
        .into_iter()
        .map(|item| item.key.clone())
        .filter(|key| key.starts_with("mail"))
        .collect();
    keys.sort();
    keys
}

const MAIL: Edit = Edit::Item {
    key: "mail",
    title: "Mail",
};

#[test]
fn three_macs_with_partial_views_that_create_one_key_show_same_keys_and_mint_nothing_for_it() {
    let mut sim = Sim::new(3, None);
    for n in 0..3 {
        assert!(sim.transaction(n, Some(&MAIL)));
    }

    // Each Mac joins the first file of one other Mac. Later files of Mac 0
    // would include the key that it received from Mac 1.
    for (n, from) in [(0, 1), (1, 2), (2, 0)] {
        let first = sim.files_of(from)[0];
        sim.deliver(n, first);
        assert!(sim.transaction(n, None));
        let keys = mail_keys(&sim, n);
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], "mail");
        assert!(keys[1].starts_with("mail-"));
    }

    sim.converge();
    sim.check_quiet();

    let state = sim.check_converged();
    let keys = mail_keys(&sim, 0);
    assert_eq!(keys.len(), 3);
    assert_eq!(keys[0], "mail");
    assert!(keys[1..].iter().all(|key| key.starts_with("mail-")));
    // The bare key is shown for the key value with the lowest order key.
    let view = VaultView::of(&state);
    let lowest = state
        .store
        .items
        .iter()
        .min_by_key(|(_, item)| item.key.ordered()[0].0)
        .map(|(id, _)| *id)
        .unwrap();
    assert_eq!(view.items[&lowest].key, "mail");
    // Each replica minted its setup write and its creation, and nothing for
    // the duplicate.
    for n in 0..3 {
        let replica = Sim::replica(n);
        let minted: u64 = state
            .context
            .iter()
            .filter(|(actor, _)| state.actors[actor].replica == replica)
            .map(|(_, seq)| seq)
            .sum();
        assert_eq!(minted, 2, "Mac {n}");
    }
}

#[test]
fn join_that_produces_duplicate_key_writes_nothing_publishes_nothing_and_is_not_drift() {
    let mut sim = Sim::new(2, None);
    sim.transaction(0, Some(&MAIL));
    sim.transaction(1, Some(&MAIL));

    // Each Mac joins the other's `mail`, and one of the two is shown with a
    // suffix. The transaction checks that sync stays active.
    for (n, from) in [(0, 1), (1, 0)] {
        sim.deliver_latest(n, from);
        sim.transaction(n, None);
        let keys = mail_keys(&sim, n);
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], "mail");
        assert!(keys[1].starts_with("mail-"));
    }

    // A transaction with no edit on each Mac writes and publishes nothing,
    // and sync stays active.
    sim.converge();
    sim.check_quiet();
    for mac in &sim.macs {
        let local = LocalSyncState::load(&mac.root, mac.vault_id(), &TestSigner::device()).unwrap();
        assert_eq!(local.stopped_build, None);
    }
    sim.check_converged();
}

#[test]
fn mac_whose_clock_is_behind_does_not_take_key_of_restored_item() {
    let mut sim = Sim::new(2, Some((1, -30 * 86_400)));
    // Mac 0 creates `mail`, and Mac 1 joins it and then its trash.
    sim.transaction(0, Some(&MAIL));
    let established = *sim.macs[0].saved_vault().get_item_id("mail").unwrap();
    sim.deliver_latest(1, 0);
    sim.transaction(1, None);
    sim.transaction(0, Some(&Edit::TrashItem(0)));
    sim.deliver_latest(1, 0);
    sim.transaction(1, None);
    // Mac 1 creates `mail` again while Mac 0 restores the established item.
    sim.transaction(1, Some(&MAIL));
    let later = *sim.macs[1].saved_vault().get_item_id("mail").unwrap();
    sim.transaction(0, Some(&Edit::RestoreItem(0)));

    sim.converge();
    sim.check_quiet();

    let state = sim.check_converged();
    let written_at = |id: &Uuid| {
        state.store.items.get(id).unwrap().key.ordered()[0]
            .1
            .written_at
    };
    assert!(written_at(&later) < written_at(&established));
    let view = VaultView::of(&state);
    assert_eq!(view.items[&established].key, "mail");
    assert!(view.items[&later].key.starts_with("mail-"));
    for n in 0..2 {
        let vault = sim.macs[n].saved_vault();
        assert_eq!(*vault.get_item_id("mail").unwrap(), established);
    }
    sim.check_established_keys(&state);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    #[test]
    fn macs_that_create_one_key_concurrently_show_same_keys_once_states_are_equal(
        steps in Step::steps(3),
    ) {
        // Each transaction checks that the vault shows the view of its state
        // and that no transaction with no edit mints.
        let mut sim = Sim::new(3, None);
        sim.apply_all(&steps);

        sim.converge();
        sim.check_quiet();

        sim.check_converged();
    }

    #[test]
    fn mac_whose_clock_is_behind_does_not_take_established_key(
        steps in Step::steps(3),
        slow in 0..3usize,
        behind in 1..=30 * 86_400i64,
    ) {
        let mut sim = Sim::new(3, Some((slow, -behind)));
        sim.apply_all(&steps);

        sim.converge();
        sim.check_quiet();

        let state = sim.check_converged();
        sim.check_established_keys(&state);
    }
}
