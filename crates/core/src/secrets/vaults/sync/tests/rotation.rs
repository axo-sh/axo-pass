//! Key rotation, Remove Mac, and cleanup (milestone 13).
//!
//! Each test Mac has its own app data directory, signing key, and software
//! encryption key. Every Mac reads and writes one shared synced folder. A Mac
//! can also run a transaction offline, with a folder that cannot be reached.

mod cleanup;
mod concurrent;
mod faults;
mod receive;
mod remove;
mod rotate_key;
mod signature;
mod simulator;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

use tempfile::TempDir;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::NOW;
use super::load::{GENERATION, state_of};
use super::state_file::key;
use super::transport::FakeTransport;
use super::view::State;
use super::wrapping::SoftwareKey;
use crate::secrets::vaults::format::encrypted_vault::EncryptedVault;
use crate::secrets::vaults::format::signing::{TestSigner, VaultSigner};
use crate::secrets::vaults::model::{UnlockedKey, Vault};
use crate::secrets::vaults::storage::txn::{Committed, Target, Unlock, VaultWriter};
use crate::secrets::vaults::sync::crdt::{ReplicaId, Session};
use crate::secrets::vaults::sync::keys::{SyncKeyWrapper, SyncKeyring, TestKeyWrapper};
use crate::secrets::vaults::sync::local_state::{LocalSyncState, PinSource, PinnedKeys};
use crate::secrets::vaults::sync::model::{KeyId, PublicKey, ReplicaKeys};
use crate::secrets::vaults::sync::report::SyncReport;
use crate::secrets::vaults::sync::rotation::{
    Accepted, Cleaned, Rotated, RotationPlan, RotationPrompt, RotationRecord, Rotations,
};
use crate::secrets::vaults::sync::state_file::StateFile;
use crate::secrets::vaults::sync::state_file::padded::PaddedBody;
use crate::secrets::vaults::sync::status::SyncStatus;
use crate::secrets::vaults::sync::transport::{FileName, ReadResult, SyncTransport};
use crate::secrets::vaults::sync::wrapping::{DeviceUnwrap, KeyFile};
use crate::secrets::vaults::{Error, VaultHandle};

/// Encryption key of a test Mac. It unwraps `Device` wrappings with its
/// software key and stores sync keys as [`TestKeyWrapper`] does.
pub(super) struct TestDevice(SoftwareKey);

impl DeviceUnwrap for TestDevice {
    fn unwrap_sync_key(&self, wrapped: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        self.0.unwrap_sync_key(wrapped)
    }
}

impl SyncKeyWrapper for TestDevice {
    fn wrap(&self, raw: &[u8]) -> Option<String> {
        TestKeyWrapper.wrap(raw)
    }

    fn unwrap(&self, wrapped: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        TestKeyWrapper.unwrap(wrapped)
    }
}

/// Seed of the signing key of Mac `n`.
fn seed(n: usize) -> u8 {
    u8::try_from(n).unwrap() + 20
}

/// SEC1 bytes of the public key of `signer`.
pub(super) fn signing_of(signer: &TestSigner) -> PublicKey {
    let key = signer.verifying_key().unwrap();
    PublicKey(key.to_encoded_point(false).as_bytes().to_vec())
}

/// Item title of every test item.
const TITLE: &str = "Title";

/// One Mac with its app data directory and its vaults.
pub(super) struct Mac {
    _dir: TempDir,
    pub(super) root: PathBuf,
    pub(super) n: usize,
    /// Vault `v` of the Mac, if the Mac syncs it.
    pub(super) vaults: Vec<Option<VaultHandle>>,
    pub(super) writer: VaultWriter,
    /// Writer of the Mac with a folder that cannot be reached.
    pub(super) offline: VaultWriter,
    pub(super) keys: ReplicaKeys,
}

impl Mac {
    pub(super) fn signer(&self) -> TestSigner {
        TestSigner::seeded(seed(self.n))
    }

    pub(super) fn vault(&self, v: usize) -> &VaultHandle {
        self.vaults[v].as_ref().expect("Mac syncs the vault")
    }

    pub(super) fn target(&self, v: usize) -> Target {
        Target::of(self.vault(v))
    }

    /// Run `f` in a transaction on vault `v` with `writer`.
    pub(super) fn write_with(
        &self,
        writer: &VaultWriter,
        v: usize,
        f: impl FnOnce(&mut VaultHandle) -> Result<(), Error>,
    ) -> Result<Committed<()>, Error> {
        let vh = self.vault(v);
        let key = || vh.unlocked_key().unwrap();
        writer.write(&Target::of(vh), Unlock::Test(&key), super::as_writer(f))
    }

    pub(super) fn write_in(
        &self,
        v: usize,
        f: impl FnOnce(&mut VaultHandle) -> Result<(), Error>,
    ) -> Result<Committed<()>, Error> {
        self.write_with(&self.writer, v, f)
    }

    /// Transaction with no change on vault 0.
    pub(super) fn sync(&self) -> Committed<()> {
        self.write_in(0, |_| Ok(())).unwrap()
    }

    /// Transaction with no change on vault 0, offline.
    pub(super) fn sync_offline(&self) -> Committed<()> {
        self.write_with(&self.offline, 0, |_| Ok(())).unwrap()
    }

    /// Add an item with key `key` to vault 0.
    pub(super) fn add(&self, key: &str) -> Committed<()> {
        self.write_in(0, |vh| vh.add_item(key, TITLE).map(|_| ()))
            .unwrap()
    }

    pub(super) fn local_in(&self, v: usize) -> LocalSyncState {
        let id = self.vault(v).vault_id().unwrap();
        LocalSyncState::load(&self.root, id, &self.signer()).unwrap()
    }

    pub(super) fn local(&self) -> LocalSyncState {
        self.local_in(0)
    }

    /// Saved sync state of vault `v`.
    pub(super) fn state_in(&self, v: usize) -> State {
        let local = self.local_in(v);
        let keyring = SyncKeyring::unwrap(&local.sync_keys, &TestKeyWrapper).unwrap();
        local.open(&keyring).unwrap()
    }

    pub(super) fn state(&self) -> State {
        self.state_in(0)
    }

    /// Keys of the live items of the saved vault 0.
    pub(super) fn items(&self) -> BTreeSet<String> {
        let vh = self.vault(0);
        let file = EncryptedVault::load(&vh.path, &self.signer()).unwrap();
        let vault = Vault::from_unlocked_key(&vh.unlocked_key().unwrap(), file).unwrap();
        vault
            .list_items()
            .into_iter()
            .map(|item| item.key.clone())
            .collect()
    }

    pub(super) fn rotate_in(
        &self,
        v: usize,
        plan: &RotationPlan,
    ) -> Result<Committed<Rotated>, Error> {
        let vh = self.vault(v);
        let key = || vh.unlocked_key().unwrap();
        self.writer
            .rotate(&Target::of(vh), Unlock::Test(&key), plan)
    }

    pub(super) fn rotate(&self, plan: &RotationPlan) -> Rotated {
        self.rotate_in(0, plan).unwrap().value
    }

    pub(super) fn accept_in(
        &self,
        v: usize,
        record: &RotationRecord,
    ) -> Result<Committed<Accepted>, Error> {
        let vh = self.vault(v);
        let key = || vh.unlocked_key().unwrap();
        self.writer
            .accept_rotation(&Target::of(vh), Unlock::Test(&key), record)
    }

    pub(super) fn accept(&self, record: &RotationRecord) -> Accepted {
        self.accept_in(0, record).unwrap().value
    }

    pub(super) fn decline(&self, records: &[RotationRecord]) -> Committed<()> {
        let vh = self.vault(0);
        let key = || vh.unlocked_key().unwrap();
        self.writer
            .decline_rotations(&Target::of(vh), Unlock::Test(&key), records)
            .unwrap()
    }

    pub(super) fn clean(&self, replica: ReplicaId) -> Result<Committed<Cleaned>, Error> {
        let vh = self.vault(0);
        let key = || vh.unlocked_key().unwrap();
        self.writer
            .clean_replica(&Target::of(vh), Unlock::Test(&key), replica)
    }

    pub(super) fn report_in(&self, v: usize) -> SyncReport {
        let vh = self.vault(v);
        let key = || vh.unlocked_key().unwrap();
        SyncReport::read(&self.writer, &Target::of(vh), Unlock::Test(&key)).unwrap()
    }

    /// Prompts of the pending rotations of vault 0.
    pub(super) fn prompts(&self) -> Vec<RotationPrompt> {
        Rotations::prompts(&self.local())
    }

    /// Rotation of the one `Confirm` prompt of vault 0.
    pub(super) fn confirm(&self) -> RotationRecord {
        match &self.prompts()[..] {
            [RotationPrompt::Confirm { rotation, .. }] => rotation.clone(),
            prompts => panic!("Mac {} prompts {prompts:?}", self.n),
        }
    }

    /// Sync, then accept the one `Confirm` prompt of vault 0.
    pub(super) fn sync_and_accept(&self) -> Accepted {
        self.sync();
        self.accept(&self.confirm())
    }

    /// Sync status of a transaction with no change on vault 0.
    pub(super) fn status(&self) -> Option<SyncStatus> {
        self.sync().sync_status
    }

    /// Pin of `replica` in vault `v`.
    pub(super) fn pin(&self, v: usize, replica: ReplicaId) -> Option<PinnedKeys> {
        self.local_in(v).pinned_keys.get(&replica).cloned()
    }
}

/// Macs that sync one or more vaults through one shared folder.
pub(super) struct Net {
    pub(super) folder: Arc<FakeTransport>,
    pub(super) macs: Vec<Mac>,
    pub(super) vault_ids: Vec<Uuid>,
}

impl Net {
    /// Replica id of Mac `n` in vault `v`.
    pub(super) fn replica_in(v: usize, n: usize) -> ReplicaId {
        ReplicaId(Uuid::from_u128(((v as u128 + 1) << 8) | (n as u128 + 1)))
    }

    /// Replica id of Mac `n` in vault 0.
    pub(super) fn replica(n: usize) -> ReplicaId {
        Self::replica_in(0, n)
    }

    /// `macs` Macs that all sync one vault.
    pub(super) fn new(macs: usize) -> Self {
        Self::with(macs, 1, |_, _| true)
    }

    /// `macs` Macs and `vaults` vaults. Mac `n` syncs vault `v` if
    /// `member(v, n)`. Each sync state holds the keys and the name of every
    /// member, each written by an actor of that member, at [`GENERATION`].
    pub(super) fn with(macs: usize, vaults: usize, member: impl Fn(usize, usize) -> bool) -> Self {
        let folder = Arc::new(FakeTransport::default());
        let devices: Vec<Arc<TestDevice>> = (0..macs)
            .map(|_| Arc::new(TestDevice(SoftwareKey::generate())))
            .collect();
        let keys: Vec<ReplicaKeys> = (0..macs)
            .map(|n| ReplicaKeys {
                encryption: PublicKey(devices[n].0.public_sec1()),
                signing: signing_of(&TestSigner::seeded(seed(n))),
            })
            .collect();
        let file_keys: Vec<UnlockedKey> = (0..vaults)
            .map(|_| Vault::new_for_test().unlocked_key())
            .collect();
        let vault_ids: Vec<Uuid> = file_keys.iter().map(UnlockedKey::vault_id).collect();
        let initial: Vec<State> = (0..vaults)
            .map(|v| {
                let mut state = State::default();
                for n in (0..macs).filter(|n| member(v, *n)) {
                    let replica = Self::replica_in(v, n);
                    let mut session = Session::new(replica);
                    let mut part = State::default();
                    let mint = session.mint(&mut part, NOW);
                    part.store
                        .replica_keys
                        .entry(replica)
                        .write(&mint, keys[n].clone());
                    part.store
                        .replica_names
                        .entry(replica)
                        .write(&mint, format!("Mac {n}"));
                    state.join(part);
                }
                state
            })
            .collect();
        let macs = (0..macs)
            .map(|n| {
                let dir = tempfile::tempdir().unwrap();
                let root = dir.path().join("data");
                let device: Arc<TestDevice> = devices[n].clone();
                let writer = VaultWriter::isolated_with_signer(&root, TestSigner::seeded(seed(n)))
                    .with_transport(folder.clone())
                    .with_test_rotation_keys(device);
                let unreachable = Arc::new(FakeTransport::default());
                unreachable.set_unavailable(true);
                let offline = writer.clone().with_transport(unreachable);
                let vaults = (0..vaults)
                    .map(|v| {
                        if !member(v, n) {
                            return None;
                        }
                        let replica = Self::replica_in(v, n);
                        let mut vault =
                            Vault::with_unlocked_key(format!("vault{v}"), &file_keys[v]);
                        vault.set_sync(GENERATION, Some(replica.0));
                        let vh = VaultHandle::new_in(&dir.path().join("vaults"), vault);
                        writer.create(&vh).unwrap();
                        state_of(vault_ids[v], replica, GENERATION, &initial[v])
                            .save(&root, &TestSigner::seeded(seed(n)))
                            .unwrap();
                        Some(vh)
                    })
                    .collect();
                Mac {
                    _dir: dir,
                    root,
                    n,
                    vaults,
                    writer,
                    offline,
                    keys: keys[n].clone(),
                }
            })
            .collect();
        Self {
            folder,
            macs,
            vault_ids,
        }
    }

    pub(super) fn vault_id(&self) -> Uuid {
        self.vault_ids[0]
    }

    /// Sync every Mac in `macs`, in order, in rounds, so every Mac of them
    /// joins the latest file of every other one.
    pub(super) fn sync_all(&self, macs: &[usize]) {
        for _ in 0..3 {
            for n in macs {
                self.macs[*n].sync();
            }
        }
    }

    /// `key.json` of Mac `n` in vault 0, if any.
    pub(super) fn key_file(&self, n: usize) -> Option<KeyFile> {
        let read = self
            .folder
            .read(self.vault_id(), Net::replica(n), FileName::Key)
            .unwrap();
        match read {
            ReadResult::Local(bytes) => Some(KeyFile::parse(&bytes).unwrap()),
            _ => None,
        }
    }

    /// Raw `key.json` of Mac `n` in vault 0, removed from the folder, for a
    /// Mac that must not see it yet.
    pub(super) fn hide_key_file(&self, n: usize) -> Vec<u8> {
        let ReadResult::Local(bytes) = self
            .folder
            .read(self.vault_id(), Net::replica(n), FileName::Key)
            .unwrap()
        else {
            panic!("Mac {n} has no key.json");
        };
        self.folder
            .remove(self.vault_id(), Net::replica(n), "key.json");
        bytes
    }

    /// Put back the `key.json` `bytes` of Mac `n`.
    pub(super) fn show_key_file(&self, n: usize, bytes: &[u8]) {
        self.folder
            .put(self.vault_id(), Net::replica(n), "key.json", bytes);
    }

    /// Replica ids of the `Device` wrappings in the `key.json` of Mac `n`
    /// under key id `key_id`.
    pub(super) fn wrapped_to(&self, n: usize, key_id: u32) -> BTreeSet<ReplicaId> {
        self.key_file(n)
            .map(|file| {
                file.devices()
                    .filter(|device| device.key_id.0 == key_id)
                    .map(|device| device.to_replica)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Whether the directory of Mac `n` in vault 0 holds a file.
    pub(super) fn has_directory(&self, n: usize) -> bool {
        !self
            .folder
            .names(self.vault_id(), Net::replica(n))
            .is_empty()
    }

    /// State files of `replica` in vault 0, by name.
    pub(super) fn files_of(&self, replica: ReplicaId) -> Vec<(String, Vec<u8>)> {
        let id = self.vault_id();
        self.folder
            .list_states(id, replica)
            .unwrap()
            .into_iter()
            .filter_map(
                |hash| match self.folder.read(id, replica, FileName::State(hash)) {
                    Ok(ReadResult::Local(bytes)) => {
                        Some((FileName::State(hash).file_name(), bytes))
                    },
                    _ => None,
                },
            )
            .collect()
    }

    /// Remove the state files of `replica` from the folder, and return them.
    pub(super) fn stash(&self, replica: ReplicaId) -> Vec<(String, Vec<u8>)> {
        let files = self.files_of(replica);
        for (name, _) in &files {
            self.folder.remove(self.vault_id(), replica, name);
        }
        files
    }

    /// Put back the state files `files` of `replica`.
    pub(super) fn unstash(&self, replica: ReplicaId, files: &[(String, Vec<u8>)]) {
        for (name, bytes) in files {
            self.folder.put(self.vault_id(), replica, name, bytes);
        }
    }

    /// Make every state file of `replica` remote, as a file not yet
    /// downloaded.
    pub(super) fn make_remote(&self, replica: ReplicaId) {
        for (name, bytes) in self.stash(replica) {
            self.folder
                .put_remote_with(self.vault_id(), replica, &name, &bytes);
        }
    }

    /// Put a state file of `state` under key 1 into the directory of
    /// `replica`, as a holder of key 1 can.
    pub(super) fn plant(&self, replica: ReplicaId, state: &State) {
        let padded = PaddedBody::of(state).unwrap();
        let bytes = StateFile::encode(&padded, self.vault_id(), replica, KeyId(1), &key()).unwrap();
        self.folder.put_state(self.vault_id(), replica, &bytes);
    }

    /// State with the keys `keys` in the `replica_keys` register of `owner`,
    /// written by a new actor of `writer`.
    pub(super) fn keys_written(writer: ReplicaId, owner: ReplicaId, keys: ReplicaKeys) -> State {
        let mut state = State::default();
        let mut session = Session::new(writer);
        let mint = session.mint(&mut state, NOW);
        state.store.replica_keys.entry(owner).write(&mint, keys);
        state
    }

    /// Mark the keys of Mac `pinned` in vault `v` on Mac `n` as paired.
    pub(super) fn pin_paired(&self, n: usize, v: usize, pinned: usize) {
        let mac = &self.macs[n];
        let mut local = mac.local_in(v);
        let keys = &self.macs[pinned].keys;
        local.pinned_keys.insert(
            Net::replica_in(v, pinned),
            PinnedKeys {
                source: PinSource::Pairing,
                encryption: keys.encryption.clone(),
                signing: keys.signing.clone(),
                revoked: false,
            },
        );
        local.save(&mac.root, &mac.signer()).unwrap();
    }
}
