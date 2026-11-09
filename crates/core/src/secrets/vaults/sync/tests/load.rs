//! Load classification at each load path, and the own signing key check.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use tempfile::TempDir;
use uuid::Uuid;

use super::NOW;
use super::state_file::{WRITER, key, keyring};
use super::view::State;
use crate::core::auth::AuthContext;
use crate::secrets::vaults::format::encrypted_vault::EncryptedVault;
use crate::secrets::vaults::format::signing::{TestSigner, VaultSigner};
use crate::secrets::vaults::model::Vault;
use crate::secrets::vaults::storage::test_unlocker::KeyUnlocker;
use crate::secrets::vaults::storage::txn::{Committed, Target, Unlock, VaultWriter};
use crate::secrets::vaults::sync::crdt::{ReplicaId, Session};
use crate::secrets::vaults::sync::keys::{
    KeyFingerprint, SyncKey, SyncKeyring, TestKeyWrapper, WrappedSyncKey,
};
use crate::secrets::vaults::sync::load::{Mismatch, SignatureFailure, SyncLoad};
use crate::secrets::vaults::sync::local_state::LocalSyncState;
use crate::secrets::vaults::sync::model::{KeyId, PublicKey, ReplicaKeys, SYNC_FORMAT_VERSION};
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::state_file::padded::PaddedBody;
use crate::secrets::vaults::sync::status::BUILD_ID;
use crate::secrets::vaults::sync::transport::{SyncTransport, SyncTransports};
use crate::secrets::vaults::{Error, VaultCatalog, VaultHandle};

/// Replica id of the synced vaults.
pub(super) const REPLICA: ReplicaId = WRITER;

/// Generation of the vault files.
pub(super) const GENERATION: u64 = 7;

/// SEC1 bytes of the test device key.
pub(super) fn device_key() -> Vec<u8> {
    let key = TestSigner::device().verifying_key().unwrap();
    key.to_encoded_point(false).as_bytes().to_vec()
}

/// SEC1 bytes of a key of another Mac.
fn other_key() -> Vec<u8> {
    let key = TestSigner::random().verifying_key().unwrap();
    key.to_encoded_point(false).as_bytes().to_vec()
}

/// State whose `replica_keys` entry of `replica` holds each signing key of
/// `signing`. Each value is written by its own actor, so the values are
/// concurrent.
pub(super) fn body(replica: ReplicaId, signing: &[Vec<u8>]) -> State {
    let mut state = State::default();
    for signing in signing {
        let mut session = Session::new(replica);
        let mut part = State::default();
        let m = session.mint(&mut part, NOW);
        part.store.replica_keys.entry(replica).write(
            &m,
            ReplicaKeys {
                encryption: PublicKey(vec![4, 1]),
                signing: PublicKey(signing.clone()),
            },
        );
        state.join(part);
    }
    state
}

/// Sync state of vault `vault_id` and `replica` at `generation` with the
/// body `body`, sealed with `seal`. Its keyring is [`keyring`], wrapped by
/// [`TestKeyWrapper`].
fn sealed(
    vault_id: Uuid,
    replica: ReplicaId,
    generation: u64,
    body: &State,
    seal: &SyncKeyring,
) -> LocalSyncState {
    let padded = PaddedBody::of(body).unwrap();
    let mut local = LocalSyncState::new(vault_id, replica, KeyId(1));
    local.generation = generation;
    local.sync_keys = keyring().wrap(&TestKeyWrapper).unwrap();
    local.seal(&padded, seal).unwrap();
    local
}

/// [`sealed`] with the body `body`, sealed with [`keyring`].
pub(super) fn state_of(
    vault_id: Uuid,
    replica: ReplicaId,
    generation: u64,
    body: &State,
) -> LocalSyncState {
    sealed(vault_id, replica, generation, body, &keyring())
}

/// [`state_of`] with the device key as the own key.
pub(super) fn state(vault_id: Uuid, replica: ReplicaId, generation: u64) -> LocalSyncState {
    state_of(
        vault_id,
        replica,
        generation,
        &body(replica, &[device_key()]),
    )
}

/// Key ids and fingerprints of `keyring`.
fn fingerprints(keyring: &SyncKeyring) -> Vec<(KeyId, KeyFingerprint)> {
    keyring
        .keys()
        .iter()
        .map(|(key_id, key)| (*key_id, key.fingerprint()))
        .collect()
}

/// Vault `personal` written to a temp directory, with the sync files under
/// the app data directory `root`. The catalog unlocks it with its file key.
pub(super) struct Fixture {
    _dir: TempDir,
    pub(super) root: PathBuf,
    pub(super) vaults_dir: PathBuf,
    pub(super) catalog: VaultCatalog,
    /// The vault as created, still unlocked.
    pub(super) vault: VaultHandle,
}

impl Fixture {
    /// Vault saved with `generation`, and with replica id `replica` if set.
    /// No sync state is written.
    pub(super) fn new(generation: u64, replica: Option<ReplicaId>) -> Self {
        Self::build(generation, replica, None)
    }

    /// [`Self::new`], with own state files read through `transport`.
    pub(super) fn with_transport(
        generation: u64,
        replica: Option<ReplicaId>,
        transport: Arc<dyn SyncTransport>,
    ) -> Self {
        Self::build(generation, replica, Some(transport))
    }

    /// [`Self::new`], with each vault resolved by the root in its sidecar
    /// through `transports`.
    pub(super) fn with_transports(
        generation: u64,
        replica: Option<ReplicaId>,
        transports: Arc<dyn SyncTransports>,
    ) -> Self {
        Self::build_with(generation, replica, |files| {
            files.with_transports(transports)
        })
    }

    fn build(
        generation: u64,
        replica: Option<ReplicaId>,
        transport: Option<Arc<dyn SyncTransport>>,
    ) -> Self {
        Self::build_with(generation, replica, |files| match transport {
            Some(transport) => files.with_transport(transport),
            None => files,
        })
    }

    fn build_with(
        generation: u64,
        replica: Option<ReplicaId>,
        writer: impl FnOnce(VaultWriter) -> VaultWriter,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("data");
        let vaults_dir = dir.path().join("vaults");
        let files = writer(VaultWriter::isolated(&root));
        let mut vault = Vault::new_for_test();
        vault.set_sync(generation, replica.map(|replica| replica.0));
        let vh = VaultHandle::new_in(&vaults_dir, vault);
        files.create(&vh).unwrap();
        let keys = HashMap::from([(vh.vault_id().unwrap(), vh.unlocked_key().unwrap())]);
        let catalog = VaultCatalog::with_unlocker(
            vaults_dir.clone(),
            files,
            Vec::new(),
            Arc::new(KeyUnlocker(keys)),
        );
        Self {
            _dir: dir,
            root,
            vaults_dir,
            catalog,
            vault: vh,
        }
    }

    /// Vault synced as [`REPLICA`] at [`GENERATION`], with no sync state.
    pub(super) fn synced() -> Self {
        Self::new(GENERATION, Some(REPLICA))
    }

    pub(super) fn id(&self) -> Uuid {
        self.vault.vault_id().unwrap()
    }

    pub(super) fn state_path(&self) -> PathBuf {
        LocalSyncState::path(&self.root, self.id())
    }

    /// Write `contents` as the sync state file of this vault.
    pub(super) fn put_text(&self, contents: &str) {
        let path = self.state_path();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    /// Write `local`, signed by `signer`, as the sync state of this vault.
    pub(super) fn put(&self, local: &LocalSyncState, signer: &TestSigner) {
        self.put_text(&local.to_file_contents(signer).unwrap());
    }

    /// Write a valid sync state of this vault as [`REPLICA`] at `generation`.
    pub(super) fn put_state(&self, generation: u64) {
        self.put(
            &state(self.id(), REPLICA, generation),
            &TestSigner::device(),
        );
    }

    /// Write a valid sync state of this vault at [`GENERATION`], signed by a
    /// key of another Mac.
    pub(super) fn put_foreign_state(&self) {
        self.put(
            &state(self.id(), REPLICA, GENERATION),
            &TestSigner::random(),
        );
    }

    /// Write a valid sync state of this vault at [`GENERATION`] and create a
    /// second synced vault, `work`, in the same directory. The sync state of
    /// `work` is not written. Return the handle and replica of `work`.
    pub(super) fn put_state_and_create_work_vault(&self) -> (VaultHandle, ReplicaId) {
        self.put_state(GENERATION);
        let work_replica = ReplicaId(Uuid::from_u128(2));
        let mut vault = Vault::new_for_test();
        vault.set_key("work".to_string());
        vault.set_sync(GENERATION, Some(work_replica.0));
        let work = VaultHandle::new_in(&self.vaults_dir, vault);
        self.catalog.files().create(&work).unwrap();
        (work, work_replica)
    }

    /// Vault file and sync state file as they are on disk now.
    pub(super) fn on_disk(&self) -> (String, Option<String>) {
        (
            fs::read_to_string(&self.vault.path).unwrap(),
            fs::read_to_string(self.state_path()).ok(),
        )
    }

    /// Case at the unlock, which loads the sync state and unwraps its keyring
    /// together.
    pub(super) fn read_case(&self) -> SyncLoad {
        let signer = TestSigner::device();
        let vault = EncryptedVault::load(&self.vault.path, &signer).unwrap();
        SyncLoad::load(&self.root, &vault, &signer, &TestKeyWrapper)
            .unwrap()
            .0
    }

    /// Case at a transaction, which unwraps the keyring before the locks and
    /// loads the sync state again under them.
    pub(super) fn write_case(&self) -> SyncLoad {
        let signer = TestSigner::device();
        let vault = EncryptedVault::load(&self.vault.path, &signer).unwrap();
        let keyring = SyncLoad::keyring(&self.root, &vault, &signer, &TestKeyWrapper);
        let local = LocalSyncState::load(&self.root, vault.id, &signer);
        SyncLoad::classify(&vault, local, keyring.as_ref(), &signer).unwrap()
    }

    /// Unlock the vault through the catalog, a read path.
    pub(super) fn read(&self) -> Result<VaultHandle, Error> {
        let mut vh = self.catalog.load("personal")?;
        self.catalog.unlock(&mut vh, AuthContext::OneTime)?;
        Ok(vh)
    }

    /// Run `f` in a transaction on the vault, a write path. The keyring is
    /// read from the sync state.
    pub(super) fn write(
        &self,
        f: impl FnOnce(&mut VaultHandle) -> Result<(), Error>,
    ) -> Result<Committed<()>, Error> {
        let key = || self.vault.unlocked_key().unwrap();
        self.catalog
            .files()
            .write(&Target::of(&self.vault), Unlock::Test(&key), f)
    }

    /// Add an item in a transaction.
    pub(super) fn add_item(&self) -> Result<Committed<()>, Error> {
        self.write(|vh| vh.add_item("item", "Item").map(|_| ()))
    }

    /// Restore the retained version `name` in a transaction.
    pub(super) fn restore(&self, name: &str) -> Result<Committed<()>, Error> {
        let key = || self.vault.unlocked_key().unwrap();
        self.catalog
            .files()
            .restore_version(&Target::of(&self.vault), Unlock::Test(&key), name)
    }
}

/// Whether the sync state, the staged file, and the sidecar of `fx` exist.
pub(super) fn sync_files(fx: &Fixture) -> [bool; 3] {
    [
        LocalSyncState::path(&fx.root, fx.id()),
        LocalSyncState::staged_path(&fx.root, fx.id()),
        Sidecar::path(&fx.root, fx.id()),
    ]
    .map(|path| path.exists())
}

/// Assert that the vault file and sync state file of `fx` equal `before`, a
/// result of [`Fixture::on_disk`], and that no other sync file exists.
pub(super) fn assert_nothing_written(fx: &Fixture, before: &(String, Option<String>)) {
    assert_eq!(&fx.on_disk(), before);
    assert_eq!(sync_files(fx), [false; 3]);
}

/// Each case, with a vault and a sync state that give it.
pub(super) fn cases() -> Vec<(&'static str, Fixture, SyncLoad)> {
    let device = TestSigner::device();
    let mut cases = Vec::new();

    cases.push((
        "not synced",
        Fixture::new(GENERATION, None),
        SyncLoad::NotSynced,
    ));

    let fx = Fixture::synced();
    fx.put_state(GENERATION);
    cases.push(("v == s", fx, SyncLoad::Current));

    let fx = Fixture::synced();
    fx.put_state(GENERATION + 1);
    let case = SyncLoad::OlderVault {
        vault: GENERATION,
        state: GENERATION + 1,
    };
    cases.push(("v < s", fx, case));

    let fx = Fixture::synced();
    let mut local = state(fx.id(), REPLICA, GENERATION + 1);
    local.stopped_build = Some(BUILD_ID.to_string());
    fx.put(&local, &device);
    let case = SyncLoad::StoppedOlderVault {
        vault: GENERATION,
        state: GENERATION + 1,
    };
    cases.push(("v < s while stopped by drift", fx, case));

    let fx = Fixture::synced();
    fx.put_state(GENERATION - 1);
    let case = SyncLoad::NewerVault {
        vault: GENERATION,
        state: GENERATION - 1,
    };
    cases.push(("v > s", fx, case));

    let fx = Fixture::synced();
    let other = Uuid::from_u128(0x200);
    fx.put(&state(other, REPLICA, GENERATION), &device);
    let case = SyncLoad::Mismatch(Mismatch::VaultId(other));
    cases.push(("vault id mismatch", fx, case));

    let fx = Fixture::synced();
    let other = ReplicaId(Uuid::from_u128(2));
    fx.put(&state(fx.id(), other, GENERATION), &device);
    let case = SyncLoad::Mismatch(Mismatch::ReplicaId(other));
    cases.push(("replica id mismatch", fx, case));

    cases.push((
        "sync state missing",
        Fixture::synced(),
        SyncLoad::StateMissing,
    ));

    let fx = Fixture::synced();
    fx.put_text("not json");
    let case = SyncLoad::SignatureFailed(SignatureFailure::Envelope);
    cases.push(("malformed envelope", fx, case));

    let fx = Fixture::synced();
    fx.put_foreign_state();
    let case = SyncLoad::SignatureFailed(SignatureFailure::Signature);
    cases.push(("signed by another key", fx, case));

    let fx = Fixture::synced();
    let mut local = state(fx.id(), REPLICA, GENERATION);
    local.sync_keys = vec![WrappedSyncKey {
        key_id: KeyId(1),
        wrapped: "AAAA".to_string(),
    }];
    fx.put(&local, &device);
    let case = SyncLoad::SignatureFailed(SignatureFailure::Keyring);
    cases.push(("keyring fails to unwrap", fx, case));

    let fx = Fixture::synced();
    let other_sync_key = SyncKeyring::new(vec![(KeyId(1), SyncKey::from_bytes([2; 32]))]).unwrap();
    let own = body(REPLICA, &[device_key()]);
    fx.put(
        &sealed(fx.id(), REPLICA, GENERATION, &own, &other_sync_key),
        &device,
    );
    let case = SyncLoad::SignatureFailed(SignatureFailure::Body);
    cases.push(("body fails to decrypt", fx, case));

    let fx = Fixture::synced();
    let foreign = body(REPLICA, &[other_key()]);
    fx.put(&state_of(fx.id(), REPLICA, GENERATION, &foreign), &device);
    let case = SyncLoad::SignatureFailed(SignatureFailure::OwnKey);
    cases.push(("own key absent", fx, case));

    let fx = Fixture::synced();
    let mut local = state(fx.id(), REPLICA, GENERATION);
    let other_id = SyncKeyring::new(vec![(KeyId(2), key())]).unwrap();
    local.sync_keys = other_id.wrap(&TestKeyWrapper).unwrap();
    fx.put(&local, &device);
    cases.push(("key missing", fx, SyncLoad::KeyMissing(KeyId(1))));

    let fx = Fixture::synced();
    let mut local = state(fx.id(), REPLICA, GENERATION);
    local.format_version = SYNC_FORMAT_VERSION + 1;
    fx.put(&local, &device);
    let newer = SYNC_FORMAT_VERSION + 1;
    let case = SyncLoad::VersionSkew(format!("format version {newer}"));
    cases.push(("newer format", fx, case));

    let fx = Fixture::new(GENERATION, None);
    fx.put_state(GENERATION);
    cases.push(("disable in progress", fx, SyncLoad::DisableInProgress));

    // A disable that stopped after the `leaving` save and before the vault
    // save.
    let fx = Fixture::synced();
    let mut local = state(fx.id(), REPLICA, GENERATION + 1);
    local.leaving = true;
    fx.put(&local, &device);
    cases.push((
        "vault saved before its leaving sync state",
        fx,
        SyncLoad::Leaving,
    ));

    cases
}

#[test]
fn each_case_classified_and_served_or_refused_at_each_load_path() {
    for (name, fx, expected) in cases() {
        assert_eq!(fx.read_case(), expected, "{name}: case at unlock");
        assert_eq!(fx.write_case(), expected, "{name}: case at transaction");

        // A transaction rebuilds a `v < s` vault and a vault of another
        // replica id from the sync state (6a.6), and repairs a `v > s` vault
        // (6c.3). A read runs the same transaction in these cases (9.2).
        let rebuilt = matches!(
            expected,
            SyncLoad::OlderVault { .. }
                | SyncLoad::Mismatch(Mismatch::ReplicaId(_))
                | SyncLoad::NewerVault { .. }
        );
        let served = expected.check().map_err(|e| e.to_string());
        let written = if rebuilt { Ok(()) } else { served.clone() };
        let before = fx.on_disk();
        let read = fx.read().map(|_| ()).map_err(|e| e.to_string());
        assert_eq!(read, written, "{name}: unlock");
        if rebuilt {
            assert_ne!(fx.on_disk(), before, "{name}: unlock writes");
        } else {
            assert_eq!(fx.on_disk(), before, "{name}: unlock writes nothing");
        }

        let write = fx.add_item().map(|_| ()).map_err(|e| e.to_string());
        assert_eq!(write, written, "{name}: transaction");
        if written.is_err() {
            assert_eq!(
                fx.on_disk(),
                before,
                "{name}: refused transaction writes nothing"
            );
        }
        // A transaction finishes the disable: the vault holds no replica id
        // and the `leaving` sync state is kept for its copy (D8 of doc 18).
        if expected == SyncLoad::Leaving {
            assert_eq!(fx.read_case(), SyncLoad::DisableInProgress, "{name}");
            assert_eq!(fx.on_disk().1, before.1, "{name}: sync state is kept");
        }
    }
}

#[test]
fn only_repair_cases_and_newer_format_refused() {
    for (name, _, case) in cases() {
        let result = case.check();
        match case {
            SyncLoad::OlderVault { .. } | SyncLoad::NewerVault { .. } | SyncLoad::Mismatch(_) => {
                assert!(matches!(result, Err(Error::SyncRepairNeeded(_))), "{name}");
            },
            SyncLoad::VersionSkew(_) => {
                assert!(
                    matches!(result, Err(Error::SyncStateVersionSkew(_))),
                    "{name}"
                );
            },
            _ => assert!(result.is_ok(), "{name}"),
        }
    }
}

#[test]
fn read_path_on_vault_with_v_other_than_s_runs_repair_transaction_and_serves_repaired_vault() {
    // `v > s` is repaired at `v + 1`, and `v < s` is rebuilt at `s + 1`.
    for (state, saved) in [
        (GENERATION - 1, GENERATION + 1),
        (GENERATION + 1, GENERATION + 2),
    ] {
        let fx = Fixture::synced();
        fx.put_state(state);
        let before = fx.on_disk();

        let vh = fx.read().unwrap();

        assert_ne!(fx.on_disk(), before, "s = {state}");
        assert_eq!(fx.read_case(), SyncLoad::Current, "s = {state}");
        let file = EncryptedVault::load(&fx.vault.path, &TestSigner::device()).unwrap();
        assert_eq!(file.generation, saved, "s = {state}");
        let served = vh.get_unlocked_vault().unwrap();
        assert_eq!(served.generation(), saved, "s = {state}");
        assert!(!vh.keyring().unwrap().keys().is_empty(), "s = {state}");
    }
}

#[test]
fn vault_not_synced_loads_with_no_sync_state() {
    let fx = Fixture::new(0, None);

    assert_eq!(fx.read_case(), SyncLoad::NotSynced);
    fx.read().unwrap();
    fx.add_item().unwrap();

    assert!(!fx.root.join("sync").exists());
}

#[test]
fn deleted_sync_state_of_vault_that_names_replica_id_is_state_missing_and_vault_loads() {
    let fx = Fixture::synced();
    fx.put_state(GENERATION);
    assert_eq!(fx.read_case(), SyncLoad::Current);

    fs::remove_file(fx.state_path()).unwrap();

    assert_eq!(fx.read_case(), SyncLoad::StateMissing);
    assert_eq!(fx.write_case(), SyncLoad::StateMissing);
    let vh = fx.read().unwrap();
    assert!(vh.keyring().unwrap().keys().is_empty());
    fx.add_item().unwrap();
}

#[test]
fn sync_state_with_planted_sync_keys_entry_fails_verification_and_vault_loads() {
    let fx = Fixture::synced();
    let contents = state(fx.id(), REPLICA, GENERATION)
        .to_file_contents(&TestSigner::device())
        .unwrap();
    let planted = contents.replacen(
        "\"sync_keys\": [",
        "\"sync_keys\": [\n    { \"key_id\": 9, \"wrapped\": \"AAAA\" },",
        1,
    );
    assert_ne!(planted, contents);
    fx.put_text(&planted);

    let case = SyncLoad::SignatureFailed(SignatureFailure::Signature);
    assert_eq!(fx.read_case(), case);
    assert_eq!(fx.write_case(), case);
    let vh = fx.read().unwrap();
    assert!(vh.keyring().unwrap().keys().is_empty());
    fx.add_item().unwrap();
}

#[test]
fn missing_device_key_failed_signature() {
    let without_entry = body(REPLICA, &[]);
    let other_replica = body(ReplicaId(Uuid::from_u128(2)), &[device_key()]);
    let another_key = body(REPLICA, &[other_key()]);
    for (name, own) in [
        ("no entry", without_entry),
        ("entry of another replica only", other_replica),
        ("entry with another key", another_key),
    ] {
        let fx = Fixture::synced();
        fx.put(
            &state_of(fx.id(), REPLICA, GENERATION, &own),
            &TestSigner::device(),
        );

        let case = SyncLoad::SignatureFailed(SignatureFailure::OwnKey);
        assert_eq!(fx.read_case(), case, "{name}");
        assert_eq!(fx.write_case(), case, "{name}");
        let vh = fx.read().unwrap();
        assert!(vh.keyring().unwrap().keys().is_empty(), "{name}");
    }
}

#[test]
fn second_replica_keys_value_passes_check() {
    for signing in [[other_key(), device_key()], [device_key(), other_key()]] {
        let fx = Fixture::synced();
        let own = body(REPLICA, &signing);
        let register = own.store.replica_keys.get(&REPLICA).unwrap();
        assert_eq!(register.values().count(), 2);
        fx.put(
            &state_of(fx.id(), REPLICA, GENERATION, &own),
            &TestSigner::device(),
        );

        assert_eq!(fx.read_case(), SyncLoad::Current);
        assert_eq!(fx.write_case(), SyncLoad::Current);
    }
}

#[test]
fn keyring_wrapped_and_unwrapped_through_unlock_gives_same_keys() {
    let fx = Fixture::synced();
    fx.put_state(GENERATION);
    let expected = fingerprints(&keyring());

    let vh = fx.read().unwrap();
    assert_eq!(fingerprints(vh.keyring().unwrap()), expected);

    let committed = fx.add_item().unwrap();
    assert_eq!(fingerprints(committed.vault.keyring().unwrap()), expected);

    // A transaction on the unlocked vault copies its keyring.
    let next = fx
        .catalog
        .files()
        .write_unlocked::<_, Error>(&committed.vault, |_| Ok(()))
        .unwrap();
    assert_eq!(fingerprints(next.vault.keyring().unwrap()), expected);
}

#[test]
fn renaming_vault_key_leaves_sync_state_in_place_and_next_transaction_finds_it() {
    let fx = Fixture::synced();
    fx.put_state(GENERATION);

    let renamed = fx
        .write(|vh| vh.set_vault_key("renamed".to_string()))
        .unwrap();

    assert_eq!(renamed.vault.key, "renamed");
    // The sync state stays at its path, and the rename advances it to the
    // next generation (D15).
    let local = LocalSyncState::load(&fx.root, fx.id(), &TestSigner::device()).unwrap();
    assert_eq!(local.generation, GENERATION + 1);
    let key = || fx.vault.unlocked_key().unwrap();
    let next = fx
        .catalog
        .files()
        .write::<_, Error>(&Target::of(&renamed.vault), Unlock::Test(&key), |_| Ok(()))
        .unwrap();
    assert_eq!(
        fingerprints(next.vault.keyring().unwrap()),
        fingerprints(&keyring())
    );
    let mut vh = fx.catalog.load("renamed").unwrap();
    fx.catalog.unlock(&mut vh, AuthContext::OneTime).unwrap();
    assert!(!vh.keyring().unwrap().keys().is_empty());
}

#[test]
fn vault_file_copied_to_other_path_refused() {
    let fx = Fixture::synced();
    let (work, work_replica) = fx.put_state_and_create_work_vault();
    let work_id = work.vault_id().unwrap();
    state(work_id, work_replica, GENERATION)
        .save(&fx.root, &TestSigner::device())
        .unwrap();

    fs::copy(&fx.vault.path, &work.path).unwrap();
    let copied = fs::read_to_string(&work.path).unwrap();

    // The scan lists neither file, since both hold one vault id. No file
    // holds the id of the replaced vault, so its sync state is a missing
    // vault.
    let scan = fx.catalog.scan();
    assert!(scan.vaults.is_empty());
    assert_eq!(scan.duplicates.len(), 1);
    let mut paths = vec![fx.vault.path.clone(), work.path.clone()];
    paths.sort();
    assert_eq!(scan.duplicates[0].paths, paths);
    let missing: Vec<Uuid> = scan.missing.iter().map(|missing| missing.id).collect();
    assert_eq!(missing, vec![work_id]);

    // A transaction on the vault at the copied path finds another vault id.
    let result = fx
        .catalog
        .files()
        .write_unlocked::<_, Error>(&work, |vh| vh.add_item("item", "Item").map(|_| ()));
    assert!(matches!(result, Err(Error::VaultNotFound(_))));
    assert_eq!(fs::read_to_string(&work.path).unwrap(), copied);
}

#[test]
fn sync_state_with_no_vault_file_listed_as_missing_vault() {
    let fx = Fixture::synced();
    fx.put_state(GENERATION);
    let device = TestSigner::device();
    let lost = Uuid::from_u128(0x200);
    state(lost, REPLICA, 1).save(&fx.root, &device).unwrap();
    let left = Uuid::from_u128(0x300);
    let mut leaving = state(left, REPLICA, 1);
    leaving.leaving = true;
    leaving.save(&fx.root, &device).unwrap();
    let forged = Uuid::from_u128(0x400);
    let contents = state(forged, REPLICA, 1)
        .to_file_contents(&TestSigner::random())
        .unwrap();
    fs::write(LocalSyncState::path(&fx.root, forged), contents).unwrap();
    fs::write(fx.root.join("sync").join("other.json"), "{}").unwrap();

    let scan = fx.catalog.scan();

    let missing: BTreeSet<Uuid> = scan.missing.iter().map(|missing| missing.id).collect();
    assert_eq!(missing, BTreeSet::from([lost, forged]));
    for missing in &scan.missing {
        assert_eq!(missing.path, LocalSyncState::path(&fx.root, missing.id));
    }
    assert!(scan.vaults.contains_key("personal"));
}

#[test]
fn restore_takes_next_generation_of_sync_state_and_keeps_replica_id() {
    let fx = Fixture::synced();
    fx.put_state(GENERATION);
    fx.add_item().unwrap();
    let versions = fx.catalog.files().list_versions(fx.id()).unwrap();
    assert_eq!(versions.len(), 1);

    // The oldest version is the vault as created, at the older generation.
    fx.restore(&versions[0].name).unwrap();

    // The restore is a save at `v == s`, so it advances `s`.
    let file = EncryptedVault::load(&fx.vault.path, &TestSigner::device()).unwrap();
    assert_eq!(file.generation, GENERATION + 2);
    assert_eq!(file.replica_id, Some(REPLICA.0));
    assert!(file.items.is_empty());
    assert_eq!(fx.read_case(), SyncLoad::Current);
}

#[test]
fn retained_version_of_another_replica_id_not_restored() {
    let fx = Fixture::new(GENERATION, None);
    fx.write(|vh| vh.set_sync_for_test(GENERATION, Some(REPLICA.0)))
        .unwrap();
    fx.put_state(GENERATION);
    let versions = fx.catalog.files().list_versions(fx.id()).unwrap();
    let before = fx.on_disk();

    let result = fx.restore(&versions[0].name);

    assert!(matches!(result, Err(Error::SyncRepairNeeded(_))));
    assert_eq!(fx.on_disk(), before);
}
