//! `SyncManager`: the start scan, the watches, the notifications, and the
//! staged file copy (9.3).
//!
//! Each manager runs on the test thread through `SyncManager::run_queued`,
//! which runs the queued scans and the retries that are due, as the manager
//! thread does when it wakes. Watch events are fired with
//! `FakeTransport::fire_watch`, downloads complete with
//! `FakeTransport::complete_downloads`, and the retry clock is advanced with
//! `SyncManager::advance_clock`.
//!
//! The pairing request notifications of 9.5 are tested here, with pairing
//! events fired by `FakeTransport::fire_pairing_watch`. The pairing watcher
//! of the new Mac is tested in `sync/tests/pairing.rs`.

use std::collections::BTreeMap;
use std::fs::{self, File, TryLockError};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use jiff::Timestamp;
use uuid::Uuid;

use super::join::{PEER, peer_state, with_format_version};
use super::load::{Fixture, GENERATION, REPLICA};
use super::publish::{last_publish, published};
use super::reads::{Reader, has_item, put_peer, save_count};
use super::state_file::key;
use super::transport::{FakeTransport, request};
use super::txn::{saved, saved_vault, state_file, synced};
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::model::UnlockedKey;
use crate::secrets::vaults::storage::txn::{Committed, StagedCopy, Target, Unlock, VaultWriter};
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::local_state::LocalSyncState;
use crate::secrets::vaults::sync::manager::{
    RESCAN_INTERVAL, RETRY_INTERVAL, SyncEvents, SyncManager, SyncUnlock,
};
use crate::secrets::vaults::sync::model::KeyId;
use crate::secrets::vaults::sync::pairing::PairedVault;
use crate::secrets::vaults::sync::pairing::prompt::PairingPrompt;
use crate::secrets::vaults::sync::recovery::RecoveryKit;
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::state_file::{StateFile, StateHash};
use crate::secrets::vaults::sync::status::PausedCause;
use crate::secrets::vaults::sync::sync_log;
use crate::secrets::vaults::sync::transport::TransportRoot;
use crate::secrets::vaults::{Error, VaultCatalog, VaultsManager};

/// Replica of a third Mac.
const OTHER_PEER: ReplicaId = ReplicaId(Uuid::from_u128(3));

/// Notification of the manager.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Event {
    Synced(Uuid),
    Changed(Uuid),
    /// Count of the pairing requests of a root that prompt.
    Pairings(TransportRoot, usize),
    /// Vault paired on the new Mac, with its sync key bytes.
    Paired(Uuid, Vec<u8>),
    /// Import of a paired vault that waits.
    ImportWaiting(Uuid),
    /// Paired vault imported, with its vault key.
    Imported(Uuid, String),
    /// Import of a paired vault that failed, with the error text.
    ImportFailed(Uuid, String),
}

/// Notifications in the order the manager sent them.
#[derive(Default)]
pub(super) struct Events(Mutex<Vec<Event>>);

impl Events {
    pub(super) fn taken(&self) -> Vec<Event> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

impl SyncEvents for Events {
    fn vault_synced(&self, vault_id: Uuid) {
        self.0.lock().unwrap().push(Event::Synced(vault_id));
    }

    fn peer_changed(&self, vault_id: Uuid) {
        self.0.lock().unwrap().push(Event::Changed(vault_id));
    }

    fn pairing_requests(&self, root: &TransportRoot, count: usize) {
        self.0
            .lock()
            .unwrap()
            .push(Event::Pairings(root.clone(), count));
    }

    fn paired(&self, vault: &PairedVault) {
        let key = vault.key.as_bytes().to_vec();
        self.0
            .lock()
            .unwrap()
            .push(Event::Paired(vault.vault_id, key));
    }

    fn import_waiting(&self, vault_id: Uuid) {
        self.0.lock().unwrap().push(Event::ImportWaiting(vault_id));
    }

    fn vault_imported(&self, vault_id: Uuid, vault_key: &str) {
        self.0
            .lock()
            .unwrap()
            .push(Event::Imported(vault_id, vault_key.to_string()));
    }

    fn import_failed(&self, vault_id: Uuid, error: &Error) {
        self.0
            .lock()
            .unwrap()
            .push(Event::ImportFailed(vault_id, error.to_string()));
    }
}

/// Unlock of the tests: an unlocked flag the test sets, and transactions
/// with the file key of the fixture vault, counted.
pub(super) struct TestUnlock {
    unlocked: AtomicBool,
    key: UnlockedKey,
    transactions: AtomicUsize,
}

impl TestUnlock {
    pub(super) fn transactions(&self) -> usize {
        self.transactions.load(Ordering::SeqCst)
    }
}

impl SyncUnlock for TestUnlock {
    fn unlocked(&self) -> bool {
        self.unlocked.load(Ordering::SeqCst)
    }

    fn transaction(&self, files: &VaultWriter, target: &Target) -> Result<Committed<()>, Error> {
        self.transactions.fetch_add(1, Ordering::SeqCst);
        let key = || self.key.duplicate_for_test();
        files.write(target, Unlock::Test(&key), |_| Ok(()))
    }
}

/// Manager of the vault of `fx`, run on the test thread, and its events
/// and unlock. The start scan is queued.
pub(super) struct Managed {
    pub(super) manager: SyncManager,
    pub(super) events: Arc<Events>,
    pub(super) unlock: Arc<TestUnlock>,
}

impl Managed {
    pub(super) fn start(fx: &Fixture, unlocked: bool) -> Self {
        Self::of(&fx.catalog, fx.vault.unlocked_key().unwrap(), unlocked)
    }

    /// Manager of `catalog`, whose transactions use the file key `key`.
    pub(super) fn of(catalog: &VaultCatalog, key: UnlockedKey, unlocked: bool) -> Self {
        let events = Arc::new(Events::default());
        let unlock = Arc::new(TestUnlock {
            unlocked: AtomicBool::new(unlocked),
            key,
            transactions: AtomicUsize::new(0),
        });
        let manager = SyncManager::manual(catalog.clone(), events.clone(), unlock.clone());
        Self {
            manager,
            events,
            unlock,
        }
    }

    pub(super) fn run(&self) {
        self.manager.run_queued();
    }
}

/// Root of the synced folder of the pairing tests.
pub(super) fn folder_root() -> TransportRoot {
    TransportRoot::Folder {
        path: PathBuf::from("/manager/Vaults"),
    }
}

/// Record `root` as the transport root in the sidecar of `fx`.
pub(super) fn set_root(fx: &Fixture, root: &TransportRoot) {
    let mut sidecar = Sidecar::load(&fx.root, fx.id());
    sidecar.transport = Some(root.clone());
    sidecar.save(&fx.root, fx.id()).unwrap();
}

/// Bytes of each file under `dir`, by path, with the lock files left out.
fn files_under(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut found = BTreeMap::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name != "locks") {
                    dirs.push(path);
                }
            } else {
                found.insert(path.clone(), fs::read(&path).unwrap());
            }
        }
    }
    found
}

/// Lock checks of the writes to the synced folder, one for each write: the
/// `flock` of the vault excludes a second open file, and the per-vault
/// mutex is held.
type LockChecks = Arc<Mutex<Vec<(bool, bool)>>>;

/// Check the locks of the vault at each write of `transport` to the
/// directory of a vault of `fx`.
pub(super) fn check_locks_on_write(transport: &FakeTransport, fx: &Fixture) -> LockChecks {
    let checks = LockChecks::default();
    let found = checks.clone();
    let locks = fx.catalog.files().locks().clone();
    let root = fx.root.clone();
    transport.on_write(move |vault_id| {
        let id = ShortId::encode_uuid(vault_id);
        let path = root.join("locks").join(format!("{id}.lock"));
        let flocked = File::open(&path)
            .is_ok_and(|file| matches!(file.try_lock(), Err(TryLockError::WouldBlock)));
        found
            .lock()
            .unwrap()
            .push((flocked, locks.is_held(vault_id)));
    });
    checks
}

/// Assert that each write checked by `checks` held both locks, and that at
/// least `count` writes were checked.
pub(super) fn assert_locked_writes(checks: &LockChecks, count: usize) {
    let checks = checks.lock().unwrap();
    assert!(checks.len() >= count, "{} writes checked", checks.len());
    for (n, (flocked, held)) in checks.iter().enumerate() {
        assert!(flocked, "write {n} holds the lock file");
        assert!(held, "write {n} holds the per-vault mutex");
    }
}

/// Add an item to the vault of `fx` with a publish that fails, then make
/// the writes of the folder work again. Returns the hash of the staged file.
fn failed_publish(transport: &FakeTransport, fx: &Fixture) -> StateHash {
    let listed = published(transport, fx);
    transport.set_failing_writes(true);
    fx.write(|vh| vh.add_item("unpublished", "Unpublished").map(|_| ()))
        .unwrap();
    transport.set_failing_writes(false);
    let staged = fs::read(LocalSyncState::staged_path(&fx.root, fx.id())).unwrap();
    let hash = StateHash::of(&staged);
    assert_eq!(saved(fx).0.staged_hash, Some(hash));
    assert_eq!(published(transport, fx), listed);
    hash
}

#[test]
fn only_files_manager_writes_staged_file_copy_and_sidecar_hash_under_both_locks() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let hash = failed_publish(&transport, &fx);
    let checks = check_locks_on_write(&transport, &fx);
    let before = files_under(&fx.root);
    let vault = fs::read(&fx.vault.path).unwrap();
    let sidecar = Sidecar::load(&fx.root, fx.id());
    assert!(matches!(
        &sidecar.paused[..],
        [PausedCause::PublishFailed { .. }]
    ));
    assert!(published(&transport, &fx).is_empty());
    let writes = transport.writes();
    let managed = Managed::start(&fx, false);

    // The copy waits for the vault locks.
    let held = fx.catalog.files().hold_for_test(fx.id(), &fx.vault.path);
    std::thread::scope(|s| {
        let run = s.spawn(|| managed.run());
        fx.catalog.files().locks().wait_for_waiters(fx.id(), 1);
        assert_eq!(transport.writes(), writes);
        assert_eq!(Sidecar::load(&fx.root, fx.id()), sidecar);
        drop(held);
        run.join().unwrap();
    });

    // One file is written in the folder, the staged file under its hash.
    assert_eq!(transport.writes(), writes + 1);
    assert_eq!(published(&transport, &fx), [hash]);
    assert_locked_writes(&checks, 1);
    // Under the app data directory, only the sidecar changes, by the hash.
    let after = files_under(&fx.root);
    let sidecar_path = Sidecar::path(&fx.root, fx.id());
    let changed: Vec<&PathBuf> = after
        .iter()
        .filter(|(path, bytes)| before.get(*path) != Some(bytes))
        .map(|(path, _)| path)
        .collect();
    assert_eq!(changed, [&sidecar_path]);
    assert_eq!(after.len(), before.len());
    assert_eq!(fs::read(&fx.vault.path).unwrap(), vault);
    let mut expected = sidecar;
    expected.last_publish = Some(hash);
    expected.record_joined(REPLICA, hash);
    expected.paused.clear();
    assert_eq!(Sidecar::load(&fx.root, fx.id()), expected);
    assert_eq!(managed.unlock.transactions(), 0);
}

#[test]
fn replaced_staged_file_not_copied_and_next_transaction_rewrites_it() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let hash = failed_publish(&transport, &fx);
    let staged_path = LocalSyncState::staged_path(&fx.root, fx.id());
    fs::write(&staged_path, b"replaced").unwrap();
    let managed = Managed::start(&fx, false);

    managed.run();

    assert!(published(&transport, &fx).is_empty());
    assert_eq!(last_publish(&fx), None);
    assert_eq!(fs::read(&staged_path).unwrap(), b"replaced");
    assert_eq!(
        fx.catalog
            .files()
            .copy_staged(fx.id(), Some(&fx.vault.path))
            .unwrap(),
        StagedCopy::Refused
    );

    fx.write(|_| Ok(())).unwrap();

    let rewritten = fs::read(&staged_path).unwrap();
    let rewritten_hash = StateHash::of(&rewritten);
    assert_ne!(rewritten, b"replaced");
    // A new staged file of the same state, with a fresh nonce.
    assert_ne!(rewritten_hash, hash);
    assert_eq!(saved(&fx).0.staged_hash, Some(rewritten_hash));
    assert_eq!(published(&transport, &fx), [rewritten_hash]);
    assert_eq!(last_publish(&fx), Some(rewritten_hash));
}

#[test]
fn every_synced_vault_folder_write_holds_per_vault_mutex_and_lock_file() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let checks = check_locks_on_write(&transport, &fx);

    // A publish, and the `key.json` write of a recovery kit.
    fx.add_item().unwrap();
    let kit = RecoveryKit::create(fx.id(), KeyId(1), &key());
    let unlock = || fx.vault.unlocked_key().unwrap();
    kit.confirm_saved(
        fx.catalog.files(),
        &Target::of(&fx.vault),
        Unlock::Test(&unlock),
    )
    .unwrap();
    // A second publish, which deletes the first.
    fx.write(|vh| vh.add_item("second", "Second").map(|_| ()))
        .unwrap();
    assert_eq!(published(&transport, &fx).len(), 1);
    let transactions = checks.lock().unwrap().len();
    assert!(transactions >= 4, "{transactions} writes checked");

    // A copy of the manager.
    failed_publish(&transport, &fx);
    let managed = Managed::start(&fx, false);
    managed.run();

    assert_eq!(published(&transport, &fx).len(), 2);
    assert_locked_writes(&checks, transactions + 1);
}

#[test]
fn watch_event_for_peer_change_while_vault_is_locked_sets_flag() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let reader = Reader::of(&fx);
    let locks = fx.catalog.files().locks();
    let managed = Managed::start(&fx, false);
    managed.run();
    assert_eq!(transport.watch_count(), 1);
    assert!(!locks.is_pending(fx.id()));

    put_peer(&fx, &transport, PEER, "joined");
    assert_eq!(transport.fire_watch(fx.id()), 1);
    managed.run();

    assert!(locks.is_pending(fx.id()));
    assert_eq!(managed.events.taken(), [Event::Changed(fx.id())]);
    assert_eq!(managed.unlock.transactions(), 0);

    let vh = reader.read().unwrap();

    assert!(has_item(&vh, "joined"));
    assert_eq!(reader.key_reads(), 1, "one prompt");
    assert!(!locks.is_pending(fx.id()));
}

#[test]
fn peer_change_before_start_sets_flag() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    put_peer(&fx, &transport, PEER, "joined");
    let saves = save_count(&fx);
    let managed = Managed::start(&fx, false);

    managed.run();

    let locks = fx.catalog.files().locks();
    assert!(locks.is_pending(fx.id()));
    assert_eq!(managed.events.taken(), [Event::Changed(fx.id())]);
    assert_eq!(save_count(&fx), saves);
    assert!(transport.download_requests().is_empty());
    assert!(saved_vault(&fx).get_item("joined").is_err());
}

#[test]
fn failed_publish_completes_after_vault_locks() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let hash = failed_publish(&transport, &fx);
    let (local, state) = saved(&fx);
    // The folder is still unreachable when the manager starts.
    transport.set_unavailable(true);
    let managed = Managed::start(&fx, false);
    managed.run();
    assert_eq!(last_publish(&fx), None);
    transport.set_unavailable(false);

    // The copy is retried a minute later, with no key and no unlock.
    let before = fx.on_disk();
    let retry = RETRY_INTERVAL.as_secs();
    managed.manager.advance_clock(retry - 1);
    managed.run();
    assert!(published(&transport, &fx).is_empty());
    managed.manager.advance_clock(1);
    managed.run();

    assert_eq!(published(&transport, &fx), [hash]);
    assert_eq!(last_publish(&fx), Some(hash));
    assert_eq!(fx.on_disk(), before);
    assert_eq!(managed.unlock.transactions(), 0);
    assert_eq!(saved(&fx).0, local);

    // The next transaction moves the staged context and publishes nothing.
    let writes = transport.writes();
    fx.write(|_| Ok(())).unwrap();

    let (local, _) = saved(&fx);
    assert_eq!(local.published_context, state.context);
    assert_eq!(local.staged_hash, None);
    assert_eq!(transport.writes(), writes);
}

#[test]
fn unlock_with_peer_files_not_yet_downloaded_joins_rest_by_transaction_if_unlocked_and_flag_if_locked()
 {
    for unlocked in [true, false] {
        let transport = Arc::new(FakeTransport::default());
        let fx = synced(&transport);
        let remote = peer_state(&fx, OTHER_PEER, "remote");
        let bytes = state_file(&fx, OTHER_PEER, &remote);
        let name = StateFile::name(StateHash::of(&bytes));
        transport.put_remote_with(fx.id(), OTHER_PEER, &name, &bytes);
        let locks = fx.catalog.files().locks();
        let managed = Managed::start(&fx, unlocked);

        // A file that is not local is requested and not reported.
        managed.run();

        assert_eq!(transport.download_requests(), [fx.id()]);
        assert!(managed.events.taken().is_empty());
        assert!(!locks.is_pending(fx.id()));
        assert_eq!(managed.unlock.transactions(), 0);

        assert_eq!(transport.complete_downloads(fx.id()), 1);
        assert_eq!(transport.fire_watch(fx.id()), 1);
        managed.run();

        if unlocked {
            assert_eq!(managed.unlock.transactions(), 1);
            assert_eq!(managed.events.taken(), [Event::Synced(fx.id())]);
            assert!(saved_vault(&fx).get_item("remote").is_ok());
            assert!(!locks.is_pending(fx.id()));
        } else {
            assert_eq!(managed.unlock.transactions(), 0);
            assert_eq!(managed.events.taken(), [Event::Changed(fx.id())]);
            assert!(saved_vault(&fx).get_item("remote").is_err());
            assert!(locks.is_pending(fx.id()));
            let vh = fx.read().unwrap();
            assert!(has_item(&vh, "remote"));
        }
        assert_eq!(transport.download_requests(), [fx.id()]);
    }
}

#[test]
fn bad_signature_or_staged_hash_gets_no_copy() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let hash = failed_publish(&transport, &fx);
    let files = fx.catalog.files();
    let valid = fs::read_to_string(fx.state_path()).unwrap();

    // Signed by another key.
    let (local, _) = saved(&fx);
    fx.put(&local, &TestSigner::random());
    let managed = Managed::start(&fx, false);
    managed.run();

    assert_eq!(
        files.copy_staged(fx.id(), Some(&fx.vault.path)).unwrap(),
        StagedCopy::NotStaged
    );
    assert!(published(&transport, &fx).is_empty());
    assert_eq!(last_publish(&fx), None);

    // The sidecar records the staged hash as the last publish.
    fx.put_text(&valid);
    let mut sidecar = Sidecar::load(&fx.root, fx.id());
    sidecar.last_publish = Some(hash);
    sidecar.save(&fx.root, fx.id()).unwrap();
    let writes = transport.writes();

    assert_eq!(
        files.copy_staged(fx.id(), Some(&fx.vault.path)).unwrap(),
        StagedCopy::NotStaged
    );
    assert_eq!(transport.writes(), writes);
    assert!(published(&transport, &fx).is_empty());
}

#[test]
fn repeated_hash_does_not_set_flag_again() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    // A file of a newer format is listed and never joins.
    let peer = peer_state(&fx, PEER, "newer");
    let newer = with_format_version(&state_file(&fx, PEER, &peer), 2);
    transport.put_state(fx.id(), PEER, &newer);
    let locks = fx.catalog.files().locks();
    let managed = Managed::start(&fx, false);
    managed.run();
    assert!(locks.is_pending(fx.id()));
    assert_eq!(managed.events.taken(), [Event::Changed(fx.id())]);

    fx.write(|_| Ok(())).unwrap();
    assert!(!locks.is_pending(fx.id()));

    transport.fire_watch(fx.id());
    managed.run();

    assert!(!locks.is_pending(fx.id()));
    assert!(managed.events.taken().is_empty());

    // A file with a new hash sets it again.
    put_peer(&fx, &transport, OTHER_PEER, "other");
    transport.fire_watch(fx.id());
    managed.run();

    assert!(locks.is_pending(fx.id()));
    assert_eq!(managed.events.taken(), [Event::Changed(fx.id())]);
}

#[test]
fn watch_event_while_unlocked_runs_one_transaction_and_calls_vault_synced() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let managed = Managed::start(&fx, true);
    managed.run();
    assert_eq!(managed.unlock.transactions(), 0);
    let saves = save_count(&fx);

    // A burst of events gives one scan.
    put_peer(&fx, &transport, PEER, "joined");
    transport.fire_watch(fx.id());
    transport.fire_watch(fx.id());
    managed.run();

    assert_eq!(managed.unlock.transactions(), 1);
    assert_eq!(managed.events.taken(), [Event::Synced(fx.id())]);
    assert_eq!(save_count(&fx), saves + 1);
    assert!(saved_vault(&fx).get_item("joined").is_ok());
    assert!(!fx.catalog.files().locks().is_pending(fx.id()));
}

#[test]
fn background_copy_read_again_on_next_use() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let manager = Mutex::new(VaultsManager::with(fx.catalog.clone()));
    VaultsManager::unlock_vault(&manager, "personal").unwrap();
    let managed = Managed::start(&fx, true);
    managed.run();

    put_peer(&fx, &transport, PEER, "joined");
    transport.fire_watch(fx.id());
    managed.run();
    assert_eq!(managed.events.taken(), [Event::Synced(fx.id())]);

    // The copy kept before the transaction is locked at its next use.
    {
        let mut m = VaultsManager::lock(&manager);
        let vh = m.get_or_create_vault_mut("personal").unwrap();
        assert!(matches!(vh.list_items(), Err(Error::VaultLocked)));
    }
    VaultsManager::unlock_vault(&manager, "personal").unwrap();

    let mut m = VaultsManager::lock(&manager);
    let vh = m.get_or_create_vault_mut("personal").unwrap();
    assert!(has_item(vh, "joined"));
}

#[test]
fn shutdown_ends_every_watch() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let managed = Managed::start(&fx, false);
    managed.run();
    assert_eq!(transport.watch_count(), 1);

    managed.manager.shutdown();

    assert_eq!(transport.watch_count(), 0);
    // A change after the shutdown sets no flag.
    put_peer(&fx, &transport, PEER, "joined");
    assert_eq!(transport.fire_watch(fx.id()), 0);
    managed.run();
    assert!(!fx.catalog.files().locks().is_pending(fx.id()));
}

#[test]
fn refresh_watches_vault_whose_sync_was_enabled_after_start() {
    let transport = Arc::new(FakeTransport::default());
    let fx = Fixture::with_transport(GENERATION, Some(REPLICA), transport.clone());
    let managed = Managed::start(&fx, false);
    managed.run();
    assert_eq!(transport.watch_count(), 0);

    fx.put_state(GENERATION);
    put_peer(&fx, &transport, PEER, "joined");
    managed.manager.refresh();
    managed.run();

    assert_eq!(transport.watch_count(), 1);
    assert!(fx.catalog.files().locks().is_pending(fx.id()));
    assert_eq!(managed.events.taken(), [Event::Changed(fx.id())]);
}

#[test]
fn new_pairing_request_reaches_app() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    set_root(&fx, &folder_root());
    transport.set_now(Timestamp::now());
    let managed = Managed::start(&fx, false);
    managed.run();
    // One watch of the vault and one of the pairing directory of its root.
    assert_eq!(transport.watch_count(), 2);
    assert_eq!(managed.events.taken(), [Event::Pairings(folder_root(), 0)]);

    transport.put_pairing(request(1), b"{}");
    assert_eq!(transport.fire_pairing_watch(), 1);
    managed.run();

    assert_eq!(managed.events.taken(), [Event::Pairings(folder_root(), 1)]);
    // The request is downloaded before the user types its code.
    assert_eq!(transport.pairing_download_requests(), [request(1)]);

    // A burst of events gives one count.
    transport.put_pairing(request(2), b"{}");
    transport.fire_pairing_watch();
    transport.fire_pairing_watch();
    managed.run();

    assert_eq!(managed.events.taken(), [Event::Pairings(folder_root(), 2)]);
    assert!(!fx.catalog.files().locks().is_pending(fx.id()));

    managed.manager.shutdown();

    assert_eq!(transport.watch_count(), 0);
    assert_eq!(transport.fire_pairing_watch(), 0);
}

#[test]
fn dismissed_request_does_not_raise_count_and_request_with_new_id_does() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    set_root(&fx, &folder_root());
    transport.set_now(Timestamp::now());
    transport.put_pairing(request(1), b"{}");
    let managed = Managed::start(&fx, false);
    managed.run();
    assert_eq!(managed.events.taken(), [Event::Pairings(folder_root(), 1)]);

    PairingPrompt::dismiss(&*transport, &folder_root(), &fx.root).unwrap();
    transport.fire_pairing_watch();
    managed.run();

    assert_eq!(managed.events.taken(), [Event::Pairings(folder_root(), 0)]);
    // A dismissed request is not downloaded again.
    assert_eq!(transport.pairing_download_requests(), [request(1)]);

    transport.put_pairing(request(2), b"{}");
    transport.fire_pairing_watch();
    managed.run();

    assert_eq!(managed.events.taken(), [Event::Pairings(folder_root(), 1)]);

    // A request older than 24 hours on the clock of the manager is not
    // counted.
    managed.manager.advance_clock(24 * 60 * 60 + 60);
    transport.fire_pairing_watch();
    managed.run();

    assert_eq!(managed.events.taken(), [Event::Pairings(folder_root(), 0)]);
}

#[test]
fn rescan_reports_peer_change_with_no_watch_event() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let managed = Managed::start(&fx, false);
    managed.run();
    assert!(managed.events.taken().is_empty());

    put_peer(&fx, &transport, PEER, "joined");
    managed.manager.advance_clock(RESCAN_INTERVAL.as_secs() - 1);
    managed.run();
    assert!(managed.events.taken().is_empty());
    managed.manager.advance_clock(1);
    managed.run();

    assert_eq!(managed.events.taken(), [Event::Changed(fx.id())]);
    assert!(fx.catalog.files().locks().is_pending(fx.id()));
    let logged = sync_log::entries().into_iter().any(|entry| {
        entry.vault_id == Some(fx.id())
            && entry.message == "Rescan found a peer change that no watch event reported"
    });
    assert!(logged);
}

#[test]
fn rescan_with_no_change_reports_nothing() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let managed = Managed::start(&fx, true);
    managed.run();

    for _ in 0..3 {
        managed.manager.advance_clock(RESCAN_INTERVAL.as_secs());
        managed.run();
    }

    assert!(managed.events.taken().is_empty());
    assert_eq!(managed.unlock.transactions(), 0);
    assert!(!fx.catalog.files().locks().is_pending(fx.id()));
}

#[test]
fn rescan_joins_peer_change_if_unlocked() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let managed = Managed::start(&fx, true);
    managed.run();

    put_peer(&fx, &transport, PEER, "joined");
    managed.manager.advance_clock(RESCAN_INTERVAL.as_secs());
    managed.run();

    assert_eq!(managed.unlock.transactions(), 1);
    assert_eq!(managed.events.taken(), [Event::Synced(fx.id())]);
    assert!(saved_vault(&fx).get_item("joined").is_ok());
}

#[test]
fn rescan_counts_pairing_requests_and_reports_only_new_count() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    set_root(&fx, &folder_root());
    transport.set_now(Timestamp::now());
    let managed = Managed::start(&fx, false);
    managed.run();
    assert_eq!(managed.events.taken(), [Event::Pairings(folder_root(), 0)]);

    managed.manager.advance_clock(RESCAN_INTERVAL.as_secs());
    managed.run();
    assert!(managed.events.taken().is_empty());

    transport.put_pairing(request(1), b"{}");
    managed.manager.advance_clock(RESCAN_INTERVAL.as_secs());
    managed.run();

    assert_eq!(managed.events.taken(), [Event::Pairings(folder_root(), 1)]);

    managed.manager.advance_clock(RESCAN_INTERVAL.as_secs());
    managed.run();

    assert!(managed.events.taken().is_empty());
}
