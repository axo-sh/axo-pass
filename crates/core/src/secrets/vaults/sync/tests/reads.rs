//! Read-only requests: the pending flag, the listing of a vault with no
//! change notifications, and the repair transaction for reads (9.2).
//!
//! A read is an unlock through [`VaultCatalog::unlock`], the path of the
//! broker reads and, through [`VaultsManager::unlock_vault`], of the app
//! reads. The broker request parsing and the keychain are not run.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use super::guard::{drift, published_vault, stopped};
use super::join::{PEER, peer_state};
use super::load::{Fixture, GENERATION, REPLICA, body, device_key, state};
use super::state_file::keyring;
use super::transport::FakeTransport;
use super::txn::{
    add_item_counting, saved, saved_vault, state_file, synced, two_keys, under_key_2,
};
use crate::core::auth::AuthContext;
use crate::secrets::vaults::bundle::FileKeyWrapper;
use crate::secrets::vaults::format::encrypted_vault::EncryptedVault;
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::model::Vault;
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::storage::test_unlocker::KeyUnlocker;
use crate::secrets::vaults::storage::txn::{Committed, Target, Unlock, VaultWriter};
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::load::SyncLoad;
use crate::secrets::vaults::sync::model::KeyId;
use crate::secrets::vaults::sync::state_file::{StateFile, StateHash};
use crate::secrets::vaults::sync::view::VaultView;
use crate::secrets::vaults::{Error, Unlocker, VaultCatalog, VaultHandle, VaultsManager, autofill};

/// Replica of a third Mac.
const OTHER_PEER: ReplicaId = ReplicaId(Uuid::from_u128(3));

/// Unlocker that counts the reads of a file key, as the counting key source
/// of 7.9 counts prompts. An unlock reads the key once, and a transaction
/// reads it once per attempt.
struct CountingUnlocker {
    keys: KeyUnlocker,
    reads: Arc<AtomicUsize>,
}

impl Unlocker for CountingUnlocker {
    fn unlock(&self, vw: &mut VaultHandle, root: &Path, context: AuthContext) -> Result<(), Error> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.keys.unlock(vw, root, context)
    }

    fn read_transaction(
        &self,
        files: &VaultWriter,
        target: &Target,
        _context: AuthContext,
    ) -> Result<Committed<()>, Error> {
        let enc_vault = EncryptedVault::load(&target.path, &TestSigner::device())?;
        let key = self.keys.file_key(&enc_vault)?;
        let unlock = || {
            self.reads.fetch_add(1, Ordering::SeqCst);
            key.duplicate_for_test()
        };
        files.write(target, Unlock::Test(&unlock), |_| Ok(()))
    }

    fn file_key_wrapper(&self, context: AuthContext) -> Result<FileKeyWrapper, Error> {
        self.keys.file_key_wrapper(context)
    }

    fn new_vault(
        &self,
        name: Option<String>,
        key: String,
        context: AuthContext,
    ) -> Result<Vault, Error> {
        self.keys.new_vault(name, key, context)
    }
}

/// Catalog of the vault of a fixture, with the writer and locks of the
/// fixture, whose unlocker counts the key reads.
struct Reader {
    catalog: VaultCatalog,
    reads: Arc<AtomicUsize>,
}

impl Reader {
    fn of(fx: &Fixture) -> Self {
        let keys = HashMap::from([(fx.id(), fx.vault.unlocked_key().unwrap())]);
        let reads = Arc::new(AtomicUsize::new(0));
        let unlocker = CountingUnlocker {
            keys: KeyUnlocker(keys),
            reads: reads.clone(),
        };
        let catalog = VaultCatalog::with_unlocker(
            fx.vaults_dir.clone(),
            fx.catalog.files().clone(),
            Vec::new(),
            Arc::new(unlocker),
        );
        Self { catalog, reads }
    }

    /// Unlock the vault through the catalog, a read.
    fn read(&self) -> Result<VaultHandle, Error> {
        let mut vh = self.catalog.load("personal")?;
        self.catalog.unlock(&mut vh, AuthContext::OneTime)?;
        Ok(vh)
    }

    fn key_reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }
}

/// Put a state file of `replica` that adds item `item_key` in the folder.
pub(super) fn put_peer(
    fx: &Fixture,
    transport: &FakeTransport,
    replica: ReplicaId,
    item_key: &str,
) {
    let peer = peer_state(fx, replica, item_key);
    transport.put_state(fx.id(), replica, &state_file(fx, replica, &peer));
}

fn save_count(fx: &Fixture) -> u64 {
    fx.catalog.files().locks().save_count(fx.id()).unwrap()
}

fn has_item(vh: &VaultHandle, key: &str) -> bool {
    vh.get_item_overview(key).unwrap().is_some()
}

/// Lock file of the vault of `fx`.
fn lock_path(fx: &Fixture) -> PathBuf {
    let id = ShortId::encode_uuid(fx.id());
    fx.root.join("locks").join(format!("{id}.lock"))
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn with_pending_flag_clear_secret_read_and_login_fill_read_no_synced_folder_file_and_run_no_transaction()
 {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    fx.write(|vh| {
        vh.add_item("mail", "Mail")?;
        let value = SecretString::from("secret".to_string());
        vh.add_secret("mail", "password", "Password", FieldKind::default(), value)
    })
    .unwrap();
    put_peer(&fx, &transport, PEER, "joined");
    fx.write(|_| Ok(())).unwrap();
    let reader = Reader::of(&fx);
    let locks = fx.catalog.files().locks();
    let reads = transport.reads();
    let saves = save_count(&fx);

    // A secret read opens the vault by key. A login fill unlocks each
    // listed vault. The first read lists the peer directories, which reads
    // no state file and finds every file joined.
    let vh = reader
        .catalog
        .open("personal", AuthContext::OneTime)
        .unwrap();
    let secret = vh.get_secret("mail", "password").unwrap().unwrap();
    assert_eq!(secret.expose_secret().as_str(), "secret");
    for (_, mut vh) in reader.catalog.list() {
        reader
            .catalog
            .unlock(&mut vh, AuthContext::OneTime)
            .unwrap();
        autofill::collect_items(&vh, None).unwrap();
    }

    assert_eq!(transport.reads(), reads);
    assert_eq!(save_count(&fx), saves);
    assert_eq!(reader.key_reads(), 2);

    // With a live watch, a read lists nothing, so a peer file that is not
    // joined runs no transaction until the flag is set.
    locks.set_watched(fx.id(), true);
    put_peer(&fx, &transport, OTHER_PEER, "other");
    let vh = reader.read().unwrap();

    assert!(!has_item(&vh, "other"));
    assert_eq!(transport.reads(), reads);
    assert_eq!(save_count(&fx), saves);
}

#[test]
fn peer_change_while_vault_is_locked_sets_flag_and_next_read_joins_it_before_serving_with_one_prompt()
 {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let reader = Reader::of(&fx);
    let locks = fx.catalog.files().locks();
    locks.set_watched(fx.id(), true);
    put_peer(&fx, &transport, PEER, "joined");

    // The flag is set as the `SyncManager` of 9.3 sets it for a peer change
    // while the vault is locked.
    assert!(locks.set_pending(fx.id()));
    let vh = reader.read().unwrap();

    assert!(has_item(&vh, "joined"));
    assert!(saved_vault(&fx).get_item("joined").is_ok());
    assert_eq!(reader.key_reads(), 1, "one prompt");
    assert!(!locks.is_pending(fx.id()));

    // The next read runs no transaction.
    let saves = save_count(&fx);
    let vh = reader.read().unwrap();

    assert!(has_item(&vh, "joined"));
    assert_eq!(save_count(&fx), saves);
    assert_eq!(reader.key_reads(), 2);
}

#[test]
fn with_no_change_notifications_read_lists_peer_files_at_most_once_a_minute_and_joins_changed_one()
{
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let reader = Reader::of(&fx);
    let files = fx.catalog.files();
    let saves = save_count(&fx);

    // The first read lists and finds no change.
    reader.read().unwrap();
    assert_eq!(save_count(&fx), saves);

    // A peer file that arrives within the minute is not listed by a read.
    put_peer(&fx, &transport, PEER, "joined");
    let reads = transport.reads();
    assert!(!has_item(&reader.read().unwrap(), "joined"));
    files.advance_listing_clock(30);
    assert!(!has_item(&reader.read().unwrap(), "joined"));
    assert_eq!(save_count(&fx), saves);
    assert_eq!(transport.reads(), reads);

    // A minute after the first listing, a read lists again and joins it.
    files.advance_listing_clock(31);
    let vh = reader.read().unwrap();

    assert!(has_item(&vh, "joined"));
    assert_eq!(save_count(&fx), saves + 1);
    assert_eq!(transport.reads(), reads + 1);
    assert!(saved_vault(&fx).get_item("joined").is_ok());
}

#[test]
fn pending_file_that_is_still_remote_does_not_delay_read() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let reader = Reader::of(&fx);
    let locks = fx.catalog.files().locks();
    locks.set_watched(fx.id(), true);
    let peer = peer_state(&fx, PEER, "joined");
    let bytes = state_file(&fx, PEER, &peer);
    let name = StateFile::name(fx.id(), StateHash::of(&bytes));
    transport.put_remote_with(fx.id(), PEER, &name, &bytes);
    locks.set_pending(fx.id());

    let vh = reader.read().unwrap();

    // The read serves the local vault and requests the download. A file
    // that is not local does not keep the flag set.
    assert!(!has_item(&vh, "joined"));
    assert_eq!(transport.download_requests(), [fx.id()]);
    assert!(!locks.is_pending(fx.id()));
}

#[test]
fn read_on_vault_with_v_other_than_s_runs_repair_transaction_with_same_unlock_and_serves_repaired_vault()
 {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    fx.add_item().unwrap();
    let backup = fs::read_to_string(fx.state_path()).unwrap();
    transport.set_unavailable(true);
    fx.write(|vh| vh.add_item("unpublished", "Unpublished").map(|_| ()))
        .unwrap();
    transport.set_unavailable(false);
    fx.put_text(&backup);
    let SyncLoad::NewerVault { vault: v, .. } = fx.read_case() else {
        panic!("not a newer vault");
    };
    let reader = Reader::of(&fx);

    let vh = reader.read().unwrap();

    // The unlock reads the key, finds `v > s`, and the repair transaction
    // reads it once more on the same context. The app authenticated that
    // context at the unlock, so the read draws one prompt.
    assert_eq!(reader.key_reads(), 2);
    assert!(has_item(&vh, "unpublished"));
    assert_eq!(fx.read_case(), SyncLoad::Current);
    let (local, state) = saved(&fx);
    assert_eq!(local.generation, v + 1);
    let view = VaultView::of(&state);
    assert!(view.items.values().any(|item| item.key == "unpublished"));
}

#[test]
fn read_on_vault_with_paused_or_stopped_sync_serves_local_vault() {
    // Stopped by drift: the read transaction joins nothing.
    let transport = Arc::new(FakeTransport::default());
    let fx = published_vault(&transport);
    drift(&fx, "item");
    assert_eq!(fx.write(|_| Ok(())).unwrap().sync_status, stopped());
    put_peer(&fx, &transport, PEER, "joined");
    let locks = fx.catalog.files().locks();
    locks.set_pending(fx.id());

    let vh = fx.read().unwrap();

    let vault = vh.get_unlocked_vault().unwrap();
    assert_eq!(vault.get_item("item").unwrap().title, "Drifted");
    assert!(vault.get_item("joined").is_err());

    // Paused by an unreachable folder: the read transaction lists nothing,
    // so the flag stays set.
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    fx.add_item().unwrap();
    transport.set_unavailable(true);
    let locks = fx.catalog.files().locks();
    locks.set_pending(fx.id());

    let vh = fx.read().unwrap();

    assert!(has_item(&vh, "item"));
    assert!(locks.is_pending(fx.id()));
}

#[test]
fn after_second_key_missing_miss_unlock_with_key_repairs_v_greater_than_s_and_serves_change() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let own = body(REPLICA, &[device_key()]);
    fx.put_text(&under_key_2(&fx, &own, &keyring()));
    add_item_counting(&fx, |_| {});
    assert_eq!(fx.read_case(), SyncLoad::KeyMissing(KeyId(2)));

    // The keyring of the sync state gains key id 2, so the next unlock
    // holds the key and finds `v > s`.
    fx.put_text(&under_key_2(&fx, &own, &two_keys()));
    let case = SyncLoad::NewerVault {
        vault: GENERATION + 1,
        state: GENERATION,
    };
    assert_eq!(fx.read_case(), case);

    let vh = fx.read().unwrap();

    assert!(has_item(&vh, "item"));
    assert_eq!(fx.read_case(), SyncLoad::Current);
    let file = EncryptedVault::load(&fx.vault.path, &TestSigner::device()).unwrap();
    assert_eq!(file.generation, GENERATION + 2);
}

#[test]
fn sync_state_of_another_vault_id_is_still_refused_at_read() {
    let fx = Fixture::synced();
    fx.put(
        &state(Uuid::from_u128(0x200), REPLICA, GENERATION),
        &TestSigner::device(),
    );
    let before = fx.on_disk();

    let result = fx.read();

    assert!(matches!(result, Err(Error::SyncRepairNeeded(_))));
    assert_eq!(fx.on_disk(), before);
}

#[test]
fn flag_set_during_transaction_after_its_peer_listing_is_not_cleared_by_it() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    put_peer(&fx, &transport, PEER, "joined");
    let locks = fx.catalog.files().locks().clone();
    let id = fx.id();
    locks.set_pending(id);
    // The peer file is read after the epoch is read, as a change that the
    // `SyncManager` reports while the transaction runs.
    let during = locks.clone();
    transport.on_read(move || {
        during.set_pending(id);
    });

    fx.write(|_| Ok(())).unwrap();

    assert!(saved_vault(&fx).get_item("joined").is_ok());
    assert!(locks.is_pending(id));

    // A transaction during which the flag is not set again clears it.
    transport.on_read(|| {});
    fx.write(|_| Ok(())).unwrap();

    assert!(!locks.is_pending(id));
}

#[test]
fn read_transaction_that_fails_serves_vault_as_unlocked_before_and_repair_that_fails_fails_read() {
    // A transaction started by the flag fails to take the lock file.
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    fx.add_item().unwrap();
    put_peer(&fx, &transport, PEER, "joined");
    let locks = fx.catalog.files().locks();
    locks.set_watched(fx.id(), true);
    locks.set_pending(fx.id());
    let before = fx.on_disk();
    let lock = lock_path(&fx);
    set_mode(&lock, 0o444);

    let result = fx.read();

    set_mode(&lock, 0o644);
    let vh = result.unwrap();
    assert!(has_item(&vh, "item"));
    assert!(!has_item(&vh, "joined"));
    assert_eq!(fx.on_disk(), before);
    assert!(locks.is_pending(fx.id()));

    // A repair transaction that fails fails the read with its error.
    let fx = Fixture::synced();
    fx.put_state(GENERATION - 1);
    let before = fx.on_disk();
    let lock = lock_path(&fx);
    set_mode(&lock, 0o444);

    let result = fx.read();

    set_mode(&lock, 0o644);
    assert!(matches!(result, Err(Error::VaultLockError(_))));
    assert_eq!(fx.on_disk(), before);
}

#[test]
fn app_read_through_unlock_vault_takes_no_per_vault_mutex_while_it_holds_manager_mutex() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    put_peer(&fx, &transport, PEER, "joined");
    let manager = Mutex::new(VaultsManager::with(fx.catalog.clone()));
    let locks = fx.catalog.files().locks();
    locks.set_watched(fx.id(), true);
    locks.set_pending(fx.id());

    // Hold the vault locks, so the read transaction waits for them.
    let held = fx.catalog.files().hold_for_test(fx.id(), &fx.vault.path);
    std::thread::scope(|s| {
        let reader = s.spawn(|| VaultsManager::unlock_vault(&manager, "personal").unwrap());
        std::thread::sleep(Duration::from_millis(100));
        // The manager is free while the read waits.
        assert!(manager.try_lock().is_ok());
        drop(held);
        reader.join().unwrap();
    });

    let m = VaultsManager::lock(&manager);
    let vh = m.get_vault("personal").unwrap();
    assert!(has_item(vh, "joined"));
    assert!(!locks.is_pending(fx.id()));
}
