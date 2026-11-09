use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use jiff::Zoned;
use jiff::civil::date;
use tempfile::TempDir;

use super::*;
use crate::audit::test_support::test_dir;
use crate::audit::{AuditFilter, read};
use crate::core::auth::AuthContext;
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::storage::catalog::VaultCatalog;
use crate::secrets::vaults::storage::device_keys::{
    KeyProbe, KeyState, OnNewHardware, ensure_device_keys,
};
use crate::secrets::vaults::storage::handle::VaultHandle;
use crate::secrets::vaults::storage::manager::VaultsManager;
use crate::secrets::vaults::storage::test_keys::TestKeys;
use crate::secrets::vaults::storage::test_unlocker::KeyUnlocker;
use crate::secrets::vaults::storage::txn::VaultWriter;
use crate::secrets::vaults::sync::model::KeyId;

/// App data directory of a Mac restored from another Mac, in a temp
/// directory. External vaults are in `external/`, outside the data
/// directory.
struct Mac {
    dir: TempDir,
    root: PathBuf,
    external: Vec<PathBuf>,
}

impl Mac {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("data");
        Self {
            dir,
            root,
            external: Vec::new(),
        }
    }

    /// Mac with the vault file `vaults/personal.json`, one retained version,
    /// one invalid file, a sync state, a staged file, and a sidecar.
    fn restored() -> (Self, Uuid) {
        let mac = Self::new();
        let id = mac.add_vault("personal");
        let short = ShortId::encode_uuid(id);
        mac.put(&format!("versions/{short}/1000-0.json"));
        mac.put(&format!("versions/{short}/2000-0.invalid.json"));
        mac.save_state(id, ReplicaId(Uuid::from_u128(5)));
        mac.put(&format!("sync/{short}.staged.apstate"));
        mac.put(&format!("sync/{short}.json"));
        (mac, id)
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn vaults(&self) -> PathBuf {
        self.root().join("vaults")
    }

    /// Write a vault file with key `key` to the vaults directory. Returns its
    /// vault id.
    fn add_vault(&self, key: &str) -> Uuid {
        let vh = VaultHandle::new_for_test_at(self.vaults().join(format!("{key}.json")));
        VaultWriter::isolated(self.root()).create(&vh).unwrap();
        vh.vault_id().unwrap()
    }

    /// Write a vault file with key `key` and name `name` to the vaults
    /// directory. Returns its vault id.
    fn add_named_vault(&self, key: &str, name: &str) -> Uuid {
        let mut vh = VaultHandle::new_for_test_at(self.vaults().join(format!("{key}.json")));
        vh.set_vault_name(name.to_string()).unwrap();
        VaultWriter::isolated(self.root()).create(&vh).unwrap();
        vh.vault_id().unwrap()
    }

    /// Write an external vault file with key `key`, listed in the config.
    fn add_external(&mut self, key: &str) -> PathBuf {
        let path = self.dir.path().join("external").join(format!("{key}.json"));
        let vh = VaultHandle::new_for_test_at(path.clone());
        VaultWriter::isolated(self.root()).create(&vh).unwrap();
        self.external.push(path.clone());
        path
    }

    /// Write a sync state of vault `id` and `replica`, signed by another key.
    fn save_state(&self, id: Uuid, replica: ReplicaId) {
        LocalSyncState::new(id, replica, KeyId(1))
            .save(self.root(), &TestSigner::random())
            .unwrap();
    }

    /// Write a file at `relative` under the app data directory.
    fn put(&self, relative: &str) {
        let path = self.root().join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, relative.as_bytes()).unwrap();
    }

    fn files(&self) -> VaultFiles {
        VaultFiles::new(self.vaults(), self.root(), self.external.clone())
    }

    fn catalog(&self, keys: &Arc<TestKeys>) -> VaultCatalog {
        VaultCatalog::with_unlocker(
            self.vaults(),
            VaultWriter::isolated(self.root()),
            self.external.clone(),
            Arc::new(KeyUnlocker::default()),
        )
        .with_keys(keys.clone())
    }

    /// Every file under `dir`, by path relative to `dir`, with its bytes.
    fn snapshot_of(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        fn walk(base: &Path, dir: &Path, found: &mut BTreeMap<PathBuf, Vec<u8>>) {
            let Ok(entries) = fs::read_dir(dir) else {
                return;
            };
            for entry in entries {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(base, &path, found);
                } else {
                    let relative = path.strip_prefix(base).unwrap().to_path_buf();
                    found.insert(relative, fs::read(&path).unwrap());
                }
            }
        }
        let mut found = BTreeMap::new();
        walk(dir, dir, &mut found);
        found
    }

    /// Every file under the app data directory.
    fn snapshot(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        Self::snapshot_of(self.root())
    }

    /// Files of `snapshot` under `vaults/`, `versions/`, and `sync/`.
    fn vault_files_of(snapshot: &BTreeMap<PathBuf, Vec<u8>>) -> BTreeMap<PathBuf, Vec<u8>> {
        snapshot
            .iter()
            .filter(|(path, _)| {
                ["vaults", "versions", "sync"]
                    .iter()
                    .any(|dir| path.starts_with(dir))
            })
            .map(|(path, bytes)| (path.clone(), bytes.clone()))
            .collect()
    }

    /// Directories under `unreadable/`, ordered by name.
    fn moved_dirs(&self) -> Vec<PathBuf> {
        let mut dirs: Vec<PathBuf> = fs::read_dir(self.root().join(UNREADABLE_DIR))
            .into_iter()
            .flatten()
            .map(|entry| entry.unwrap().path())
            .collect();
        dirs.sort();
        dirs
    }
}

fn keys(encryption: KeyProbe, signing: KeyProbe) -> Arc<TestKeys> {
    Arc::new(TestKeys::new(encryption, signing))
}

fn moved_events() -> Vec<AuditEvent> {
    read(&AuditFilter {
        actions: vec![Action::VaultUnreadableMoved],
        ..Default::default()
    })
    .events
}

#[test]
fn launch_with_vault_files_and_both_keys_missing_creates_no_key_or_resign_and_moves_nothing() {
    let _audit = test_dir();
    let (mac, _) = Mac::restored();
    let keys = keys(KeyProbe::Missing, KeyProbe::Missing);
    let before = mac.snapshot();

    let manager = VaultsManager::with(mac.catalog(&keys));
    let resigned = mac.catalog(&keys).resign();

    assert_eq!(manager.key_state(), &KeyState::NewHardware);
    assert!(
        matches!(resigned, Err(Error::ResignNotOffered)),
        "{resigned:?}"
    );
    assert_eq!(keys.created(), 0);
    assert_eq!(mac.snapshot(), before);
    assert!(moved_events().is_empty());
}

#[test]
fn encryption_key_missing_with_signing_key() {
    let _audit = test_dir();
    for signing in [KeyProbe::Missing, KeyProbe::Present] {
        let (mac, _) = Mac::restored();
        let keys = keys(KeyProbe::Missing, signing.clone());
        let before = mac.snapshot();

        let manager = VaultsManager::with(mac.catalog(&keys));
        let resigned = mac.catalog(&keys).resign();
        let imported = ensure_device_keys(
            &*keys,
            &mac.files(),
            AuthContext::OneTime,
            OnNewHardware::Fail,
        );

        assert_eq!(manager.key_state(), &KeyState::NewHardware, "{signing:?}");
        assert!(matches!(resigned, Err(Error::ResignNotOffered)));
        assert!(matches!(imported, Err(Error::NewHardware)));
        assert_eq!(keys.created(), 0);
        assert_eq!(mac.snapshot(), before);

        mac.catalog(&keys).create(None, "work").unwrap();

        let expected = if signing == KeyProbe::Missing { 2 } else { 1 };
        assert_eq!(keys.created(), expected, "{signing:?}");
        let moved = Mac::snapshot_of(&mac.moved_dirs()[0]);
        assert_eq!(moved, Mac::vault_files_of(&before), "{signing:?}");
    }
}

#[test]
fn creating_vault_on_new_hardware_moves_every_file_first_and_keeps_them_after_invalid_files() {
    let _audit = test_dir();
    let (mac, id) = Mac::restored();
    let keys = keys(KeyProbe::Missing, KeyProbe::Missing);
    let catalog = mac.catalog(&keys);
    let before = mac.snapshot();
    let today = || Zoned::now().date().strftime("%Y-%m-%d").to_string();
    let day_before = today();

    let vh = catalog.create(None, "work").unwrap();

    assert_eq!(keys.created(), 2);
    assert_eq!(catalog.key_state(), KeyState::Normal);
    let dirs = mac.moved_dirs();
    assert_eq!(dirs.len(), 1);
    let name = dirs[0].file_name().unwrap().to_str().unwrap().to_string();
    assert!([day_before, today()].contains(&name), "{name}");
    let expected = Mac::vault_files_of(&before);
    assert_eq!(Mac::snapshot_of(&dirs[0]), expected);
    let after = mac.snapshot();
    assert_eq!(
        Mac::vault_files_of(&after).keys().collect::<Vec<_>>(),
        vec![&PathBuf::from("vaults").join(vh.path.file_name().unwrap())],
        "only the new vault is in the vaults directory"
    );

    // Invalid files of the moved vault id prune only `versions/`.
    let writer = catalog.files();
    for n in 0..25u8 {
        writer.add_invalid_for_test(id, &[n]);
    }

    assert_eq!(writer.list_invalid(id).len(), 20);
    assert_eq!(Mac::snapshot_of(&dirs[0]), expected);
    assert_eq!(catalog.list().keys().collect::<Vec<_>>(), vec!["work"]);
    assert!(LocalSyncState::list(mac.root()).is_empty());
    assert!(catalog.scan().missing.is_empty());
}

#[test]
fn sync_states_staged_files_and_sidecars_move_with_vault_files() {
    let _audit = test_dir();
    let (mac, id) = Mac::restored();
    let short = ShortId::encode_uuid(id);

    let moved = Unreadable::move_all(&mac.files(), date(2026, 11, 4)).unwrap();

    let dir = moved.dir.unwrap();
    assert_eq!(dir, mac.root().join("unreadable").join("2026-11-04"));
    assert_eq!(moved.count, 6);
    for relative in [
        "vaults/personal.json".to_string(),
        format!("versions/{short}/1000-0.json"),
        format!("versions/{short}/2000-0.invalid.json"),
        format!("sync/{short}.state.json"),
        format!("sync/{short}.staged.apstate"),
        format!("sync/{short}.json"),
    ] {
        assert!(dir.join(&relative).is_file(), "{relative}");
        assert!(!mac.root().join(&relative).exists(), "{relative}");
    }
}

#[test]
fn locks_and_config_do_not_move() {
    let _audit = test_dir();
    let (mac, _) = Mac::restored();
    mac.put("locks/abc.lock");
    mac.put("config.toml");

    Unreadable::move_all(&mac.files(), date(2026, 11, 4)).unwrap();

    assert!(mac.root().join("locks/abc.lock").is_file());
    assert!(mac.root().join("config.toml").is_file());
}

#[test]
fn external_vault_file_not_moved_or_changed() {
    let _audit = test_dir();
    let (mut mac, _) = Mac::restored();
    let external = mac.add_external("shared");
    let bytes = fs::read(&external).unwrap();
    let keys = keys(KeyProbe::Missing, KeyProbe::Missing);

    mac.catalog(&keys).create(None, "work").unwrap();

    assert_eq!(fs::read(&external).unwrap(), bytes);
    let moved = Mac::snapshot_of(&mac.moved_dirs()[0]);
    assert!(moved.values().all(|moved| *moved != bytes));
    assert_eq!(keys.created(), 2);
}

#[test]
fn new_hardware_with_only_external_vault_moves_nothing_and_creates_keys() {
    let _audit = test_dir();
    let mut mac = Mac::new();
    let external = mac.add_external("shared");
    let bytes = fs::read(&external).unwrap();
    let keys = keys(KeyProbe::Missing, KeyProbe::Missing);
    assert_eq!(mac.catalog(&keys).key_state(), KeyState::NewHardware);

    mac.catalog(&keys).create(None, "work").unwrap();

    assert_eq!(fs::read(&external).unwrap(), bytes);
    assert!(mac.moved_dirs().is_empty());
    assert_eq!(keys.created(), 2);
    let events = moved_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].detail["file_count"], "0");
}

#[test]
fn move_only_renames_files_and_moved_files_are_never_listed() {
    let _audit = test_dir();
    let (mac, id) = Mac::restored();
    let catalog = mac.catalog(&Arc::new(TestKeys::both()));
    let before: BTreeMap<PathBuf, u64> = Mac::vault_files_of(&mac.snapshot())
        .into_keys()
        .map(|relative| {
            let inode = fs::metadata(mac.root().join(&relative)).unwrap().ino();
            (relative, inode)
        })
        .collect();

    let moved = Unreadable::move_all(&mac.files(), date(2026, 11, 4)).unwrap();

    let dir = moved.dir.unwrap();
    for (relative, inode) in &before {
        let moved = fs::metadata(dir.join(relative)).unwrap();
        assert_eq!(moved.ino(), *inode, "{relative:?} was renamed, not copied");
    }
    assert!(catalog.list().is_empty());
    assert!(catalog.scan().missing.is_empty());
    assert!(LocalSyncState::list(mac.root()).is_empty());
    assert!(catalog.files().list_versions(id).unwrap().is_empty());
    assert!(Unreadable::synced_vaults(mac.root()).is_empty());
}

#[test]
fn second_move_on_same_date_uses_new_directory_and_replaces_no_file() {
    let _audit = test_dir();
    let (mac, _) = Mac::restored();
    let day = date(2026, 11, 4);
    let first = Unreadable::move_all(&mac.files(), day)
        .unwrap()
        .dir
        .unwrap();
    let first_files = Mac::snapshot_of(&first);
    fs::create_dir_all(mac.root().join("unreadable/2026-11-04-1")).unwrap();
    mac.add_vault("personal");

    let second = Unreadable::move_all(&mac.files(), day)
        .unwrap()
        .dir
        .unwrap();

    assert_eq!(first, mac.root().join("unreadable/2026-11-04"));
    assert_eq!(second, mac.root().join("unreadable/2026-11-04-2"));
    assert_eq!(Mac::snapshot_of(&first), first_files);
    assert_eq!(Mac::snapshot_of(&second).len(), 1);
    assert!(second.join("vaults/personal.json").is_file());
}

#[test]
fn failed_rename_stops_move_and_creates_no_key() {
    let _audit = test_dir();
    let (mac, id) = Mac::restored();
    let versions = mac.root().join("versions").join(ShortId::encode_uuid(id));
    fs::set_permissions(&versions, fs::Permissions::from_mode(0o555)).unwrap();
    let keys = keys(KeyProbe::Missing, KeyProbe::Missing);

    let result = mac.catalog(&keys).create(None, "work");

    fs::set_permissions(&versions, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        matches!(result, Err(Error::UnreadableMoveFailed(_))),
        "{:?}",
        result.err()
    );
    assert_eq!(keys.created(), 0);
    let dir = &mac.moved_dirs()[0];
    assert!(
        dir.join("vaults/personal.json").is_file(),
        "moved files stay"
    );
    assert!(versions.join("1000-0.json").is_file());
    assert!(!mac.vaults().join("work.json").exists());
    let events = moved_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, Outcome::Failed);
    assert_eq!(events[0].detail["file_count"], "1");
}

#[test]
fn move_records_one_audit_event_with_number_of_files() {
    let _audit = test_dir();
    let (mac, _) = Mac::restored();

    Unreadable::move_all(&mac.files(), date(2026, 11, 4)).unwrap();

    let events = moved_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, Outcome::Succeeded);
    assert_eq!(events[0].detail["file_count"], "6");
}

#[test]
fn new_hardware_lists_synced_vaults() {
    let _audit = test_dir();
    let (mac, id) = Mac::restored();
    let other = Uuid::new_v4();
    mac.save_state(other, ReplicaId(Uuid::from_u128(6)));
    mac.put("sync/not-a-state.state.json");
    let keys = keys(KeyProbe::Missing, KeyProbe::Missing);
    let mut expected = vec![
        SyncedVault {
            vault_id: id,
            replica_id: ReplicaId(Uuid::from_u128(5)),
        },
        SyncedVault {
            vault_id: other,
            replica_id: ReplicaId(Uuid::from_u128(6)),
        },
    ];
    expected.sort_by_key(|vault| LocalSyncState::path(mac.root(), vault.vault_id));

    assert_eq!(mac.catalog(&keys).unverified_synced_vaults(), expected);
    let moved = Unreadable::move_all(&mac.files(), date(2026, 11, 4)).unwrap();

    assert_eq!(moved.synced, expected);
    assert!(mac.catalog(&keys).unverified_synced_vaults().is_empty());
}

#[test]
fn moved_vaults_lists_moved_vault_files_by_unverified_name_and_reads_no_file_outside_unreadable() {
    let _audit = test_dir();
    let mac = Mac::new();
    let personal = mac.add_named_vault("personal", "Personal");
    let first = Unreadable::move_all(&mac.files(), date(2026, 11, 4))
        .unwrap()
        .dir
        .unwrap();
    let work = mac.add_vault("work");
    let second = Unreadable::move_all(&mac.files(), date(2026, 11, 5))
        .unwrap()
        .dir
        .unwrap();
    // Files in a moved vaults directory that are not vault files, and a
    // vault file whose header cannot be read.
    mac.put("unreadable/2026-11-05/vaults/notes.txt");
    mac.put("unreadable/2026-11-05/vaults/broken.json");
    // Vault files outside `unreadable/`.
    let current = mac.add_vault("current");
    mac.save_state(current, ReplicaId(Uuid::from_u128(5)));
    let short = ShortId::encode_uuid(current);
    mac.put(&format!("versions/{short}/1000-0.json"));
    let catalog = mac.catalog(&Arc::new(TestKeys::both()));
    let before = mac.snapshot();
    // No directory outside `unreadable/` can be read during the listing.
    let outside = ["vaults", "versions", "sync"].map(|name| mac.root().join(name));
    for dir in &outside {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o000)).unwrap();
    }

    let moved = catalog.moved_vaults();

    for dir in &outside {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).unwrap();
    }
    assert_eq!(
        moved,
        vec![
            MovedVault {
                vault_id: personal,
                key: "personal".to_string(),
                name: Some("Personal".to_string()),
                path: first.join("vaults/personal.json"),
                dir: first.clone(),
            },
            MovedVault {
                vault_id: work,
                key: "work".to_string(),
                name: None,
                path: second.join("vaults/work.json"),
                dir: second.clone(),
            },
        ]
    );
    assert_eq!(mac.snapshot(), before);
    assert_eq!(catalog.list().keys().collect::<Vec<_>>(), vec!["current"]);
}
