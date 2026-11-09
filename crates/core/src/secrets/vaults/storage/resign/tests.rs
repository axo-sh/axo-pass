use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tempfile::TempDir;

use super::*;
use crate::audit::test_support::test_dir;
use crate::audit::{AuditFilter, read};
use crate::secrets::vaults::format::encrypted_vault::EncryptedVault;
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::model::Vault;
use crate::secrets::vaults::storage::manager::VaultsManager;
use crate::secrets::vaults::storage::test_keys::{TestKeys, keys};
use crate::secrets::vaults::storage::test_unlocker::KeyUnlocker;
use crate::secrets::vaults::storage::txn::{Target, Unlock, VaultWriter};
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::load::SignatureFailure;
use crate::secrets::vaults::sync::local_state::LocalSyncState;
use crate::secrets::vaults::sync::model::KeyId;
use crate::secrets::vaults::sync::status::{StopCause, SyncStatus};

/// Seed of the lost `device-signing-key`.
const OLD_KEY: u8 = 1;

/// Seed of the `device-signing-key` that the re-sign creates.
const NEW_KEY: u8 = 2;

/// Mac whose vault files were signed by the lost key [`OLD_KEY`]. External
/// vaults are in `external/`, outside the data directory.
struct Mac {
    _dir: TempDir,
    root: PathBuf,
    vaults: PathBuf,
    external: Vec<PathBuf>,
    /// Vaults as created, unlocked, by key.
    created: BTreeMap<String, VaultHandle>,
}

impl Mac {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("data");
        let vaults = root.join("vaults");
        Self {
            _dir: dir,
            root,
            vaults,
            external: Vec::new(),
            created: BTreeMap::new(),
        }
    }

    /// Writer under the data directory that signs with the key of `seed`.
    fn writer(&self, seed: u8) -> VaultWriter {
        VaultWriter::isolated_with_signer(&self.root, TestSigner::seeded(seed))
    }

    /// Create vault `key` at `path`, signed by the old key, and save it once
    /// more with one item, so one version is retained.
    fn add_at(&mut self, path: PathBuf, vault: Vault) -> &VaultHandle {
        let vh = VaultHandle::unlocked(path, vault);
        let writer = self.writer(OLD_KEY);
        writer.create(&vh).unwrap();
        let key = || vh.unlocked_key().unwrap();
        writer
            .write(&Target::of(&vh), Unlock::Test(&key), |vh| {
                vh.add_item("item", "Item").map(|_| ())
            })
            .unwrap();
        self.created.entry(vh.key.clone()).or_insert(vh)
    }

    /// Internal vault `key` with one retained version.
    fn add(&mut self, key: &str) -> &VaultHandle {
        let mut vault = Vault::new_for_test();
        vault.set_key(key.to_string());
        let path = VaultHandle::file_path(&self.vaults, vault.id());
        self.add_at(path, vault)
    }

    /// External vault `key` with one retained version.
    fn add_external(&mut self, key: &str) -> &VaultHandle {
        let mut vault = Vault::new_for_test();
        vault.set_key(key.to_string());
        let path = self
            ._dir
            .path()
            .join("external")
            .join(format!("{key}.json"));
        self.external.push(path.clone());
        self.add_at(path, vault)
    }

    fn vault(&self, key: &str) -> &VaultHandle {
        &self.created[key]
    }

    fn id(&self, key: &str) -> Uuid {
        self.vault(key).vault_id().unwrap()
    }

    fn versions_dir(&self, id: Uuid) -> PathBuf {
        self.root.join("versions").join(ShortId::encode_uuid(id))
    }

    /// Paths of the retained versions of vault `id`, ordered by name.
    fn versions(&self, id: Uuid) -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = fs::read_dir(self.versions_dir(id))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| !path.to_string_lossy().ends_with(".invalid.json"))
            .collect();
        paths.sort();
        paths
    }

    /// Catalog over `keys` whose writer signs with the key of `seed`.
    fn catalog(&self, keys: &Arc<TestKeys>, seed: u8) -> VaultCatalog {
        let unlocker = self
            .created
            .values()
            .map(|vh| (vh.vault_id().unwrap(), vh.unlocked_key().unwrap()))
            .collect();
        VaultCatalog::with_unlocker(
            self.vaults.clone(),
            self.writer(seed),
            self.external.clone(),
            Arc::new(KeyUnlocker(unlocker)),
        )
        .with_keys(keys.clone())
    }

    /// Every file under the data directory and the external directory.
    fn snapshot(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        fn walk(dir: &Path, found: &mut BTreeMap<PathBuf, Vec<u8>>) {
            let Ok(entries) = fs::read_dir(dir) else {
                return;
            };
            for entry in entries {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, found);
                } else {
                    let bytes = fs::read(&path).unwrap();
                    found.insert(path, bytes);
                }
            }
        }
        let mut found = BTreeMap::new();
        walk(self._dir.path(), &mut found);
        found
    }
}

/// Keys of a Mac whose `device-signing-key` is lost.
fn signing_key_lost() -> Arc<TestKeys> {
    keys(KeyProbe::Present, KeyProbe::Missing)
}

fn raw(path: &Path) -> String {
    let contents = fs::read_to_string(path).unwrap();
    EncryptedVault::raw_vault_json(&contents)
        .unwrap()
        .to_string()
}

fn verifies(path: &Path, seed: u8) -> bool {
    EncryptedVault::load(path, &TestSigner::seeded(seed)).is_ok()
}

fn resigned_events() -> Vec<AuditEvent> {
    read(&AuditFilter {
        actions: vec![Action::VaultResigned],
        ..Default::default()
    })
    .events
}

#[test]
fn launch_with_signing_key_lost_creates_no_key_and_shows_signing_key_lost() {
    let mut mac = Mac::new();
    mac.add("personal");
    let keys = signing_key_lost();
    let before = mac.snapshot();

    let manager = VaultsManager::with(mac.catalog(&keys, OLD_KEY));

    assert_eq!(manager.key_state(), &KeyState::SigningKeyLost);
    assert_eq!(keys.created(), 0);
    assert_eq!(mac.snapshot(), before);
}

#[test]
fn confirmed_resign_verifies_every_vault_and_retained_version_under_new_key() {
    let _audit = test_dir();
    let mut mac = Mac::new();
    mac.add("personal");
    mac.add("work");
    mac.add_external("shared");
    let keys = signing_key_lost();
    let catalog = mac.catalog(&keys, NEW_KEY);
    let mut files: Vec<PathBuf> = mac.created.values().map(|vh| vh.path.clone()).collect();
    for key in ["personal", "work", "shared"] {
        files.extend(mac.versions(mac.id(key)));
    }
    assert_eq!(files.len(), 6);
    for file in &files {
        assert!(verifies(file, OLD_KEY));
        assert!(!verifies(file, NEW_KEY), "{file:?}");
    }

    let resigned = catalog.resign().unwrap();

    assert_eq!(resigned.signed, 6);
    assert!(resigned.skipped.is_empty(), "{:?}", resigned.skipped);
    assert_eq!(keys.created(), 1);
    assert_eq!(catalog.key_state(), KeyState::Normal);
    for file in &files {
        assert!(verifies(file, NEW_KEY), "{file:?}");
    }
    assert_eq!(catalog.list().len(), 3);
}

#[test]
fn pre_loss_version_restores_after_resign() {
    let _audit = test_dir();
    let mut mac = Mac::new();
    mac.add("personal");
    let catalog = mac.catalog(&signing_key_lost(), NEW_KEY);
    catalog.resign().unwrap();
    let vh = mac.vault("personal");
    let name = catalog.list_versions("personal").unwrap()[0].name.clone();

    let key = || vh.unlocked_key().unwrap();
    let restored = catalog
        .files()
        .restore_version(&Target::of(vh), Unlock::Test(&key), &name)
        .unwrap();

    assert!(restored.changed);
    assert!(restored.vault.list_items().unwrap().is_empty());
    assert!(verifies(&vh.path, NEW_KEY));
}

#[test]
fn resign_leaves_raw_vault_bytes_unchanged() {
    let _audit = test_dir();
    let mut mac = Mac::new();
    mac.add("personal");
    mac.add_external("shared");
    let id = mac.id("personal");
    let mut files = vec![
        mac.vault("personal").path.clone(),
        mac.vault("shared").path.clone(),
    ];
    files.extend(mac.versions(id));
    let before: Vec<(String, String)> = files
        .iter()
        .map(|file| (fs::read_to_string(file).unwrap(), raw(file)))
        .collect();

    mac.catalog(&signing_key_lost(), NEW_KEY).resign().unwrap();

    for (file, (contents, raw_before)) in files.iter().zip(before) {
        assert_eq!(raw(file), raw_before, "{file:?}");
        assert_ne!(fs::read_to_string(file).unwrap(), contents, "{file:?}");
    }
}

#[test]
fn external_vault_signed_again() {
    let _audit = test_dir();
    let mut mac = Mac::new();
    mac.add_external("shared");
    let path = mac.vault("shared").path.clone();

    mac.catalog(&signing_key_lost(), NEW_KEY).resign().unwrap();

    assert!(verifies(&path, NEW_KEY));
}

#[test]
fn invalid_files_not_signed_again() {
    let _audit = test_dir();
    let mut mac = Mac::new();
    mac.add("personal");
    let id = mac.id("personal");
    let catalog = mac.catalog(&signing_key_lost(), NEW_KEY);
    let refused = fs::read(&mac.vault("personal").path).unwrap();
    catalog.files().add_invalid_for_test(id, &refused);
    let names = catalog.files().list_invalid(id);
    assert_eq!(names.len(), 1);
    let invalid = mac.versions_dir(id).join(&names[0]);

    let resigned = catalog.resign().unwrap();

    assert_eq!(resigned.signed, 2);
    assert_eq!(fs::read(&invalid).unwrap(), refused);
    assert!(!verifies(&invalid, NEW_KEY));
}

#[test]
fn file_that_does_not_hold_its_vault_skipped_and_others_signed() {
    let _audit = test_dir();
    let mut mac = Mac::new();
    mac.add("personal");
    mac.add("work");
    let id = mac.id("personal");
    let version = mac.versions(id)[0].clone();
    let other = fs::read(&mac.versions(mac.id("work"))[0]).unwrap();
    fs::write(&version, &other).unwrap();

    let resigned = mac.catalog(&signing_key_lost(), NEW_KEY).resign().unwrap();

    assert_eq!(resigned.signed, 3);
    assert_eq!(resigned.skipped, vec![version.clone()]);
    assert_eq!(fs::read(&version).unwrap(), other);
}

#[test]
fn retained_versions_of_vault_with_no_file_signed_again() {
    let _audit = test_dir();
    let mut mac = Mac::new();
    mac.add("personal");
    let id = mac.id("personal");
    fs::remove_file(&mac.vault("personal").path).unwrap();

    let resigned = mac.catalog(&signing_key_lost(), NEW_KEY).resign().unwrap();

    assert_eq!(resigned.signed, 1);
    assert!(verifies(&mac.versions(id)[0], NEW_KEY));
}

#[test]
fn confirmation_outside_signing_key_lost_fails_and_changes_nothing() {
    type Refused = fn(&Error) -> bool;
    let rows: [(&str, KeyProbe, KeyProbe, Refused); 4] = [
        (
            "both keys present",
            KeyProbe::Present,
            KeyProbe::Present,
            |e| matches!(e, Error::ResignNotOffered),
        ),
        ("neither key", KeyProbe::Missing, KeyProbe::Missing, |e| {
            matches!(e, Error::ResignNotOffered)
        }),
        (
            "signing key present, encryption key missing",
            KeyProbe::Missing,
            KeyProbe::Present,
            |e| matches!(e, Error::ResignNotOffered),
        ),
        (
            "keychain error",
            KeyProbe::Error("keychain failed".into()),
            KeyProbe::Missing,
            |e| matches!(e, Error::KeyRetrievalFailed(_)),
        ),
    ];
    let _audit = test_dir();
    let mut mac = Mac::new();
    mac.add("personal");
    let before = mac.snapshot();
    assert!(!verifies(&mac.vault("personal").path, NEW_KEY));
    for (label, encryption, signing, refused) in rows {
        let keys = keys(encryption, signing);

        let result = mac.catalog(&keys, NEW_KEY).resign();

        assert!(
            matches!(&result, Err(e) if refused(e)),
            "{label}: {result:?}"
        );
        assert_eq!(keys.created(), 0, "{label}");
        assert_eq!(mac.snapshot(), before, "{label}");
        assert!(resigned_events().is_empty(), "{label}");
    }
}

#[test]
fn resign_records_one_audit_event_with_number_of_files() {
    let _audit = test_dir();
    let mut mac = Mac::new();
    mac.add("personal");
    mac.add("work");

    mac.catalog(&signing_key_lost(), NEW_KEY).resign().unwrap();

    let events = resigned_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, Outcome::Succeeded);
    assert_eq!(events[0].detail["file_count"], "4");
    assert_eq!(events[0].detail["skipped_count"], "0");
}

#[test]
fn synced_vault_verifies_after_resign_and_its_sync_stops_with_failed_signature() {
    let _audit = test_dir();
    let mut mac = Mac::new();
    let replica = ReplicaId(Uuid::from_u128(5));
    let mut vault = Vault::new_for_test();
    vault.set_sync(7, Some(replica.0));
    let path = VaultHandle::file_path(&mac.vaults, vault.id());
    mac.add_at(path, vault);
    let id = mac.id("personal");
    LocalSyncState::new(id, replica, KeyId(1))
        .save(&mac.root, &TestSigner::seeded(OLD_KEY))
        .unwrap();
    let state_path = LocalSyncState::path(&mac.root, id);
    let state = fs::read(&state_path).unwrap();
    let catalog = mac.catalog(&signing_key_lost(), NEW_KEY);

    catalog.resign().unwrap();

    let vh = mac.vault("personal");
    assert!(verifies(&vh.path, NEW_KEY));
    assert_eq!(
        fs::read(&state_path).unwrap(),
        state,
        "sync state not signed again"
    );
    let key = || vh.unlocked_key().unwrap();
    let committed = catalog
        .files()
        .write(&Target::of(vh), Unlock::Test(&key), |vh| {
            vh.add_item("second", "Second").map(|_| ())
        })
        .unwrap();
    assert_eq!(
        committed.sync_status,
        Some(SyncStatus::Stopped(StopCause::SignatureFailed(
            SignatureFailure::Signature
        )))
    );
    assert!(verifies(&vh.path, NEW_KEY));
}
