use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tempfile::TempDir;
use uuid::Uuid;

use super::*;
use crate::audit::test_support::test_dir;
use crate::secrets::vaults::bundle::{ImportAction, ImportSelection, ImportableBundle};
use crate::secrets::vaults::storage::catalog::VaultCatalog;
use crate::secrets::vaults::storage::handle::{VaultHandle, get_vault_encryption_key_with};
use crate::secrets::vaults::storage::manager::VaultsManager;
use crate::secrets::vaults::storage::test_keys::{TestKeys, keys};
use crate::secrets::vaults::storage::test_unlocker::KeyUnlocker;
use crate::secrets::vaults::storage::txn::VaultWriter;

/// App data directory of a Mac, in a temp directory.
struct Mac {
    dir: TempDir,
}

impl Mac {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    /// Mac with one vault file, `vaults/personal.json`.
    fn with_vault() -> Self {
        let mac = Self::new();
        let vh = VaultHandle::new_for_test_at(mac.root().join("vaults").join("personal.json"));
        VaultWriter::isolated(mac.root()).create(&vh).unwrap();
        mac
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    fn files(&self) -> VaultFiles {
        self.files_with(Vec::new())
    }

    fn files_with(&self, external: Vec<PathBuf>) -> VaultFiles {
        VaultFiles::new(self.root().join("vaults"), self.root(), external)
    }

    /// Write a file at `relative` under the app data directory.
    fn put(&self, relative: &str) {
        let path = self.root().join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"{}").unwrap();
    }

    /// Catalog of this Mac over `keys`. Its unlocker holds no file key.
    fn catalog(&self, keys: &Arc<TestKeys>) -> VaultCatalog {
        VaultCatalog::with_unlocker(
            self.root().join("vaults"),
            VaultWriter::isolated(self.root()),
            Vec::new(),
            Arc::new(KeyUnlocker::default()),
        )
        .with_keys(keys.clone())
    }

    /// Every file under the app data directory, with its bytes.
    fn snapshot(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        fn walk(dir: &Path, found: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in fs::read_dir(dir).unwrap() {
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
        walk(self.root(), &mut found);
        found
    }
}

fn failure() -> KeyProbe {
    KeyProbe::Error("keychain failed".to_string())
}

fn classify(keys: &TestKeys, files: &VaultFiles) -> KeyState {
    KeyState::probe(keys, files)
}

/// Import of one empty vault under key `imported`.
fn import_one(catalog: &VaultCatalog) -> Result<Vec<VaultHandle>, Error> {
    let id = Uuid::new_v4();
    let selection = BTreeMap::from([(id, ImportSelection::new("imported", ImportAction::Default))]);
    catalog.import(
        ImportableBundle::for_test(&[id]),
        &selection,
        AuthContext::OneTime,
    )
}

#[test]
fn each_state_classified_from_keys_and_files() {
    use KeyProbe::{Missing, Present};

    let empty = Mac::new();
    let full = Mac::with_vault();
    let rows = [
        (
            "no files, both keys",
            &empty,
            Present,
            Present,
            KeyState::NoVaultFiles,
        ),
        (
            "no files, no keys",
            &empty,
            Missing,
            Missing,
            KeyState::NoVaultFiles,
        ),
        (
            "no files, one key",
            &empty,
            Present,
            Missing,
            KeyState::NoVaultFiles,
        ),
        (
            "files, both keys",
            &full,
            Present,
            Present,
            KeyState::Normal,
        ),
        (
            "files, encryption key only",
            &full,
            Present,
            Missing,
            KeyState::SigningKeyLost,
        ),
        (
            "files, no keys",
            &full,
            Missing,
            Missing,
            KeyState::NewHardware,
        ),
        (
            "files, signing key only",
            &full,
            Missing,
            Present,
            KeyState::NewHardware,
        ),
        (
            "files, encryption key error",
            &full,
            failure(),
            Present,
            KeyState::KeychainError("keychain failed".into()),
        ),
        (
            "files, signing key error",
            &full,
            Present,
            failure(),
            KeyState::KeychainError("keychain failed".into()),
        ),
        (
            "no files, encryption key error",
            &empty,
            failure(),
            Missing,
            KeyState::KeychainError("keychain failed".into()),
        ),
    ];
    for (label, mac, encryption, signing, expected) in rows {
        let keys = TestKeys::new(encryption, signing);
        assert_eq!(classify(&keys, &mac.files()), expected, "{label}");
    }
}

#[test]
fn mac_with_only_one_kind_of_vault_file_has_vault_files() {
    // Label, file path, and whether the file is listed as an external vault.
    let rows = [
        ("retained version", "versions/abc/1000-1.json", false),
        ("sync state", "sync/abc.json", false),
        ("external vault", "external/work.json", true),
    ];
    for (label, path, external) in rows {
        let mac = Mac::new();
        mac.put(path);
        let files = if external {
            mac.files_with(vec![mac.root().join(path)])
        } else {
            mac.files()
        };

        let keys = TestKeys::both();
        assert_eq!(classify(&keys, &files), KeyState::Normal, "{label}");
        let keys = TestKeys::neither();
        assert_eq!(classify(&keys, &files), KeyState::NewHardware, "{label}");
    }
}

#[test]
fn listed_missing_external_vault_not_file() {
    let mac = Mac::new();
    let files = mac.files_with(vec![mac.root().join("external").join("work.json")]);
    let keys = TestKeys::neither();

    assert_eq!(classify(&keys, &files), KeyState::NoVaultFiles);
    ensure_device_keys(&keys, &files, AuthContext::OneTime, OnNewHardware::Fail).unwrap();

    assert_eq!(keys.created(), 2);
}

#[test]
fn empty_directories_and_other_files_not_vault_files() {
    let mac = Mac::new();
    fs::create_dir_all(mac.root().join("vaults")).unwrap();
    fs::create_dir_all(mac.root().join("versions").join("abc")).unwrap();
    fs::create_dir_all(mac.root().join("sync")).unwrap();
    mac.put("locks/abc.lock");
    mac.put("config.toml");

    let keys = TestKeys::neither();
    assert_eq!(classify(&keys, &mac.files()), KeyState::NoVaultFiles);
}

#[test]
fn key_gated_by_authentication_is_present() {
    let gated: Result<Option<()>, _> = Err(KeychainError::ItemNotAccessible);
    assert_eq!(KeyProbe::of(gated), KeyProbe::Present);
    assert_eq!(KeyProbe::of(Ok(Some(()))), KeyProbe::Present);
    assert_eq!(KeyProbe::of::<()>(Ok(None)), KeyProbe::Missing);
}

#[test]
fn keychain_error_other_than_item_not_found_is_probe_error() {
    for error in [
        KeychainError::UserCancelled,
        KeychainError::AuthenticationExpired,
        KeychainError::Generic(anyhow!("got error code: -25299")),
    ] {
        assert!(matches!(KeyProbe::of::<()>(Err(error)), KeyProbe::Error(_)));
    }
}

#[test]
fn unlock_with_vault_files_and_missing_encryption_key_creates_no_key() {
    // Unlock, `Unlock::App`, `Unlock::new_keys`, and the import wrapper read
    // the key through `get_vault_encryption_key_with`.
    let mac = Mac::with_vault();
    let before = mac.snapshot();
    for signing in [KeyProbe::Present, KeyProbe::Missing] {
        let keys = TestKeys::new(KeyProbe::Missing, signing);
        assert_eq!(classify(&keys, &mac.files()), KeyState::NewHardware);

        let result = get_vault_encryption_key_with(&keys, AuthContext::OneTime);

        assert!(
            matches!(result, Err(Error::VaultEncryptionKeyMissing)),
            "{:?}",
            result.err()
        );
        assert_eq!(keys.created(), 0);
        assert_eq!(
            classify(&keys, &mac.files()),
            KeyState::NewHardware,
            "the read did not change the keys"
        );
    }
    assert_eq!(mac.snapshot(), before);
}

#[test]
fn import_with_vault_files_and_missing_encryption_key_creates_no_key() {
    let _audit = test_dir();
    let mac = Mac::with_vault();
    let before = mac.snapshot();
    for (encryption, signing, expected) in [
        (KeyProbe::Missing, KeyProbe::Missing, KeyState::NewHardware),
        (KeyProbe::Missing, KeyProbe::Present, KeyState::NewHardware),
        (
            KeyProbe::Present,
            KeyProbe::Missing,
            KeyState::SigningKeyLost,
        ),
    ] {
        let keys = keys(encryption, signing);
        assert_eq!(mac.catalog(&keys).key_state(), expected);

        let result = import_one(&mac.catalog(&keys));

        match expected {
            KeyState::NewHardware => assert!(matches!(result, Err(Error::NewHardware))),
            _ => assert!(matches!(result, Err(Error::SigningKeyNotFound))),
        }
        assert_eq!(keys.created(), 0, "{expected:?}");
    }
    assert_eq!(mac.snapshot(), before);
}

#[test]
fn keychain_error_creates_no_key_and_moves_no_file() {
    let _audit = test_dir();
    for with_files in [false, true] {
        let mac = if with_files {
            Mac::with_vault()
        } else {
            Mac::new()
        };
        for (encryption, signing) in [
            (failure(), KeyProbe::Present),
            (failure(), KeyProbe::Missing),
            (KeyProbe::Present, failure()),
            (KeyProbe::Missing, failure()),
        ] {
            let keys = keys(encryption, signing);
            let catalog = mac.catalog(&keys);
            let before = mac.snapshot();

            let ensured = ensure_device_keys(
                &*keys,
                &mac.files(),
                AuthContext::OneTime,
                OnNewHardware::MoveFiles,
            );
            let created = catalog.create(None, "work");
            let imported = import_one(&catalog);

            assert!(
                matches!(ensured, Err(Error::KeyRetrievalFailed(_))),
                "{:?}",
                ensured.err()
            );
            assert!(
                matches!(created, Err(Error::KeyRetrievalFailed(_))),
                "{:?}",
                created.err()
            );
            assert!(
                matches!(imported, Err(Error::KeyRetrievalFailed(_))),
                "{:?}",
                imported.err()
            );
            assert_eq!(keys.created(), 0);
            assert_eq!(mac.snapshot(), before);
            assert_eq!(
                catalog.key_state(),
                KeyState::KeychainError("keychain failed".into())
            );
        }
    }
}

#[test]
fn first_vault_on_mac_with_no_vault_files_creates_both_keys() {
    let _audit = test_dir();
    let mac = Mac::new();
    let keys = Arc::new(TestKeys::neither());
    let catalog = mac.catalog(&keys);

    let vh = catalog.create(None, "personal").unwrap();

    assert_eq!(keys.created(), 2);
    assert_eq!(keys.probe_encryption_key(), KeyProbe::Present);
    assert_eq!(keys.probe_signing_key(), KeyProbe::Present);
    assert!(vh.path.is_file());
    assert_eq!(catalog.key_state(), KeyState::Normal);
}

#[test]
fn import_on_mac_with_no_vault_files_and_no_keys_creates_both_keys() {
    let _audit = test_dir();
    let mac = Mac::new();
    let keys = Arc::new(TestKeys::neither());
    let catalog = mac.catalog(&keys);

    let imported = import_one(&catalog).unwrap();

    assert_eq!(imported.len(), 1);
    assert_eq!(keys.created(), 2);
    assert_eq!(keys.probe_encryption_key(), KeyProbe::Present);
    assert_eq!(keys.probe_signing_key(), KeyProbe::Present);
    assert!(imported[0].path.is_file());
}

#[test]
fn only_missing_key_created_if_no_vault_files_exist() {
    let mac = Mac::new();
    let keys = TestKeys::new(KeyProbe::Present, KeyProbe::Missing);

    ensure_device_keys(
        &keys,
        &mac.files(),
        AuthContext::OneTime,
        OnNewHardware::Fail,
    )
    .unwrap();

    assert_eq!(keys.created(), 1);
    assert_eq!(keys.probe_signing_key(), KeyProbe::Present);
}

#[test]
fn vault_created_and_imported_with_vault_files_and_both_keys_creates_no_key() {
    let _audit = test_dir();
    let mac = Mac::with_vault();
    let keys = Arc::new(TestKeys::both());
    let catalog = mac.catalog(&keys);

    catalog.create(None, "work").unwrap();
    import_one(&catalog).unwrap();

    assert_eq!(keys.created(), 0);
}

#[test]
fn creating_vault_with_signing_key_lost_creates_no_key() {
    let mac = Mac::with_vault();
    let keys = keys(KeyProbe::Present, KeyProbe::Missing);
    let before = mac.snapshot();

    let result = mac.catalog(&keys).create(None, "work");

    assert!(
        matches!(result, Err(Error::SigningKeyNotFound)),
        "{:?}",
        result.err()
    );
    assert_eq!(keys.created(), 0);
    assert_eq!(mac.snapshot(), before);
}

#[test]
fn build_with_missing_keys_changes_nothing() {
    let rows: [(&str, TestKeys, KeyState, fn(&Error) -> bool); 2] = [
        (
            "neither key",
            TestKeys::neither(),
            KeyState::NewHardware,
            |e| matches!(e, Error::NewHardware),
        ),
        (
            "encryption key only",
            TestKeys::new(KeyProbe::Present, KeyProbe::Missing),
            KeyState::SigningKeyLost,
            |e| matches!(e, Error::SigningKeyNotFound),
        ),
    ];
    for (label, keys, state, refused) in rows {
        let mac = Mac::with_vault();
        mac.put("versions/abc/1000-1.json");
        mac.put("sync/abc.json");
        let before = mac.snapshot();

        assert_eq!(classify(&keys, &mac.files()), state, "{label}");
        let result = ensure_device_keys(
            &keys,
            &mac.files(),
            AuthContext::OneTime,
            OnNewHardware::Fail,
        );

        assert!(matches!(&result, Err(e) if refused(e)), "{label}");
        assert_eq!(keys.created(), 0, "{label}");
        assert_eq!(mac.snapshot(), before, "{label}");
    }
}

#[test]
fn manager_holds_key_state_of_its_launch_scan() {
    let mac = Mac::with_vault();
    let keys = Arc::new(TestKeys::neither());

    let manager = VaultsManager::with(mac.catalog(&keys));

    assert_eq!(manager.key_state(), &KeyState::NewHardware);
    assert_eq!(keys.created(), 0);
}
