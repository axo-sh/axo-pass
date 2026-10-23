use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use tempfile::TempDir;

use super::*;
use crate::secrets::vaults::fields::FieldKind;

/// A vault written to a temp directory, with its lock files in the same
/// directory.
struct Fixture {
    dir: TempDir,
    files: VaultWriter,
    /// The vault as created, still unlocked. Its file key opens the file.
    vault: VaultHandle,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let files = VaultWriter::isolated(dir.path().join("data"));
        let vault = VaultHandle::new_for_test_at(dir.path().join("vaults").join("personal.json"));
        files.create(&vault).unwrap();
        Self { dir, files, vault }
    }

    fn id(&self) -> Uuid {
        self.vault.vault_id().unwrap()
    }

    fn target(&self) -> Target {
        Target::of(&self.vault)
    }

    fn unlock(&self) -> Unlock<'_> {
        Unlock::Unlocked(&self.vault)
    }

    /// Add a credential `item/cred` with `value` in its own transaction.
    fn add(&self, target: &Target, cred: &str, value: &str) -> Committed<()> {
        self.files
            .write::<_, Error>(target, self.unlock(), |vw| add_credential(vw, cred, value))
            .unwrap()
    }

    /// The vault as it is on disk now, at `path`.
    fn read(&self, path: &Path) -> VaultHandle {
        let contents = fs::read_to_string(path).unwrap();
        let enc_vault = EncryptedVault::parse(&contents).unwrap();
        let vault =
            Vault::from_unlocked_key(&self.vault.unlocked_key().unwrap(), enc_vault).unwrap();
        VaultHandle::unlocked("personal".to_string(), path.to_path_buf(), vault)
    }

    fn value(&self, path: &Path, cred: &str) -> Option<String> {
        self.read(path)
            .get_secret("item", cred)
            .unwrap()
            .map(|s| s.expose_secret().clone())
    }
}

/// Add a credential `item/cred` with `value`, creating `item` if needed.
fn add_credential(vw: &mut VaultHandle, cred: &str, value: &str) -> Result<(), Error> {
    vw.add_item("item", "Item")?;
    vw.add_secret(
        "item",
        cred,
        cred,
        FieldKind::default(),
        SecretString::from(value.to_string()),
    )
}

#[test]
fn creating_a_vault_writes_once() {
    let fx = Fixture::new();
    assert!(fx.vault.path.exists());
    let entry = fx.files.locks().entry(fx.id(), &fx.vault.path);
    assert_eq!(entry.save_count(), 1);
}

#[test]
fn creating_a_vault_over_an_existing_file_fails() {
    let fx = Fixture::new();
    let other = VaultHandle::new_for_test_at(fx.vault.path.clone());
    assert!(matches!(
        fx.files.create(&other),
        Err(Error::InvalidVaultKey(_))
    ));
    assert_eq!(VaultHeader::peek(&fx.vault.path).unwrap().id, fx.id());
}

#[test]
fn a_write_saves_the_change() {
    let fx = Fixture::new();

    let committed = fx.add(&fx.target(), "alpha", "one");

    assert!(committed.changed);
    assert_eq!(fx.value(&fx.vault.path, "alpha").as_deref(), Some("one"));
}

#[test]
fn a_write_that_changes_nothing_saves_nothing() {
    let fx = Fixture::new();
    let committed = fx
        .files
        .write::<_, Error>(&fx.target(), fx.unlock(), |vw| vw.list_items().map(|_| ()))
        .unwrap();
    assert!(!committed.changed);
}

#[test]
fn a_failed_change_writes_nothing() {
    let fx = Fixture::new();
    let before = fs::read_to_string(&fx.vault.path).unwrap();
    let result = fx
        .files
        .write::<(), Error>(&fx.target(), fx.unlock(), |vw| {
            vw.add_item("item", "Item")?;
            Err(Error::InvalidItemKey("refused".to_string()))
        });
    assert!(result.is_err());
    assert_eq!(fs::read_to_string(&fx.vault.path).unwrap(), before);
}

#[test]
fn concurrent_writers_both_land() {
    let fx = Fixture::new();
    let target = fx.target();
    thread::scope(|s| {
        for i in 0..8 {
            let fx = &fx;
            let target = &target;
            s.spawn(move || fx.add(target, &format!("cred-{i}"), &format!("value-{i}")));
        }
    });
    for i in 0..8 {
        assert_eq!(
            fx.value(&fx.vault.path, &format!("cred-{i}")),
            Some(format!("value-{i}"))
        );
    }
}

#[test]
fn a_writer_waits_for_the_cross_process_lock() {
    let fx = Fixture::new();
    // Another process holding the lock file. flock locks belong to the open
    // file, so a second open in this process conflicts with it.
    let held = fx.files.lock_file(fx.id()).unwrap();
    let landed = AtomicBool::new(false);
    thread::scope(|s| {
        s.spawn(|| {
            fx.add(&fx.target(), "alpha", "one");
            landed.store(true, Ordering::SeqCst);
        });
        thread::sleep(Duration::from_millis(200));
        assert!(!landed.load(Ordering::SeqCst));
        // Closing the file releases the lock, as a process exit does.
        drop(held);
    });
    assert!(landed.load(Ordering::SeqCst));
    assert_eq!(fx.value(&fx.vault.path, "alpha").as_deref(), Some("one"));
}

#[test]
fn a_closed_lock_file_releases_the_lock() {
    let fx = Fixture::new();
    let held = fx.files.lock_file(fx.id()).unwrap();
    drop(held);
    let again = File::open(fx.files.lock_path(fx.id())).unwrap();
    assert!(again.try_lock().is_ok());
}

#[test]
fn writers_through_different_path_spellings_share_one_entry() {
    let fx = Fixture::new();
    let link = fx.dir.path().join("link");
    std::os::unix::fs::symlink(fx.dir.path().join("vaults"), &link).unwrap();
    let spellings = [
        fx.vault.path.clone(),
        link.join("personal.json"),
        fx.dir.path().join("vaults/../vaults/personal.json"),
    ];

    let first = fx.files.locks().entry(fx.id(), &spellings[0]);
    for path in &spellings {
        assert!(Arc::ptr_eq(&first, &fx.files.locks().entry(fx.id(), path)));
    }
    thread::scope(|s| {
        for (i, path) in spellings.iter().enumerate() {
            let fx = &fx;
            s.spawn(move || fx.add(&Target::new("personal", path), &format!("cred-{i}"), "v"));
        }
    });
    for i in 0..spellings.len() {
        assert!(fx.value(&fx.vault.path, &format!("cred-{i}")).is_some());
    }
}

#[test]
fn a_rename_moves_the_file() {
    let fx = Fixture::new();
    let committed = fx
        .files
        .write::<_, Error>(&fx.target(), fx.unlock(), |vw| {
            vw.set_vault_name("Renamed".to_string())?;
            vw.set_vault_key("renamed".to_string())
        })
        .unwrap();

    let new_path = fx.dir.path().join("vaults/renamed.json");
    assert_eq!(committed.vault.path, new_path);
    assert_eq!(committed.previous_key, "personal");
    assert!(!fx.vault.path.exists());
    assert_eq!(fx.read(&new_path).vault_name(), Some("Renamed"));
}

#[test]
fn a_rename_onto_an_existing_vault_fails() {
    let fx = Fixture::new();
    let other = VaultHandle::new_for_test_at(fx.dir.path().join("vaults/work.json"));
    fx.files.create(&other).unwrap();

    let result = fx.files.write::<_, Error>(&fx.target(), fx.unlock(), |vw| {
        vw.set_vault_key("work".to_string())
    });
    assert!(matches!(result, Err(Error::InvalidVaultKey(_))));
    assert!(fx.vault.path.exists());
    assert_eq!(
        VaultHeader::peek(&other.path).unwrap().id,
        other.vault_id().unwrap()
    );
}

#[test]
fn a_writer_that_found_the_old_path_lands_after_a_rename() {
    let fx = Fixture::new();
    let old_target = fx.target();
    let entry = fx.files.locks().entry(fx.id(), &fx.vault.path);
    let barrier = Barrier::new(2);
    thread::scope(|s| {
        s.spawn(|| {
            // Hold the vault mutex so the writer below waits for it.
            let mut locked = fx.files.lock_entry(&entry, fx.id()).unwrap();
            barrier.wait();
            thread::sleep(Duration::from_millis(100));
            let new_path = fx.dir.path().join("vaults/renamed.json");
            fs::rename(&fx.vault.path, &new_path).unwrap();
            locked.state.set_path(new_path);
        });
        barrier.wait();
        fx.add(&old_target, "alpha", "one");
    });
    let new_path = fx.dir.path().join("vaults/renamed.json");
    assert_eq!(fx.value(&new_path, "alpha").as_deref(), Some("one"));
    assert!(!fx.vault.path.exists());
}

#[test]
fn a_rename_concurrent_with_a_write_keeps_both_changes() {
    let fx = Fixture::new();
    let target = fx.target();
    thread::scope(|s| {
        s.spawn(|| {
            fx.files
                .write::<_, Error>(&target, fx.unlock(), |vw| {
                    vw.set_vault_key("renamed".to_string())
                })
                .unwrap()
        });
        s.spawn(|| fx.add(&target, "alpha", "one"));
    });
    let new_path = fx.dir.path().join("vaults/renamed.json");
    assert_eq!(fx.value(&new_path, "alpha").as_deref(), Some("one"));
    assert!(!fx.vault.path.exists());
}

#[test]
fn a_changed_file_key_is_not_used_and_the_key_is_unwrapped_again() {
    let fx = Fixture::new();
    // A key whose wrapped form differs from the file's fails the check and
    // is never used to decrypt. The second attempt gets the current key.
    let calls = AtomicU64::new(0);
    let key = || {
        let call = calls.fetch_add(1, Ordering::SeqCst);
        let current = fx.vault.unlocked_key().unwrap();
        if call == 0 {
            UnlockedKey::for_test(
                crate::secrets::vaults::vault::encrypted_vault::VaultFileKey::Personal(vec![
                    1u8;
                    32
                ]),
                current.cipher_for_test(),
            )
        } else {
            current
        }
    };
    let committed = fx
        .files
        .write::<_, Error>(&fx.target(), Unlock::Test(&key), |vw| {
            add_credential(vw, "alpha", "one")
        })
        .unwrap();
    assert!(committed.changed);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn a_file_key_that_keeps_changing_fails() {
    let fx = Fixture::new();
    let key = || {
        UnlockedKey::for_test(
            crate::secrets::vaults::vault::encrypted_vault::VaultFileKey::Personal(vec![1u8; 32]),
            fx.vault.unlocked_key().unwrap().cipher_for_test(),
        )
    };
    let ran = AtomicBool::new(false);
    let result = fx
        .files
        .write::<_, Error>(&fx.target(), Unlock::Test(&key), |_| {
            ran.store(true, Ordering::SeqCst);
            Ok(())
        });
    assert!(matches!(result, Err(Error::VaultFileKeyChanged)));
    assert!(!ran.load(Ordering::SeqCst));
}

#[test]
fn a_deleted_vault_is_not_recreated_by_a_waiting_writer() {
    let fx = Fixture::new();
    let entry = fx.files.locks().entry(fx.id(), &fx.vault.path);
    let barrier = Barrier::new(2);
    let result = thread::scope(|s| {
        let writer = s.spawn(|| {
            barrier.wait();
            fx.files.write::<_, Error>(&fx.target(), fx.unlock(), |vw| {
                vw.add_item("item", "Item").map(|_| ())
            })
        });
        // Hold the mutex while the writer starts, then delete.
        let locked = fx.files.lock_entry(&entry, fx.id()).unwrap();
        barrier.wait();
        thread::sleep(Duration::from_millis(100));
        drop(locked);
        fx.files
            .delete(&fx.vault.path, |path| {
                fs::remove_file(path).map_err(Error::VaultDeleteError)
            })
            .unwrap();
        writer.join().unwrap()
    });
    // The writer either ran before the delete, or failed after it. Either
    // way no file is left.
    if let Err(e) = result {
        assert!(matches!(e, Error::VaultNotFound(_)), "{e}");
    }
    assert!(!fx.vault.path.exists());
    assert!(!fx.files.locks().contains(fx.id()));
}

#[test]
fn a_writer_waiting_on_a_deleted_entry_fails() {
    let fx = Fixture::new();
    let entry = fx.files.locks().entry(fx.id(), &fx.vault.path);
    let barrier = Barrier::new(2);
    let result = thread::scope(|s| {
        let mut locked = fx.files.lock_entry(&entry, fx.id()).unwrap();
        let writer = s.spawn(|| {
            barrier.wait();
            fx.files.write::<_, Error>(&fx.target(), fx.unlock(), |vw| {
                vw.add_item("item", "Item").map(|_| ())
            })
        });
        barrier.wait();
        thread::sleep(Duration::from_millis(100));
        // Delete as `delete` does, while the writer waits for the mutex.
        fs::remove_file(&fx.vault.path).unwrap();
        locked.state.mark_removed();
        drop(locked);
        writer.join().unwrap()
    });
    assert!(matches!(result, Err(Error::VaultNotFound(_))));
    assert!(!fx.vault.path.exists());
}

#[test]
fn two_files_with_one_vault_id_are_refused() {
    let fx = Fixture::new();
    let copy = fx.dir.path().join("vaults/copy.json");
    fs::copy(&fx.vault.path, &copy).unwrap();
    let result = fx
        .files
        .write::<_, Error>(&Target::new("copy", &copy), fx.unlock(), |vw| {
            vw.add_item("item", "Item").map(|_| ())
        });
    assert!(matches!(result, Err(Error::DuplicateVaultId(_))));
}

#[test]
fn a_read_during_saves_sees_a_whole_vault() {
    let fx = Fixture::new();
    let done = AtomicBool::new(false);
    thread::scope(|s| {
        s.spawn(|| {
            for i in 0..20 {
                fx.add(&fx.target(), &format!("cred-{i}"), "value");
            }
            done.store(true, Ordering::SeqCst);
        });
        while !done.load(Ordering::SeqCst) {
            let contents = fs::read_to_string(&fx.vault.path).unwrap();
            EncryptedVault::parse(&contents).unwrap();
        }
    });
}
