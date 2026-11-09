use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use secrecy::{ExposeSecret, SecretString};
use serde_json::value::RawValue;
use tempfile::TempDir;

use super::versions::{DAY_MS, HOUR_MS, kept_versions};
use super::*;
use crate::secrets::vaults::format::encrypted_vault::{VAULT_FORMAT, VaultFileKey};
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::format::vault_cipher::VaultCipher;
use crate::secrets::vaults::model::fields::FieldKind;

/// A vault written to a temp directory, with its retained versions and lock
/// files in the same directory.
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
        let enc_vault = EncryptedVault::parse(&contents, self.files.signer().as_ref()).unwrap();
        let vault =
            Vault::from_unlocked_key(&self.vault.unlocked_key().unwrap(), enc_vault).unwrap();
        VaultHandle::unlocked(path.to_path_buf(), vault)
    }

    fn value(&self, path: &Path, cred: &str) -> Option<String> {
        self.read(path)
            .get_secret("item", cred)
            .unwrap()
            .map(|s| s.expose_secret().clone())
    }

    fn versions(&self) -> Vec<RetainedVersion> {
        self.files.list_versions(self.id()).unwrap()
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

fn version(ms: u64, seq: u64) -> RetainedVersion {
    RetainedVersion {
        name: format!("{ms}-{seq}.json"),
        saved_at_ms: ms,
        seq,
    }
}

/// Raw vault bytes of the vault file `contents`.
fn raw(contents: &str) -> String {
    EncryptedVault::raw_vault_json(contents)
        .unwrap()
        .to_string()
}

#[test]
fn saved_vault_signed_and_reloads_unchanged() {
    let fx = Fixture::new();
    fx.add(&fx.target(), "alpha", "one");

    let saved = fs::read_to_string(&fx.vault.path).unwrap();
    let file: serde_json::Value = serde_json::from_str(&saved).unwrap();
    assert!(file["signature"].is_string());
    let reloaded = fx.read(&fx.vault.path);
    assert_eq!(reloaded.vault_json().unwrap(), raw(&saved));
    assert_eq!(fx.value(&fx.vault.path, "alpha").as_deref(), Some("one"));
}

#[test]
fn unchanged_save_writes_nothing() {
    let fx = Fixture::new();
    let signer = fx.files.signer().as_ref();
    assert_ne!(
        fx.vault.file_contents(signer).unwrap(),
        fx.vault.file_contents(signer).unwrap()
    );
    let before = fs::read_to_string(&fx.vault.path).unwrap();

    let committed = fx
        .files
        .write::<_, Error>(&fx.target(), fx.unlock(), |vw| vw.list_items().map(|_| ()))
        .unwrap();

    assert!(!committed.changed);
    assert_eq!(fs::read_to_string(&fx.vault.path).unwrap(), before);
    assert!(fx.versions().is_empty());
}

#[test]
fn reload_verifies_before_file_key_compared() {
    let fx = Fixture::new();
    let before = fs::read_to_string(&fx.vault.path).unwrap();
    let file: serde_json::Value = serde_json::from_str(&before).unwrap();
    let file_key = file["vault"]["file_key"].to_string();
    let other_key = serde_json::to_string(&VaultFileKey::new(vec![1u8; 32])).unwrap();
    assert_eq!(before.matches(&file_key).count(), 1);
    // A planted file key under the old signature. Without the signature
    // check, the file key comparison would retry and fail with
    // `VaultFileKeyChanged`.
    let planted = before.replacen(&file_key, &other_key, 1);
    fs::write(&fx.vault.path, &planted).unwrap();

    let ran = AtomicBool::new(false);
    let result = fx.files.write::<_, Error>(&fx.target(), fx.unlock(), |_| {
        ran.store(true, Ordering::SeqCst);
        Ok(())
    });

    assert!(matches!(result, Err(Error::VaultSignatureInvalid)));
    assert!(!ran.load(Ordering::SeqCst));
    assert_eq!(fs::read_to_string(&fx.vault.path).unwrap(), planted);
    assert!(fx.versions().is_empty());
}

#[test]
fn unsigned_file_refused_and_not_modified() {
    let fx = Fixture::new();
    let before = fs::read_to_string(&fx.vault.path).unwrap();
    let mut fields: BTreeMap<String, Box<RawValue>> = serde_json::from_str(&before).unwrap();
    fields.remove("signature").unwrap();
    let unsigned = serde_json::to_string_pretty(&fields).unwrap();
    fs::write(&fx.vault.path, &unsigned).unwrap();

    let result = fx.files.write::<_, Error>(&fx.target(), fx.unlock(), |vw| {
        add_credential(vw, "alpha", "one")
    });

    assert!(matches!(result, Err(Error::VaultSignatureMissing)));
    assert_eq!(fs::read_to_string(&fx.vault.path).unwrap(), unsigned);
    assert!(fx.versions().is_empty());
}

#[test]
fn file_signed_by_another_key_refused_and_not_modified() {
    let fx = Fixture::new();
    let other_mac =
        VaultWriter::isolated_with_signer(fx.dir.path().join("other"), TestSigner::random());
    let vh = VaultHandle::new_for_test_at(fx.dir.path().join("vaults").join("other.json"));
    other_mac.create(&vh).unwrap();
    let before = fs::read_to_string(&vh.path).unwrap();

    let result = fx
        .files
        .write_unlocked::<_, Error>(&vh, |vw| add_credential(vw, "alpha", "one"));

    assert!(matches!(result, Err(Error::VaultSignatureInvalid)));
    assert_eq!(fs::read_to_string(&vh.path).unwrap(), before);
    let id = vh.vault_id().unwrap();
    assert!(fx.files.list_versions(id).unwrap().is_empty());
}

#[test]
fn retained_version_whose_signature_fails_not_restored() {
    let fx = Fixture::new();
    fx.add(&fx.target(), "alpha", "one");
    fx.add(&fx.target(), "alpha", "two");
    let versions = fx.versions();
    let name = &versions[0].name;
    let path = fx.files.versions(fx.id()).file(name);
    let version = fs::read_to_string(&path).unwrap();
    let forged = EncryptedVault::sign_vault_json(raw(&version), &TestSigner::random()).unwrap();
    fs::write(&path, forged).unwrap();
    let before = fs::read_to_string(&fx.vault.path).unwrap();

    let result = fx.files.restore_version(&fx.target(), fx.unlock(), name);

    assert!(matches!(result, Err(Error::VaultSignatureInvalid)));
    assert_eq!(fs::read_to_string(&fx.vault.path).unwrap(), before);
    assert_eq!(fx.value(&fx.vault.path, "alpha").as_deref(), Some("two"));
    assert_eq!(fx.versions().len(), 2);
}

#[test]
fn creating_vault_writes_once_and_retains_nothing() {
    let fx = Fixture::new();
    assert!(fx.vault.path.exists());
    assert!(fx.versions().is_empty());
    let entry = fx.files.locks().entry(fx.id(), &fx.vault.path);
    assert_eq!(entry.save_count(), 1);
}

#[test]
fn creating_vault_over_existing_file_fails() {
    let fx = Fixture::new();
    let other = VaultHandle::new_for_test_at(fx.vault.path.clone());
    assert!(matches!(
        fx.files.create(&other),
        Err(Error::DuplicateVaultId(_))
    ));
    assert_eq!(VaultHeader::peek(&fx.vault.path).unwrap().id, fx.id());
}

#[test]
fn write_saves_and_retains_replaced_file() {
    let fx = Fixture::new();
    let before = fs::read_to_string(&fx.vault.path).unwrap();

    let committed = fx.add(&fx.target(), "alpha", "one");

    assert!(committed.changed);
    assert_eq!(fx.value(&fx.vault.path, "alpha").as_deref(), Some("one"));
    let versions = fx.versions();
    assert_eq!(versions.len(), 1);
    let retained = fs::read_to_string(fx.files.versions(fx.id()).file(&versions[0].name)).unwrap();
    assert_eq!(retained, before);
}

#[test]
fn write_that_changes_nothing_saves_nothing() {
    let fx = Fixture::new();
    let committed = fx
        .files
        .write::<_, Error>(&fx.target(), fx.unlock(), |vw| vw.list_items().map(|_| ()))
        .unwrap();
    assert!(!committed.changed);
    assert!(fx.versions().is_empty());
}

/// Vault with entries of every kind, created at `vaults/personal.json` in
/// `dir`.
fn filled_vault(dir: &TempDir, files: &VaultWriter) -> VaultHandle {
    let mut vault = Vault::new_for_test();
    vault.fill_for_test();
    let path = dir.path().join("vaults").join("personal.json");
    let vh = VaultHandle::unlocked(path, vault);
    files.create(&vh).unwrap();
    vh
}

#[test]
fn vault_with_every_entry_kind_saved_and_reloaded() {
    let dir = tempfile::tempdir().unwrap();
    let files = VaultWriter::isolated(dir.path().join("data"));
    let vh = filled_vault(&dir, &files);

    files
        .write_unlocked::<_, Error>(&vh, |vw| vw.add_item("new", "New").map(|_| ()))
        .unwrap();

    let json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&vh.path).unwrap()).unwrap();
    assert_eq!(json["format"], serde_json::json!(VAULT_FORMAT));
    let enc_vault = EncryptedVault::load(&vh.path, files.signer().as_ref()).unwrap();
    let vault = Vault::from_unlocked_key(&vh.unlocked_key().unwrap(), enc_vault).unwrap();
    vault.assert_filled_for_test();
    assert!(vault.get_item("new").is_ok());
}

#[test]
fn unchanged_vault_with_every_entry_kind_saves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let files = VaultWriter::isolated(dir.path().join("data"));
    let vh = filled_vault(&dir, &files);
    let before = fs::read_to_string(&vh.path).unwrap();

    let committed = files
        .write_unlocked::<_, Error>(&vh, |vw| vw.list_items().map(|_| ()))
        .unwrap();

    assert!(!committed.changed);
    assert_eq!(fs::read_to_string(&vh.path).unwrap(), before);
    assert!(
        files
            .list_versions(vh.vault_id().unwrap())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn rekeyed_copy_saves_beside_source_and_reloads_verified() {
    let dir = tempfile::tempdir().unwrap();
    let files = VaultWriter::isolated(dir.path().join("data"));
    let source = filled_vault(&dir, &files);
    let source_vault = {
        let enc_vault = EncryptedVault::load(&source.path, files.signer().as_ref()).unwrap();
        Vault::from_unlocked_key(&source.unlocked_key().unwrap(), enc_vault).unwrap()
    };
    let source_before = fs::read_to_string(&source.path).unwrap();

    let new_id = Uuid::new_v4();
    let mut copy = source_vault
        .rekeyed(Some(new_id), |raw| Ok(VaultFileKey::new(raw.to_vec())))
        .unwrap();
    copy.set_key("copy".to_string());
    let path = VaultHandle::file_path(&dir.path().join("vaults"), new_id);
    let vh = VaultHandle::unlocked(path.clone(), copy);
    files.create(&vh).unwrap();

    let enc_vault = EncryptedVault::load(&path, files.signer().as_ref()).unwrap();
    let reloaded = Vault::from_unlocked_key(&vh.unlocked_key().unwrap(), enc_vault).unwrap();
    assert_eq!(reloaded.id(), new_id);
    assert_eq!(reloaded.key(), "copy");
    reloaded.assert_filled_for_test();
    assert_eq!(
        reloaded.entry_ids_for_test(),
        source_vault.entry_ids_for_test()
    );

    // The source file is unchanged and still opens with its own key.
    assert_eq!(fs::read_to_string(&source.path).unwrap(), source_before);
    let enc_vault = EncryptedVault::load(&source.path, files.signer().as_ref()).unwrap();
    let source_reloaded =
        Vault::from_unlocked_key(&source.unlocked_key().unwrap(), enc_vault).unwrap();
    source_reloaded.assert_filled_for_test();
    let enc_vault = EncryptedVault::load(&path, files.signer().as_ref()).unwrap();
    assert!(matches!(
        Vault::from_unlocked_key(&source.unlocked_key().unwrap(), enc_vault),
        Err(Error::VaultFileKeyChanged)
    ));
}

#[test]
fn vault_with_hyphenated_ids_loads_and_next_save_writes_short_ids() {
    let dir = tempfile::tempdir().unwrap();
    let files = VaultWriter::isolated(dir.path().join("data"));
    let vh = filled_vault(&dir, &files);
    let id = vh.vault_id().unwrap();
    let short = fs::read_to_string(&vh.path).unwrap();
    let hyphenated = EncryptedVault::hyphenate_ids_for_test(&short, files.signer().as_ref());
    fs::write(&vh.path, &hyphenated).unwrap();

    assert_eq!(VaultHeader::peek(&vh.path).unwrap().id, id);
    let committed = files
        .write_unlocked::<_, Error>(&vh, |vw| vw.list_items().map(|_| ()))
        .unwrap();

    // The raw vault bytes differ from the saved form, so the save rewrites
    // them. The new signature differs from the first one.
    assert!(committed.changed);
    let saved = fs::read_to_string(&vh.path).unwrap();
    assert_eq!(raw(&saved), raw(&short));
    assert!(EncryptedVault::assert_short_ids_for_test(&saved) > 0);
    let enc_vault = EncryptedVault::load(&vh.path, files.signer().as_ref()).unwrap();
    let vault = Vault::from_unlocked_key(&vh.unlocked_key().unwrap(), enc_vault).unwrap();
    vault.assert_filled_for_test();

    // The replaced file is retained unchanged, in a directory named by the
    // short id.
    let versions = files.list_versions(id).unwrap();
    assert_eq!(versions.len(), 1);
    let short_id = ShortId::encode_uuid(id);
    let retained = dir
        .path()
        .join("data")
        .join("versions")
        .join(&short_id)
        .join(&versions[0].name);
    assert_eq!(fs::read_to_string(retained).unwrap(), hyphenated);
    let lock = dir
        .path()
        .join("data")
        .join("locks")
        .join(format!("{short_id}.lock"));
    assert!(lock.exists());
}

#[test]
fn failed_change_writes_nothing() {
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
    assert_eq!(fx.versions().len(), 8);
}

#[test]
fn writer_waits_for_cross_process_lock() {
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
        fx.files.locks().wait_for_waiters(fx.id(), 1);
        assert!(!landed.load(Ordering::SeqCst));
        // Closing the file releases the lock, as a process exit does.
        drop(held);
    });
    assert!(landed.load(Ordering::SeqCst));
    assert_eq!(fx.value(&fx.vault.path, "alpha").as_deref(), Some("one"));
}

#[test]
fn closed_lock_file_releases_lock() {
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
fn key_change_writes_vault_keeps_file_name_and_retains_one_version() {
    let fx = Fixture::new();
    let committed = fx
        .files
        .write::<_, Error>(&fx.target(), fx.unlock(), |vw| {
            vw.set_vault_name("Renamed".to_string())?;
            vw.set_vault_key("renamed".to_string())
        })
        .unwrap();

    assert!(committed.changed);
    assert_eq!(committed.vault.path, fx.vault.path);
    assert_eq!(committed.vault.key, "renamed");
    assert_eq!(committed.previous_key, "personal");
    let header = VaultHeader::peek(&fx.vault.path).unwrap();
    assert_eq!(header.key, "renamed");
    assert_eq!(header.name.as_deref(), Some("Renamed"));
    assert!(!fx.dir.path().join("vaults/renamed.json").exists());
    assert_eq!(fx.versions().len(), 1);
}

#[test]
fn restoring_version_from_before_key_change_keeps_current_key() {
    let fx = Fixture::new();
    fx.add(&fx.target(), "alpha", "one");
    let committed = fx
        .files
        .write::<_, Error>(&fx.target(), fx.unlock(), |vw| {
            vw.set_vault_key("renamed".to_string())
        })
        .unwrap();
    let target = Target::of(&committed.vault);
    // Newest first. The second version is the file from before the first
    // write, with key `personal`.
    let name = fx.versions()[1].name.clone();

    fx.files
        .restore_version(&target, fx.unlock(), &name)
        .unwrap();

    assert_eq!(VaultHeader::peek(&fx.vault.path).unwrap().key, "renamed");
    assert_eq!(fx.value(&fx.vault.path, "alpha"), None);
}

#[test]
fn writer_that_found_old_path_lands_after_rename() {
    let fx = Fixture::new();
    let old_target = fx.target();
    let entry = fx.files.locks().entry(fx.id(), &fx.vault.path);
    let barrier = Barrier::new(2);
    thread::scope(|s| {
        s.spawn(|| {
            // Hold the vault mutex so the writer below waits for it.
            let mut locked = fx.files.lock_entry(&entry, fx.id()).unwrap();
            barrier.wait();
            fx.files.locks().wait_for_waiters(fx.id(), 1);
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
fn rename_concurrent_with_write_keeps_both_changes() {
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
    assert_eq!(fx.value(&fx.vault.path, "alpha").as_deref(), Some("one"));
    assert_eq!(VaultHeader::peek(&fx.vault.path).unwrap().key, "renamed");
}

#[test]
fn changed_file_key_not_used_and_key_unwrapped_again() {
    let fx = Fixture::new();
    // A key whose wrapped form differs from the file's fails the check and
    // is never used to decrypt. The second attempt gets the current key.
    let calls = AtomicU64::new(0);
    let key = || {
        let call = calls.fetch_add(1, Ordering::SeqCst);
        let current = fx.vault.unlocked_key().unwrap();
        if call == 0 {
            UnlockedKey::for_test(VaultFileKey::new(vec![1u8; 32]), current.cipher_for_test())
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
fn file_key_that_keeps_changing_fails() {
    let fx = Fixture::new();
    let key = || {
        UnlockedKey::for_test(
            VaultFileKey::new(vec![1u8; 32]),
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
fn deleted_vault_not_recreated_by_waiting_writer() {
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
        // Hold the mutex until the writer waits for it, then delete.
        let locked = fx.files.lock_entry(&entry, fx.id()).unwrap();
        barrier.wait();
        fx.files.locks().wait_for_waiters(fx.id(), 1);
        drop(locked);
        fx.files
            .delete(&fx.vault.path, |path| {
                fs::remove_file(path).map_err(Error::VaultDeleteError)
            })
            .unwrap();
        writer.join().unwrap()
    });
    // The waiting writer and the delete race for the mutex. The writer
    // either ran before the delete, or failed after it. Either way no file
    // is left. `writer_waiting_on_deleted_entry_fails` covers the order with
    // the delete first.
    if let Err(e) = result {
        assert!(matches!(e, Error::VaultNotFound(_)), "{e}");
    }
    assert!(!fx.vault.path.exists());
    assert!(!fx.files.locks().contains(fx.id()));
}

#[test]
fn writer_waiting_on_deleted_entry_fails() {
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
        fx.files.locks().wait_for_waiters(fx.id(), 1);
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
fn two_files_with_one_vault_id_refused() {
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
fn read_during_saves_sees_whole_vault() {
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
            EncryptedVault::parse(&contents, fx.files.signer().as_ref()).unwrap();
        }
    });
}

#[test]
fn restoring_version_replaces_vault_and_retains_replaced_file() {
    let fx = Fixture::new();
    fx.add(&fx.target(), "alpha", "one");
    fx.add(&fx.target(), "alpha", "two");
    let before_restore = fs::read_to_string(&fx.vault.path).unwrap();
    // Newest first: the version before "two" holds "one".
    let versions = fx.versions();
    assert_eq!(versions.len(), 2);

    let committed = fx
        .files
        .restore_version(&fx.target(), fx.unlock(), &versions[0].name)
        .unwrap();

    assert!(committed.changed);
    assert_eq!(fx.value(&fx.vault.path, "alpha").as_deref(), Some("one"));
    let after = fx.versions();
    assert_eq!(after.len(), 3);
    let retained = fs::read_to_string(fx.files.versions(fx.id()).file(&after[0].name)).unwrap();
    assert_eq!(retained, before_restore);
}

#[test]
fn restoring_missing_version_fails() {
    let fx = Fixture::new();
    for name in ["1-0.json", "../personal.json", "nonsense"] {
        assert!(matches!(
            fx.files.restore_version(&fx.target(), fx.unlock(), name),
            Err(Error::VaultVersionNotFound(_))
        ));
    }
}

#[test]
fn restoring_version_with_another_file_key_fails() {
    let fx = Fixture::new();
    let signer = fx.files.signer().as_ref();
    let mut enc_vault = EncryptedVault::load(&fx.vault.path, signer)
        .unwrap()
        .into_inner();
    enc_vault.file_key = VaultFileKey::new(vec![1u8; 32]);
    let dir = fx.files.versions(fx.id());
    fs::create_dir_all(&dir.path).unwrap();
    fs::write(
        dir.file("1-0.json"),
        enc_vault.to_file_contents(signer).unwrap(),
    )
    .unwrap();

    assert!(matches!(
        fx.files
            .restore_version(&fx.target(), fx.unlock(), "1-0.json"),
        Err(Error::VaultVersionKeyChanged(_))
    ));
}

/// Replace the vault file at `path` with a copy signed by another key, which
/// is refused. Returns the refused contents.
fn refuse(path: &Path) -> String {
    let contents = fs::read_to_string(path).unwrap();
    let forged = EncryptedVault::sign_vault_json(raw(&contents), &TestSigner::random()).unwrap();
    fs::write(path, &forged).unwrap();
    forged
}

#[test]
fn restore_over_refused_file_keeps_bytes() {
    let fx = Fixture::new();
    fx.add(&fx.target(), "alpha", "one");
    fx.add(&fx.target(), "alpha", "two");
    let versions = fx.versions();
    let refused = refuse(&fx.vault.path);
    assert!(matches!(
        fx.files
            .write::<_, Error>(&fx.target(), fx.unlock(), |_| Ok(())),
        Err(Error::VaultSignatureInvalid)
    ));

    let committed = fx
        .files
        .restore_refused(&fx.target(), fx.unlock(), &versions[0].name)
        .unwrap();

    assert!(committed.changed);
    assert_eq!(fx.value(&fx.vault.path, "alpha").as_deref(), Some("one"));
    let invalid = fx.files.list_invalid(fx.id());
    assert_eq!(invalid.len(), 1);
    assert!(invalid[0].ends_with(".invalid.json"), "{}", invalid[0]);
    let kept = fs::read_to_string(fx.files.versions(fx.id()).file(&invalid[0])).unwrap();
    assert_eq!(kept, refused);
    // The invalid file is not listed or restored as a version.
    assert_eq!(fx.versions(), versions);
    assert!(matches!(
        fx.files
            .restore_version(&fx.target(), fx.unlock(), &invalid[0]),
        Err(Error::VaultVersionNotFound(_))
    ));
}

#[test]
fn restore_over_refused_file_refuses_file_that_verifies() {
    let fx = Fixture::new();
    fx.add(&fx.target(), "alpha", "one");
    let versions = fx.versions();
    let before = fs::read_to_string(&fx.vault.path).unwrap();

    let result = fx
        .files
        .restore_refused(&fx.target(), fx.unlock(), &versions[0].name);

    assert!(matches!(result, Err(Error::VaultNotRefused(_))));
    assert_eq!(fs::read_to_string(&fx.vault.path).unwrap(), before);
    assert!(fx.files.list_invalid(fx.id()).is_empty());
}

#[test]
fn failed_unlock_or_forged_version_writes_no_invalid_file() {
    let fx = Fixture::new();
    fx.add(&fx.target(), "alpha", "one");
    fx.add(&fx.target(), "alpha", "two");
    let versions = fx.versions();
    let forged_name = &versions[0].name;
    let path = fx.files.versions(fx.id()).file(forged_name);
    let version = fs::read_to_string(&path).unwrap();
    let forged = EncryptedVault::sign_vault_json(raw(&version), &TestSigner::random()).unwrap();
    fs::write(&path, forged).unwrap();
    let refused = refuse(&fx.vault.path);
    let id = fx.id();
    let wrong_key =
        || UnlockedKey::for_test(VaultFileKey::new(vec![9u8; 32]), VaultCipher::new(id));

    let forged = fx
        .files
        .restore_refused(&fx.target(), fx.unlock(), forged_name);
    let missing = fx
        .files
        .restore_refused(&fx.target(), fx.unlock(), "1-0.json");
    let wrong = fx
        .files
        .restore_refused(&fx.target(), Unlock::Test(&wrong_key), &versions[1].name);

    assert!(matches!(forged, Err(Error::VaultSignatureInvalid)));
    assert!(matches!(missing, Err(Error::VaultVersionNotFound(_))));
    assert!(matches!(wrong, Err(Error::VaultVersionKeyChanged(_))));
    assert_eq!(fs::read_to_string(&fx.vault.path).unwrap(), refused);
    assert!(fx.files.list_invalid(fx.id()).is_empty());
}

#[test]
fn invalid_files_kept_up_to_newest_20_and_not_pruned_by_time() {
    let tmp = tempfile::tempdir().unwrap();
    let files = VaultWriter::isolated(tmp.path());
    let dir = files.versions(Uuid::new_v4());
    let now = now_ms();
    let old = now - 40 * DAY_MS;
    for i in 0..22 {
        dir.add_invalid(old + i, format!("refused {i}").as_bytes())
            .unwrap();
    }

    let kept = |dir: &VersionsDir| -> Vec<String> {
        dir.list_invalid()
            .unwrap()
            .iter()
            .map(|file| fs::read_to_string(dir.file(&file.name)).unwrap())
            .collect()
    };
    let newest: Vec<String> = (2..22).rev().map(|i| format!("refused {i}")).collect();
    assert_eq!(kept(&dir), newest);
    assert!(dir.list().unwrap().is_empty());

    dir.add(now, "new").unwrap();
    dir.prune(now).unwrap();
    files.prune_all();

    assert_eq!(kept(&dir), newest);
    assert_eq!(dir.list().unwrap(), vec![version(now, 0)]);
}

#[test]
fn erasing_versions_also_deletes_invalid_files() {
    let fx = Fixture::new();
    fx.add(&fx.target(), "alpha", "one");
    let versions = fx.versions();
    refuse(&fx.vault.path);
    fx.files
        .restore_refused(&fx.target(), fx.unlock(), &versions[0].name)
        .unwrap();
    assert_eq!(fx.files.list_invalid(fx.id()).len(), 1);

    let erased = fx.files.erase_versions(fx.id(), &fx.vault.path).unwrap();

    assert_eq!(erased, 1);
    assert!(fx.versions().is_empty());
    assert!(fx.files.list_invalid(fx.id()).is_empty());
}

#[test]
fn listing_versions_deletes_versions_past_retention() {
    let fx = Fixture::new();
    fx.add(&fx.target(), "alpha", "one");
    let dir = fx.files.versions(fx.id());
    dir.add(now_ms() - 40 * DAY_MS, "old").unwrap();
    assert_eq!(dir.list().unwrap().len(), 2);

    assert_eq!(fx.versions().len(), 1);
    assert_eq!(dir.list().unwrap().len(), 1);
}

#[test]
fn pruning_all_vaults_removes_expired_versions_and_empty_directories() {
    let dir = tempfile::tempdir().unwrap();
    let files = VaultWriter::isolated(dir.path());
    let now = now_ms();
    let expired = files.versions(Uuid::new_v4());
    expired.add(now - 40 * DAY_MS, "old").unwrap();
    let current = files.versions(Uuid::new_v4());
    current.add(now - 40 * DAY_MS, "old").unwrap();
    current.add(now, "new").unwrap();

    files.prune_all();

    assert!(!expired.path.exists());
    assert_eq!(current.list().unwrap().len(), 1);
}

#[test]
fn deleting_vault_keeps_its_versions_until_they_expire() {
    let fx = Fixture::new();
    fx.add(&fx.target(), "alpha", "one");
    let dir = fx.files.versions(fx.id());
    dir.add(now_ms() - 40 * DAY_MS, "old").unwrap();

    fx.files
        .delete(&fx.vault.path, |path| {
            fs::remove_file(path).map_err(Error::VaultDeleteError)
        })
        .unwrap();

    assert_eq!(dir.list().unwrap().len(), 2);
    fx.files.prune_all();
    assert_eq!(dir.list().unwrap().len(), 1);
}

#[test]
fn erasing_versions_deletes_them_and_leaves_vault() {
    let fx = Fixture::new();
    fx.add(&fx.target(), "alpha", "one");
    fx.add(&fx.target(), "alpha", "two");
    assert_eq!(fx.versions().len(), 2);

    let erased = fx.files.erase_versions(fx.id(), &fx.vault.path).unwrap();

    assert_eq!(erased, 2);
    assert!(fx.versions().is_empty());
    assert_eq!(fx.value(&fx.vault.path, "alpha").as_deref(), Some("two"));
}

#[test]
fn versions_in_one_millisecond_get_distinct_names() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = VersionsDir::at(tmp.path());
    let first = dir.add(1_000, "a").unwrap();
    let second = dir.add(1_000, "b").unwrap();
    assert_ne!(first, second);
    let versions = dir.list().unwrap();
    assert_eq!(versions, vec![version(1_000, 1), version(1_000, 0)]);
}

#[test]
fn retention_keeps_last_hour_and_last_version_of_each_day() {
    let now = 100 * DAY_MS + 12 * HOUR_MS;
    let mut versions = Vec::new();
    // A burst of 150 saves in the last ten minutes.
    for i in 0..150 {
        versions.push(version(now - 10 * 60 * 1000 + i * 1000, 0));
    }
    // Three saves on each of the 40 days before today.
    for day in 1..=40 {
        for hour in [3, 9, 15] {
            versions.push(version(
                now - day * DAY_MS - 12 * HOUR_MS + hour * HOUR_MS,
                0,
            ));
        }
    }
    versions.sort_by_key(|v| std::cmp::Reverse((v.saved_at_ms, v.seq)));

    let keep = kept_versions(&versions, now);

    // The newest 100 of the burst.
    for i in 50..150 {
        assert!(keep.contains(&version(now - 10 * 60 * 1000 + i * 1000, 0).name));
    }
    for i in 0..50 {
        assert!(!keep.contains(&version(now - 10 * 60 * 1000 + i * 1000, 0).name));
    }
    // The last version of each earlier day within 30 days, and nothing older.
    for day in 1..=40 {
        let last = version(now - day * DAY_MS - 12 * HOUR_MS + 15 * HOUR_MS, 0);
        let earlier = version(now - day * DAY_MS - 12 * HOUR_MS + 9 * HOUR_MS, 0);
        // The last version of day 30 is 30 days less 3 hours old.
        assert_eq!(keep.contains(&last.name), day <= 30, "day {day}");
        assert!(!keep.contains(&earlier.name), "day {day}");
    }
    assert_eq!(keep.len(), 100 + 30);
}

#[test]
fn pruning_deletes_versions_retention_does_not_keep() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = VersionsDir::at(tmp.path());
    let now = 100 * DAY_MS;
    let old = now - 40 * DAY_MS;
    dir.add(old, "old").unwrap();
    dir.add(now, "new").unwrap();
    fs::write(dir.file("notes.txt"), "kept").unwrap();

    dir.prune(now).unwrap();

    assert_eq!(dir.list().unwrap(), vec![version(now, 0)]);
    assert!(dir.file("notes.txt").exists());
}
