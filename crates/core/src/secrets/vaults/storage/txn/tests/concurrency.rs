use super::*;

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
