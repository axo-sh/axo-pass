use super::*;

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
