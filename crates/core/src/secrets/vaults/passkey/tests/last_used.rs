use std::fs;

use jiff::tz::Offset;
use tempfile::TempDir;

use super::*;

/// Unix time of 2026-10-23 00:00:00 UTC.
const OCT_23_UTC: i64 = 1_792_713_600;
const HOUR: i64 = 3600;

fn fixed_zone(hours: i32) -> TimeZone {
    TimeZone::fixed(Offset::from_seconds(hours * 3600).unwrap())
}

/// Vault file in a temp directory that holds one passkey with no last
/// used time.
struct OnDisk {
    _dir: TempDir,
    files: VaultWriter,
    /// Vault as created.
    vault: VaultHandle,
    stored: PasskeyCredential,
}

impl OnDisk {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let files = VaultWriter::isolated(dir.path().join("data"));
        let mut vault =
            VaultHandle::new_for_test_at(dir.path().join("vaults").join("personal.json"));
        register(&mut vault, PasskeyTarget::NewLogin, "ada").await;
        files.create(&vault).unwrap();
        let stored = list(&vault).unwrap().remove(0);
        Self {
            _dir: dir,
            files,
            vault,
            stored,
        }
    }

    /// Vault as it is on disk now. The read runs a transaction that
    /// saves nothing.
    fn load(&self) -> VaultHandle {
        self.files
            .write_unlocked::<_, Error>(&self.vault, |_| Ok(()))
            .unwrap()
            .vault
    }

    fn last_used_on_disk(&self) -> Option<i64> {
        last_used_at(
            &self.load(),
            &self.stored.item_key,
            &self.stored.credential_key,
        )
    }

    /// Record a use at `at` in `zone` from `vw`.
    fn sign_in(&self, vw: &VaultHandle, at: i64, zone: &TimeZone) -> bool {
        record_use(&self.files, vw, &self.stored, at, zone).unwrap()
    }

    /// File contents and retained version count.
    fn snapshot(&self) -> (Vec<u8>, usize) {
        let id = self.vault.vault_id().unwrap();
        (
            fs::read(&self.vault.path).unwrap(),
            self.files.list_versions(id).unwrap().len(),
        )
    }
}

#[tokio::test]
async fn second_sign_in_on_same_day_runs_no_transaction() {
    let disk = OnDisk::new().await;
    let zone = fixed_zone(-7);
    // 2026-10-22 08:00 at UTC-7.
    let first = OCT_23_UTC - 9 * HOUR;
    assert!(disk.sign_in(&disk.vault, first, &zone));
    let loaded = disk.load();
    let before = disk.snapshot();

    // 2026-10-22 23:00 at UTC-7.
    assert!(!disk.sign_in(&loaded, first + 15 * HOUR, &zone));

    assert_eq!(disk.snapshot(), before);
    assert_eq!(disk.last_used_on_disk(), Some(first));
    // A transaction reloads the file, so with the file removed, one that
    // ran would fail.
    fs::remove_file(&disk.vault.path).unwrap();
    assert!(!disk.sign_in(&loaded, first + 15 * HOUR, &zone));
}

/// The vault the passkey signed from was loaded before another sign-in
/// recorded today. The transaction reloads the vault and saves nothing.
#[tokio::test]
async fn sign_in_from_stale_vault_on_same_day_saves_nothing() {
    let disk = OnDisk::new().await;
    let zone = fixed_zone(-7);
    let first = OCT_23_UTC - 9 * HOUR;
    assert!(disk.sign_in(&disk.vault, first, &zone));
    let before = disk.snapshot();

    assert!(!disk.sign_in(&disk.vault, first + HOUR, &zone));

    assert_eq!(disk.snapshot(), before);
    assert_eq!(disk.last_used_on_disk(), Some(first));
}

#[tokio::test]
async fn sign_in_on_later_day_writes_new_time() {
    let disk = OnDisk::new().await;
    let zone = fixed_zone(-7);
    let first = OCT_23_UTC - 9 * HOUR;
    assert!(disk.sign_in(&disk.vault, first, &zone));
    let (_, versions) = disk.snapshot();

    let next = first + 24 * HOUR;
    assert!(disk.sign_in(&disk.load(), next, &zone));

    assert_eq!(disk.last_used_on_disk(), Some(next));
    assert_eq!(disk.snapshot().1, versions + 1);
}

#[tokio::test]
async fn sign_in_after_local_midnight_writes() {
    let disk = OnDisk::new().await;
    let zone = fixed_zone(-7);
    // 2026-10-22 23:30 and 2026-10-23 00:30 at UTC-7. Both are on
    // 2026-10-23 in UTC.
    let first = OCT_23_UTC + 7 * HOUR - HOUR / 2;
    let second = first + HOUR;
    assert!(disk.sign_in(&disk.vault, first, &zone));

    assert!(disk.sign_in(&disk.load(), second, &zone));

    assert_eq!(disk.last_used_on_disk(), Some(second));
}

#[tokio::test]
async fn sign_in_after_utc_midnight_skips_write() {
    let disk = OnDisk::new().await;
    let zone = fixed_zone(-7);
    // 2026-10-22 16:30 and 17:30 at UTC-7, either side of UTC midnight.
    let first = OCT_23_UTC - HOUR / 2;
    assert!(disk.sign_in(&disk.vault, first, &zone));
    let loaded = disk.load();
    let before = disk.snapshot();

    assert!(!disk.sign_in(&loaded, first + HOUR, &zone));

    assert_eq!(disk.snapshot(), before);
    assert_eq!(disk.last_used_on_disk(), Some(first));
}

/// Another Mac at UTC+9 recorded a use at 08:00 on 2026-10-23 there, which
/// is 23:00 on 2026-10-22 in UTC. This Mac is at UTC+2, where that use is
/// at 01:00 on 2026-10-23.
#[tokio::test]
async fn use_from_other_zone_not_overwritten() {
    let disk = OnDisk::new().await;
    let other_mac = OCT_23_UTC - HOUR;
    assert!(disk.sign_in(&disk.vault, other_mac, &fixed_zone(9)));
    let loaded = disk.load();
    let before = disk.snapshot();

    // 2026-10-23 10:00 at UTC+2.
    assert!(!disk.sign_in(&loaded, OCT_23_UTC + 8 * HOUR, &fixed_zone(2)));

    assert_eq!(disk.snapshot(), before);
    assert_eq!(disk.last_used_on_disk(), Some(other_mac));
}

/// An app edit saved after the vault the passkey signed from was loaded
/// is kept, since the last used write reloads the vault in its own
/// transaction.
#[tokio::test]
async fn last_used_write_keeps_concurrent_edit() {
    let disk = OnDisk::new().await;
    let signed_from = disk.load();
    disk.files
        .write_unlocked::<_, Error>(&disk.vault, |vw| {
            vw.add_item("other", "Other")?;
            Ok(())
        })
        .unwrap();

    assert!(disk.sign_in(&signed_from, OCT_23_UTC, &TimeZone::UTC));

    let after = disk.load();
    assert!(after.get_item_overview("other").unwrap().is_some());
    assert_eq!(disk.last_used_on_disk(), Some(OCT_23_UTC));
}
