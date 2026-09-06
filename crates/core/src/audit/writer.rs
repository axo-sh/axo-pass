//! Appends audit events to monthly JSONL files.
//!
//! Records are appended under an advisory `flock`, so `ap` and the app can
//! write the same file safely. Write failures never propagate: a signature
//! must not fail because the disk is full.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Once;

use time::OffsetDateTime;

use crate::audit::event::AuditEvent;
use crate::core::dirs::app_data_dir;

/// Delete monthly files older than this many months on the first write of a
/// process.
const RETENTION_MONTHS: i32 = 12;

static PRUNE: Once = Once::new();

/// `YYYY-MM` for a timestamp.
fn month_stamp(at: OffsetDateTime) -> String {
    format!("{:04}-{:02}", at.year(), at.month() as u8)
}

/// Parse the `YYYY-MM` in `audit-YYYY-MM.jsonl` into a `(year, month)` ordinal
/// count of months, for retention comparison.
fn month_ordinal(stamp: &str) -> Option<i32> {
    let (year, month) = stamp.split_once('-')?;
    let year: i32 = year.parse().ok()?;
    let month: u8 = month.parse().ok()?;
    if !(1..=12).contains(&month) {
        return None;
    }
    Some(year * 12 + i32::from(month) - 1)
}

/// The directory holding the monthly audit files.
///
/// `AXO_PASS_AUDIT_DIR` overrides the location, for tests.
pub fn audit_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("AXO_PASS_AUDIT_DIR") {
        return PathBuf::from(dir);
    }
    app_data_dir().join("audit")
}

/// The current month's audit file.
pub fn audit_log_path() -> PathBuf {
    audit_file_for(OffsetDateTime::now_utc())
}

fn audit_file_for(at: OffsetDateTime) -> PathBuf {
    audit_dir().join(format!("audit-{}.jsonl", month_stamp(at)))
}

/// Record an event. Blocking. Never panics, never returns an error; logs at
/// `warn` on failure.
pub fn record(event: AuditEvent) {
    if let Err(e) = try_record(&event) {
        log::warn!("audit: failed to record {:?}: {e}", event.action);
    }
}

/// Record an event from an async context, off the runtime threads.
pub async fn record_async(event: AuditEvent) {
    if let Err(e) = tokio::task::spawn_blocking(move || record(event)).await {
        log::warn!("audit: record task panicked: {e}");
    }
}

fn try_record(event: &AuditEvent) -> std::io::Result<()> {
    let dir = audit_dir();
    fs::create_dir_all(&dir)?;

    PRUNE.call_once(|| {
        if let Err(e) = prune(&dir) {
            log::warn!("audit: prune failed: {e}");
        }
    });

    let path = audit_file_for(event.at);
    let existed = path.exists();

    let mut line = serde_json::to_string(event)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    line.push('\n');

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)?;

    if !existed {
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }

    let fd = file.as_raw_fd();
    lock(fd, libc::LOCK_EX)?;
    let write_result = (&file)
        .write_all(line.as_bytes())
        .and_then(|()| (&file).flush());
    let _ = lock(fd, libc::LOCK_UN);
    write_result
}

fn lock(fd: std::os::fd::RawFd, op: libc::c_int) -> std::io::Result<()> {
    if unsafe { libc::flock(fd, op) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Delete monthly files whose month is more than `RETENTION_MONTHS` before the
/// current month.
fn prune(dir: &Path) -> std::io::Result<()> {
    let now = OffsetDateTime::now_utc();
    let cutoff = month_ordinal(&month_stamp(now)).unwrap_or(0) - RETENTION_MONTHS;

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(stamp) = name
            .strip_prefix("audit-")
            .and_then(|rest| rest.strip_suffix(".jsonl"))
        else {
            continue;
        };
        let Some(ordinal) = month_ordinal(stamp) else {
            continue;
        };
        if ordinal < cutoff {
            let _ = fs::remove_file(entry.path());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use time::Duration;

    use super::*;

    #[test]
    fn prune_deletes_old_months_and_keeps_recent_ones() {
        let dir = tempfile::tempdir().unwrap();
        let now = OffsetDateTime::now_utc();

        let month_name = |months_ago: i64| {
            format!(
                "audit-{}.jsonl",
                month_stamp(now - Duration::days(months_ago * 31))
            )
        };

        let old = dir.path().join(month_name(14));
        let recent = dir.path().join(month_name(11));
        fs::write(&old, "{}\n").unwrap();
        fs::write(&recent, "{}\n").unwrap();

        prune(dir.path()).unwrap();

        assert!(!old.exists(), "14-month-old file should be pruned");
        assert!(recent.exists(), "11-month-old file should be kept");
    }
}
