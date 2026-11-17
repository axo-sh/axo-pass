//! Appends audit events to monthly JSONL files.
//!
//! Records are appended under an advisory `flock`, so `ap` and the app can
//! write the same file safely. Write failures never propagate: a signature
//! must not fail because the disk is full.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Once;

use time::OffsetDateTime;

use crate::audit::event::AuditEvent;
use crate::core::dirs::app_data_dir;
use crate::core::protected_settings::ProtectedSettings;

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
/// `AXO_PASS_AUDIT_DIR` overrides the location in test and debug builds. A
/// release build ignores it, since any process that sets the environment of the
/// app could otherwise move the log.
pub fn audit_dir() -> PathBuf {
    #[cfg(any(test, debug_assertions))]
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

/// Environment override of the account details setting. `1` records details
/// and any other value omits them. Only read in test and debug builds, since
/// any process that sets the environment of a release build could use it to
/// turn details on.
#[cfg(any(test, debug_assertions))]
const DETAILS_ENV: &str = "AXO_PASS_AUDIT_DETAILS";

/// Whether the audit log records names, paths, and hosts. Read from the
/// protected settings on every call, so a change in the app applies to a
/// running `ap`. Off if the settings cannot be read, which includes `ap`
/// running with no app.
pub fn include_details() -> bool {
    #[cfg(any(test, debug_assertions))]
    if let Some(value) = std::env::var_os(DETAILS_ENV) {
        return value == "1";
    }
    ProtectedSettings::current().audit_include_details
}

/// Record an event. Blocking. Never panics, never returns an error; logs at
/// `warn` on failure. Omits account details unless [`include_details`].
pub fn record(event: AuditEvent) {
    let action = event.action;
    let event = if include_details() {
        event
    } else {
        event.without_details()
    };
    if let Err(e) = try_record(&event) {
        log::warn!("audit: failed to record {action:?}: {e}");
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

    let file = open_locked(&path, true)?.expect("file is created if missing, so it always opens");

    if !existed {
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }

    (&file)
        .write_all(line.as_bytes())
        .and_then(|()| (&file).flush())
}

/// Open `path` for appending and take the exclusive lock. The lock is held
/// until the returned file is dropped. Returns `None` if the file is missing
/// and `create` is false.
///
/// Rewriting a file replaces it, so a file opened while a rewrite held the lock
/// is no longer the one at `path`. Reopen until the locked file is the one at
/// `path`.
fn open_locked(path: &Path, create: bool) -> std::io::Result<Option<fs::File>> {
    loop {
        let file = match OpenOptions::new()
            .read(true)
            .append(true)
            .create(create)
            .mode(0o600)
            .open(path)
        {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        lock(file.as_raw_fd(), libc::LOCK_EX)?;
        let held = file.metadata()?;
        match fs::metadata(path) {
            Ok(current) if current.dev() == held.dev() && current.ino() == held.ino() => {
                return Ok(Some(file));
            },
            _ => {},
        }
    }
}

fn lock(fd: std::os::fd::RawFd, op: libc::c_int) -> std::io::Result<()> {
    if unsafe { libc::flock(fd, op) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Rewrite every monthly file without account details. Returns the number of
/// events changed. Each file is rewritten under the lock the writer takes, so
/// an append that arrives meanwhile lands in the new file. Lines that are not
/// events and events with no details are kept byte for byte.
pub fn clear_details() -> std::io::Result<usize> {
    let dir = audit_dir();
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let mut changed = 0;
    for entry in entries {
        let path = entry?.path();
        let is_monthly = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("audit-") && n.ends_with(".jsonl"));
        if is_monthly {
            changed += clear_file_details(&path)?;
        }
    }
    Ok(changed)
}

fn clear_file_details(path: &Path) -> std::io::Result<usize> {
    let Some(mut file) = open_locked(path, false)? else {
        return Ok(0);
    };
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    let mut out = Vec::with_capacity(data.len());
    let mut changed = 0;
    for raw in data.split_inclusive(|b| *b == b'\n') {
        let stripped = serde_json::from_slice::<AuditEvent>(raw)
            .ok()
            .and_then(|event| {
                let before = serde_json::to_vec(&event).ok()?;
                let after = serde_json::to_vec(&event.without_details()).ok()?;
                (before != after).then_some(after)
            });
        match stripped {
            Some(mut line) => {
                line.push(b'\n');
                out.extend_from_slice(&line);
                changed += 1;
            },
            None => out.extend_from_slice(raw),
        }
    }
    if changed == 0 {
        return Ok(0);
    }

    let file_name = path.file_name().unwrap_or_default().to_string_lossy();
    let tmp = path.with_file_name(format!(".{file_name}.tmp"));
    let result = write_private(&tmp, &out).and_then(|()| fs::rename(&tmp, path));
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result?;
    Ok(changed)
}

/// Write `data` to a new file with mode `0600`, replacing a leftover file, and
/// sync it.
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)?;
    file.sync_all()
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
