//! Bounded in-memory log of sync events, for the sync log window.
//!
//! One log per process. The log holds at most [`CAPACITY`] entries and drops
//! the oldest entry if it is full. It resets at restart. An event that repeats
//! the latest entry of its vault is merged into that entry, with a count and a
//! new last time, so a failing poll takes one row.
//!
//! Message text is fixed and holds no account details. A detail such as a
//! bucket name, an endpoint, or an error text is kept only if
//! [`audit::include_details`] is on.

use std::collections::VecDeque;
use std::sync::Mutex;

use jiff::Timestamp;
use uuid::Uuid;

use crate::audit;

/// Most entries that the log holds.
pub const CAPACITY: usize = 500;

static LOG: SyncLog = SyncLog::new(CAPACITY);

/// Severity of a log entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Info,
    Warn,
    Error,
}

impl From<Level> for log::Level {
    fn from(level: Level) -> Self {
        match level {
            Level::Info => log::Level::Info,
            Level::Warn => log::Level::Warn,
            Level::Error => log::Level::Error,
        }
    }
}

/// One row of the log, with the repeats merged into it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub level: Level,
    /// Vault of the event, or `None` for an event of no vault.
    pub vault_id: Option<Uuid>,
    pub message: String,
    /// Account details of the event. `None` if details are off.
    pub detail: Option<String>,
    /// Number of events merged into this entry, at least 1.
    pub count: u32,
    pub first: Timestamp,
    pub last: Timestamp,
}

/// Ring of entries, oldest first.
pub struct SyncLog {
    capacity: usize,
    entries: Mutex<VecDeque<Entry>>,
}

impl SyncLog {
    pub const fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(VecDeque::new()),
        }
    }

    /// Add an event at `now`. `detail` is dropped unless `with_detail`.
    pub fn record(
        &self,
        level: Level,
        vault_id: Option<Uuid>,
        message: &str,
        detail: Option<String>,
        with_detail: bool,
        now: Timestamp,
    ) {
        let detail = detail.filter(|_| with_detail);
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let latest = entries.iter_mut().rev().find(|e| e.vault_id == vault_id);
        if let Some(entry) = latest
            && entry.level == level
            && entry.message == message
            && entry.detail == detail
        {
            entry.count = entry.count.saturating_add(1);
            entry.last = now;
            return;
        }
        if entries.len() >= self.capacity {
            entries.pop_front();
        }
        entries.push_back(Entry {
            level,
            vault_id,
            message: message.to_string(),
            detail,
            count: 1,
            first: now,
            last: now,
        });
    }

    /// Entries, oldest first.
    pub fn entries(&self) -> Vec<Entry> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.iter().cloned().collect()
    }

    pub fn clear(&self) {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
}

/// Add an event to the process log and to the developer log. `message` is
/// fixed text, and `detail` is kept only if audit details are on.
pub fn record(level: Level, vault_id: Option<Uuid>, message: &str, detail: Option<String>) {
    match &detail {
        Some(detail) => log::log!(level.into(), "{message}: {detail}"),
        None => log::log!(level.into(), "{message}"),
    }
    LOG.record(
        level,
        vault_id,
        message,
        detail,
        audit::include_details(),
        Timestamp::now(),
    );
}

/// Add an event of vault `vault_id` at level info.
pub fn info(vault_id: Uuid, message: &str) {
    record(Level::Info, Some(vault_id), message, None);
}

/// Add a failure of vault `vault_id` at level warn, with the error as detail.
pub fn warn(vault_id: Uuid, message: &str, error: &dyn std::fmt::Display) {
    record(
        Level::Warn,
        Some(vault_id),
        message,
        Some(error.to_string()),
    );
}

/// Entries of the process log, oldest first.
pub fn entries() -> Vec<Entry> {
    LOG.entries()
}

/// Remove all entries of the process log.
pub fn clear() {
    LOG.clear();
}

#[cfg(test)]
mod tests {
    use jiff::SignedDuration;

    use super::*;

    const VAULT: Uuid = Uuid::from_u128(1);
    const OTHER: Uuid = Uuid::from_u128(2);

    fn at(seconds: i64) -> Timestamp {
        Timestamp::UNIX_EPOCH + SignedDuration::from_secs(seconds)
    }

    fn warn_at(log: &SyncLog, vault_id: Uuid, message: &str, seconds: i64) {
        log.record(
            Level::Warn,
            Some(vault_id),
            message,
            None,
            false,
            at(seconds),
        );
    }

    #[test]
    fn repeat_merges_into_latest_entry() {
        let log = SyncLog::new(10);
        warn_at(&log, VAULT, "poll failed", 1);
        warn_at(&log, VAULT, "poll failed", 5);

        let entries = log.entries();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].count, 2);
        assert_eq!(entries[0].first, at(1));
        assert_eq!(entries[0].last, at(5));
    }

    #[test]
    fn repeat_merges_across_other_vault() {
        let log = SyncLog::new(10);
        warn_at(&log, VAULT, "poll failed", 1);
        warn_at(&log, OTHER, "poll failed", 2);
        warn_at(&log, VAULT, "poll failed", 3);

        let entries = log.entries();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].count, 2);
        assert_eq!(entries[1].count, 1);
    }

    #[test]
    fn repeat_after_other_event_of_vault_not_merged() {
        let log = SyncLog::new(10);
        warn_at(&log, VAULT, "poll failed", 1);
        log.record(Level::Info, Some(VAULT), "joined", None, false, at(2));
        warn_at(&log, VAULT, "poll failed", 3);

        assert_eq!(log.entries().len(), 3);
    }

    #[test]
    fn oldest_entry_dropped_at_capacity() {
        let log = SyncLog::new(2);
        warn_at(&log, VAULT, "one", 1);
        warn_at(&log, VAULT, "two", 2);
        warn_at(&log, VAULT, "three", 3);

        let messages: Vec<_> = log.entries().into_iter().map(|e| e.message).collect();

        assert_eq!(messages, ["two", "three"]);
    }

    #[test]
    fn detail_kept_only_if_enabled() {
        let log = SyncLog::new(10);
        log.record(
            Level::Warn,
            None,
            "failed",
            Some("bucket".into()),
            false,
            at(1),
        );
        log.record(
            Level::Error,
            None,
            "failed",
            Some("bucket".into()),
            true,
            at(2),
        );

        let entries = log.entries();

        assert_eq!(entries[0].detail, None);
        assert_eq!(entries[1].detail.as_deref(), Some("bucket"));
    }

    #[test]
    fn clear_removes_entries() {
        let log = SyncLog::new(10);
        warn_at(&log, VAULT, "one", 1);

        log.clear();

        assert!(log.entries().is_empty());
    }
}
