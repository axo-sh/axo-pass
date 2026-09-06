//! Reads audit events back, newest first.
//!
//! Monthly files are walked backwards. Malformed lines are skipped and
//! counted, not fatal: the file is plaintext and editable by hand.

use std::fs;

use time::OffsetDateTime;

use crate::audit::event::{Action, AuditEvent, Outcome, Source};
use crate::audit::writer::audit_dir;

/// Narrows a `read`. Every field is optional; an empty filter returns
/// everything up to `limit`.
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    pub since: Option<OffsetDateTime>,
    pub until: Option<OffsetDateTime>,
    pub actions: Vec<Action>,
    pub sources: Vec<Source>,
    pub outcomes: Vec<Outcome>,
    /// Case-insensitive substring match on caller, subject id/label and
    /// message.
    pub query: Option<String>,
    /// Maximum events to return. `None` means no limit.
    pub limit: Option<usize>,
    /// Events to skip, after filtering, before collecting.
    pub offset: usize,
}

/// The result of a `read`: matching events, newest first, plus how many lines
/// could not be parsed.
#[derive(Debug, Default)]
pub struct AuditPage {
    pub events: Vec<AuditEvent>,
    pub skipped_lines: usize,
}

impl AuditFilter {
    fn matches(&self, event: &AuditEvent) -> bool {
        if let Some(since) = self.since
            && event.at < since
        {
            return false;
        }
        if let Some(until) = self.until
            && event.at > until
        {
            return false;
        }
        if !self.actions.is_empty() && !self.actions.contains(&event.action) {
            return false;
        }
        if !self.sources.is_empty() && !self.sources.contains(&event.source) {
            return false;
        }
        if !self.outcomes.is_empty() && !self.outcomes.contains(&event.outcome) {
            return false;
        }
        if let Some(query) = &self.query {
            let query = query.to_lowercase();
            let haystacks = [
                event.actor.as_ref().and_then(|a| a.caller.clone()),
                event.subject.as_ref().map(|s| s.id.clone()),
                event.subject.as_ref().and_then(|s| s.label.clone()),
                event.message.clone(),
            ];
            let hit = haystacks
                .iter()
                .flatten()
                .any(|h| h.to_lowercase().contains(&query));
            if !hit {
                return false;
            }
        }
        true
    }
}

/// Read events matching `filter`, newest first.
pub fn read(filter: &AuditFilter) -> AuditPage {
    let mut months = month_files();
    months.sort();
    months.reverse();

    let mut page = AuditPage::default();
    let mut skipped = 0;

    for path in months {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        let mut events: Vec<AuditEvent> = Vec::new();
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<AuditEvent>(line) {
                Ok(event) => events.push(event),
                Err(_) => skipped += 1,
            }
        }
        // Within a file, newest last on disk, so reverse for newest first.
        for event in events.into_iter().rev() {
            if filter.matches(&event) {
                page.events.push(event);
            }
        }
        if let Some(limit) = filter.limit
            && page.events.len() >= filter.offset + limit
        {
            break;
        }
    }

    if filter.offset > 0 {
        page.events.drain(..filter.offset.min(page.events.len()));
    }
    if let Some(limit) = filter.limit {
        page.events.truncate(limit);
    }
    page.skipped_lines = skipped;
    page
}

fn month_files() -> Vec<std::path::PathBuf> {
    let Ok(dir) = fs::read_dir(audit_dir()) else {
        return Vec::new();
    };
    dir.filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("audit-") && n.ends_with(".jsonl"))
        })
        .collect()
}
