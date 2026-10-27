//! Reads audit events back, newest first.
//!
//! Monthly files are walked backwards. Malformed lines are skipped and
//! counted, not fatal: the file is plaintext and editable by hand.

use std::fs;

use time::OffsetDateTime;
use uuid::Uuid;

use crate::audit::event::{Action, ActionKind, AuditEvent, Category, Outcome, Requester};
use crate::audit::writer::audit_dir;
use crate::secrets::vaults::format::short_id::ShortId;

/// Narrows a `read`. Every field is optional; an empty filter returns
/// everything up to `limit`.
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    pub since: Option<OffsetDateTime>,
    pub until: Option<OffsetDateTime>,
    pub actions: Vec<Action>,
    pub categories: Vec<Category>,
    pub kind: Option<ActionKind>,
    pub requesters: Vec<Requester>,
    pub outcomes: Vec<Outcome>,
    /// Case-insensitive substring match on caller, subject id/label and
    /// message.
    pub query: Option<String>,
    /// Entity id to match in the event detail.
    pub detail_id: Option<DetailId>,
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

/// Entity id to find in event detail, such as an `item_id`.
///
/// An event names the id if its detail holds `key` equal to `id`, or holds the
/// plural key, such as `item_ids`, as a comma-separated list that contains
/// `id`. If `id` is a vault entity id in the short or hex form, a detail value
/// in any of those forms with the same UUID also matches. Events recorded with
/// hyphenated ids are found by short id this way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailId {
    /// Detail key of a single id, such as `item_id`.
    pub key: String,
    pub id: String,
    /// `id` read as a short or hex id.
    uuid: Option<Uuid>,
}

impl DetailId {
    pub fn new(key: impl Into<String>, id: impl Into<String>) -> Self {
        let id = id.into();
        Self {
            key: key.into(),
            uuid: ShortId::parse_uuid(&id).ok(),
            id,
        }
    }

    /// Whether the detail value `value` names this id.
    fn is(&self, value: &str) -> bool {
        value == self.id
            || self
                .uuid
                .is_some_and(|uuid| ShortId::parse_uuid(value).is_ok_and(|other| other == uuid))
    }

    fn matches(&self, event: &AuditEvent) -> bool {
        if event
            .detail
            .get(&self.key)
            .is_some_and(|value| self.is(value))
        {
            return true;
        }
        event
            .detail
            .get(&format!("{}s", self.key))
            .is_some_and(|ids| ids.split(',').any(|id| self.is(id.trim())))
    }
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
        if !self.categories.is_empty() && !self.categories.contains(&event.action.category()) {
            return false;
        }
        if let Some(kind) = self.kind
            && event.action.kind() != kind
        {
            return false;
        }
        if !self.requesters.is_empty() && !self.requesters.contains(&event.requester()) {
            return false;
        }
        if !self.outcomes.is_empty() && !self.outcomes.contains(&event.outcome) {
            return false;
        }
        if let Some(detail_id) = &self.detail_id
            && !detail_id.matches(event)
        {
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
