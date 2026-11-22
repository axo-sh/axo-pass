//! Audit events of the sync transaction.
//!
//! A transaction queues its events as it runs and records them after its
//! saves, so a transaction that fails records none. Events hold ids, replica
//! ids, counts, and cause names. They never hold a secret value, a title, a
//! name, or an error text.

use std::collections::BTreeSet;
use std::path::Path;

use uuid::Uuid;

use super::apply::ApplyReport;
use super::crdt::ReplicaId;
use super::load::SyncLoad;
use super::resolve::ResolveReport;
use super::sidecar::{Health, LoadFailure, Sidecar};
use super::status::PausedCause;
use super::view::{AskRegister, Entity};
use crate::audit::{self, Action, AuditEvent, Outcome, SubjectIds};

/// Cause of the `sync.repair` event of a rebuilt vault.
const REBUILT: &str = "rebuilt from sync state";

/// Audit events of one transaction, not yet recorded.
#[derive(Debug)]
pub(crate) struct SyncEvents {
    vault_id: Uuid,
    events: Vec<AuditEvent>,
}

impl SyncEvents {
    pub(crate) fn new(vault_id: Uuid) -> Self {
        Self {
            vault_id,
            events: Vec::new(),
        }
    }

    fn event(&self, action: Action, outcome: Outcome) -> AuditEvent {
        AuditEvent::new(audit::process_source(), action, outcome)
            .subject_ids(SubjectIds::vault(self.vault_id))
    }

    /// Changes of the view that the transaction applied from the files of
    /// `sources`. The state does not record which Mac purged an entry, so
    /// `sync.deleted_by_peer` names the Macs whose files were joined.
    ///
    /// `sync.applied` marks the items that gained a website and the items
    /// whose role slots changed.
    pub(crate) fn applied(&mut self, sources: &BTreeSet<ReplicaId>, report: &ApplyReport) {
        if sources.is_empty() {
            return;
        }
        let sources = list(sources.iter().map(|replica| replica.0));
        let changed: Vec<Entity> = report
            .changed
            .iter()
            .filter(|entity| !report.purged.contains(entity))
            .copied()
            .collect();
        if !changed.is_empty() {
            let mut event = self
                .event(Action::SyncApplied, Outcome::Succeeded)
                .detail("source_replicas", sources.clone())
                .detail("changes", changed.len().to_string());
            event = with_entities(event, &changed);
            if !report.websites_added.is_empty() {
                let items = list(report.websites_added.iter());
                event = event.detail("websites_added_item_ids", items);
            }
            if !report.slots_changed.is_empty() {
                let items = list(report.slots_changed.iter());
                event = event.detail("slots_changed_item_ids", items);
            }
            self.events.push(event);
        }
        if !report.purged.is_empty() {
            let purged: Vec<Entity> = report.purged.iter().copied().collect();
            let event = self
                .event(Action::SyncDeletedByPeer, Outcome::Succeeded)
                .detail("source_replicas", sources)
                .detail("purged", purged.len().to_string());
            self.events.push(with_entities(event, &purged));
        }
    }

    /// The vault was rebuilt from the sync state.
    pub(crate) fn rebuilt(&mut self) {
        self.repair(REBUILT);
    }

    /// A repair of `cause` ran.
    pub(crate) fn repair(&mut self, cause: &str) {
        let event = self
            .event(Action::SyncRepair, Outcome::Succeeded)
            .detail("cause", cause);
        self.events.push(event);
    }

    /// The latest repair added `differences` vault differences to the state.
    pub(crate) fn repair_differences(&mut self, differences: usize) {
        let latest = self
            .events
            .iter_mut()
            .rev()
            .find(|event| event.action == Action::SyncRepair);
        if let Some(event) = latest {
            event
                .detail
                .insert("differences".to_string(), differences.to_string());
        }
    }

    /// Drop the repairs, resumes, and resolved conflicts of this transaction,
    /// after its joins, repair, and edits are discarded. A rebuild is kept,
    /// since the rebuilt vault is still saved.
    pub(crate) fn discard_writes(&mut self) {
        self.events.retain(|e| match e.action {
            Action::SyncRepair => e.detail.get("cause").is_some_and(|c| c == REBUILT),
            Action::SyncResumed | Action::SyncConflictResolved => false,
            _ => true,
        });
    }

    /// Ask registers that edits wrote over concurrent values.
    pub(crate) fn conflicts_resolved(&mut self, resolved: &[ResolveReport]) {
        for report in resolved {
            let register = report.register;
            let mut event = self
                .event(Action::SyncConflictResolved, Outcome::Succeeded)
                .detail("register", register_name(register.register))
                .detail("superseded", report.not_chosen.len().to_string());
            event = with_entities(event, &[register.entity]);
            let values = report.not_chosen.iter().map(|value| {
                let replica = value
                    .replica
                    .map_or("unknown".to_string(), |r| r.0.to_string());
                format!("{replica}@{}", value.written_at)
            });
            event = event.detail("superseded_values", values.collect::<Vec<_>>().join(","));
            self.events.push(event);
        }
    }

    /// Sync stopped for `cause`, with `edits` edits found by the guard.
    pub(crate) fn stopped(&mut self, cause: &str, edits: Option<usize>) {
        let mut event = self
            .event(Action::SyncStopped, Outcome::Failed)
            .detail("cause", cause);
        if let Some(edits) = edits {
            event = event.detail("edits", edits.to_string());
        }
        self.events.push(event);
    }

    /// Sync resumed. A transaction records one resume at most.
    pub(crate) fn resumed(&mut self) {
        if self.events.iter().any(|e| e.action == Action::SyncResumed) {
            return;
        }
        let event = self.event(Action::SyncResumed, Outcome::Succeeded);
        self.events.push(event);
    }

    /// Health changed from `before` to `after`. A change of an error text
    /// alone records nothing. A change to `Ok` resumes sync, a change to
    /// `Paused` records the cause names, and a change to `Failed` records the
    /// failure.
    pub(crate) fn health_changed(&mut self, before: &Health, after: &Health) {
        if before.same_event(after) {
            return;
        }
        match after {
            Health::Ok => self.resumed(),
            Health::Paused { causes } => {
                let names: BTreeSet<&str> = causes.iter().map(PausedCause::name).collect();
                let names = names.into_iter().collect::<Vec<_>>().join(",");
                let event = self
                    .event(Action::SyncPaused, Outcome::Failed)
                    .detail("causes", names);
                self.events.push(event);
            },
            Health::Failed {
                failure: LoadFailure::StateMissing,
            } => {
                let event = self
                    .event(Action::SyncLocalFileMissing, Outcome::Failed)
                    .detail("file", "sync state");
                self.events.push(event);
            },
            Health::Failed {
                failure: LoadFailure::SignatureFailed,
            } => self.stopped("signature failed", None),
        }
    }

    /// Record the events of a health change outside a transaction.
    pub(crate) fn record_health_change(vault_id: Uuid, before: &Health, after: &Health) {
        let mut events = Self::new(vault_id);
        events.health_changed(before, after);
        events.record();
    }

    /// A state file of `replica` was quarantined.
    pub(crate) fn file_quarantined(&mut self, replica: ReplicaId, file: &str) {
        let event = self
            .event(Action::SyncFileQuarantined, Outcome::Failed)
            .detail("replica", replica.0.to_string())
            .detail("file", file);
        self.events.push(event);
    }

    /// Record the failure to load the sync state of vault `vault_id` as `case`,
    /// which stops the transaction before any sync step. The sidecar under
    /// `root` holds the last failure recorded, so a vault that keeps failing
    /// the same way records one event. A case that is not a load failure
    /// records nothing and reads no file.
    pub(crate) fn load_failed(root: &Path, vault_id: Uuid, case: &SyncLoad) {
        let failure = match case {
            SyncLoad::StateMissing => LoadFailure::StateMissing,
            SyncLoad::SignatureFailed(_) => LoadFailure::SignatureFailed,
            _ => return,
        };
        let Ok(mut sidecar) = Sidecar::read(root, vault_id) else {
            return;
        };
        let after = Health::Failed { failure };
        if sidecar.health.same_event(&after) {
            return;
        }
        let before = std::mem::replace(&mut sidecar.health, after);
        if let Err(e) = sidecar.save(root, vault_id) {
            log::warn!("Failed to save the load failure of vault {vault_id}: {e}");
        }
        Self::record_health_change(vault_id, &before, &sidecar.health);
    }

    /// Queued events. None are left queued in `self`.
    pub(crate) fn take(&mut self) -> Self {
        Self {
            vault_id: self.vault_id,
            events: std::mem::take(&mut self.events),
        }
    }

    /// Record the queued events. A test records them only on a thread that
    /// holds an audit test directory.
    pub(crate) fn record(&mut self) {
        #[cfg(test)]
        if !audit::test_support::held() {
            self.events.clear();
        }
        for event in self.events.drain(..) {
            audit::record(event);
        }
    }
}

impl PausedCause {
    /// Name of the cause, without its error text.
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::Unreachable { .. } => "unreachable",
            Self::PublishFailed { .. } => "publish_failed",
            Self::Quarantined { .. } => "quarantined",
            Self::VersionSkew { .. } => "version_skew",
            Self::ApplyFailed { .. } => "apply_failed",
            Self::DiffFailed { .. } => "diff_failed",
            Self::KeyMissing { .. } => "key_missing",
            Self::SeparateKey { .. } => "separate_key",
        }
    }
}

fn register_name(register: AskRegister) -> &'static str {
    match register {
        AskRegister::Name => "name",
        AskRegister::Title => "title",
        AskRegister::Category => "category",
        AskRegister::Key => "key",
        AskRegister::Username => "username",
        AskRegister::Password => "password",
        AskRegister::Totp => "totp",
        AskRegister::Kind => "kind",
        AskRegister::Value => "value",
    }
}

/// Comma-separated ids.
fn list<T: ToString>(ids: impl Iterator<Item = T>) -> String {
    ids.map(|id| id.to_string()).collect::<Vec<_>>().join(",")
}

/// Add the item ids and credential ids of `entities` to `event`, and
/// `vault_changed` if they include the vault.
fn with_entities(mut event: AuditEvent, entities: &[Entity]) -> AuditEvent {
    let items = list(entities.iter().filter_map(|e| match e {
        Entity::Item(id) => Some(id),
        _ => None,
    }));
    let credentials = list(entities.iter().filter_map(|e| match e {
        Entity::Credential(id) => Some(id),
        _ => None,
    }));
    if !items.is_empty() {
        event = event.detail("item_ids", items);
    }
    if !credentials.is_empty() {
        event = event.detail("credential_ids", credentials);
    }
    if entities.contains(&Entity::Vault) {
        event = event.detail("vault_changed", "true");
    }
    event
}
