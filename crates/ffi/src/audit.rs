use std::collections::HashMap;

use axo_pass_core::audit;
use axo_pass_core::core::protected_settings::ProtectedSettings;

use crate::*;

#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum AuditSourceKind {
    Agent,
    Pinentry,
    App,
    Cli,
    Askpass,
}

impl From<audit::Source> for AuditSourceKind {
    fn from(s: audit::Source) -> Self {
        match s {
            audit::Source::Agent => Self::Agent,
            audit::Source::Pinentry => Self::Pinentry,
            audit::Source::App => Self::App,
            audit::Source::Cli => Self::Cli,
            audit::Source::Askpass => Self::Askpass,
        }
    }
}

/// Who asked for an event. See `audit::Requester`.
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum AuditRequesterKind {
    App,
    Cli,
    Browser,
    Autofill,
    SshClient,
    GpgClient,
    Other,
}

impl From<audit::Requester> for AuditRequesterKind {
    fn from(r: audit::Requester) -> Self {
        match r {
            audit::Requester::App => Self::App,
            audit::Requester::Cli => Self::Cli,
            audit::Requester::Browser => Self::Browser,
            audit::Requester::Autofill => Self::Autofill,
            audit::Requester::SshClient => Self::SshClient,
            audit::Requester::GpgClient => Self::GpgClient,
            audit::Requester::Other => Self::Other,
        }
    }
}

impl From<AuditRequesterKind> for audit::Requester {
    fn from(r: AuditRequesterKind) -> Self {
        match r {
            AuditRequesterKind::App => Self::App,
            AuditRequesterKind::Cli => Self::Cli,
            AuditRequesterKind::Browser => Self::Browser,
            AuditRequesterKind::Autofill => Self::Autofill,
            AuditRequesterKind::SshClient => Self::SshClient,
            AuditRequesterKind::GpgClient => Self::GpgClient,
            AuditRequesterKind::Other => Self::Other,
        }
    }
}

/// Action category. See `audit::Category`.
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum AuditCategory {
    Ssh,
    Gpg,
    Age,
    Vault,
    Item,
    Credential,
    Passkey,
    Grant,
    Broker,
}

impl From<audit::Category> for AuditCategory {
    fn from(c: audit::Category) -> Self {
        match c {
            audit::Category::Ssh => Self::Ssh,
            audit::Category::Gpg => Self::Gpg,
            audit::Category::Age => Self::Age,
            audit::Category::Vault => Self::Vault,
            audit::Category::Item => Self::Item,
            audit::Category::Credential => Self::Credential,
            audit::Category::Passkey => Self::Passkey,
            audit::Category::Grant => Self::Grant,
            audit::Category::Broker => Self::Broker,
        }
    }
}

impl From<AuditCategory> for audit::Category {
    fn from(c: AuditCategory) -> Self {
        match c {
            AuditCategory::Ssh => Self::Ssh,
            AuditCategory::Gpg => Self::Gpg,
            AuditCategory::Age => Self::Age,
            AuditCategory::Vault => Self::Vault,
            AuditCategory::Item => Self::Item,
            AuditCategory::Credential => Self::Credential,
            AuditCategory::Passkey => Self::Passkey,
            AuditCategory::Grant => Self::Grant,
            AuditCategory::Broker => Self::Broker,
        }
    }
}

/// What an action does. See `audit::ActionKind`.
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum AuditActionKind {
    Access,
    Change,
    Other,
}

impl From<AuditActionKind> for audit::ActionKind {
    fn from(k: AuditActionKind) -> Self {
        match k {
            AuditActionKind::Access => Self::Access,
            AuditActionKind::Change => Self::Change,
            AuditActionKind::Other => Self::Other,
        }
    }
}

impl From<audit::ActionKind> for AuditActionKind {
    fn from(k: audit::ActionKind) -> Self {
        match k {
            audit::ActionKind::Access => Self::Access,
            audit::ActionKind::Change => Self::Change,
            audit::ActionKind::Other => Self::Other,
        }
    }
}

/// One audit action, for the audit log help.
#[derive(uniffi::Record)]
pub struct AuditActionInfo {
    /// Dotted action string, e.g. `ssh.sign`.
    pub action: String,
    pub category: AuditCategory,
    pub kind: AuditActionKind,
    pub description: String,
}

#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcomeKind {
    Succeeded,
    Cancelled,
    Denied,
    Failed,
}

impl From<audit::Outcome> for AuditOutcomeKind {
    fn from(o: audit::Outcome) -> Self {
        match o {
            audit::Outcome::Succeeded => Self::Succeeded,
            audit::Outcome::Cancelled => Self::Cancelled,
            audit::Outcome::Denied => Self::Denied,
            audit::Outcome::Failed => Self::Failed,
        }
    }
}

impl From<AuditOutcomeKind> for audit::Outcome {
    fn from(o: AuditOutcomeKind) -> Self {
        match o {
            AuditOutcomeKind::Succeeded => Self::Succeeded,
            AuditOutcomeKind::Cancelled => Self::Cancelled,
            AuditOutcomeKind::Denied => Self::Denied,
            AuditOutcomeKind::Failed => Self::Failed,
        }
    }
}

#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum AuditSubjectKind {
    SshKey,
    GpgKey,
    Credential,
    Item,
    Vault,
    AgeIdentity,
}

impl From<audit::SubjectKind> for AuditSubjectKind {
    fn from(k: audit::SubjectKind) -> Self {
        match k {
            audit::SubjectKind::SshKey => Self::SshKey,
            audit::SubjectKind::GpgKey => Self::GpgKey,
            audit::SubjectKind::Credential => Self::Credential,
            audit::SubjectKind::Item => Self::Item,
            audit::SubjectKind::Vault => Self::Vault,
            audit::SubjectKind::AgeIdentity => Self::AgeIdentity,
        }
    }
}

/// One audit record, flattened for Swift.
#[derive(uniffi::Record)]
pub struct AuditEventRecord {
    pub id: String,
    /// RFC 3339 timestamp.
    pub at: String,
    /// Process that wrote the event.
    pub source: AuditSourceKind,
    /// Who asked for the event.
    pub requester: AuditRequesterKind,
    /// Dotted action string, e.g. `ssh.sign`.
    pub action: String,
    pub outcome: AuditOutcomeKind,
    pub subject_kind: Option<AuditSubjectKind>,
    pub subject_id: Option<String>,
    pub subject_label: Option<String>,
    pub subject_fingerprint: Option<String>,
    pub caller: Option<String>,
    pub actor_pid: Option<u32>,
    pub actor_executable: Option<String>,
    pub actor_bundle_id: Option<String>,
    pub actor_team_id: Option<String>,
    pub actor_chain: Vec<String>,
    pub detail: HashMap<String, String>,
    pub message: Option<String>,
}

impl From<audit::AuditEvent> for AuditEventRecord {
    fn from(e: audit::AuditEvent) -> Self {
        let at = e.at_rfc3339();
        let requester = e.requester().into();
        let action = e.action.as_str().to_string();
        let (subject_kind, subject_id, subject_label, subject_fingerprint) = match e.subject {
            // The id is empty if the event was recorded without details.
            Some(s) => (
                Some(s.kind.into()),
                Some(s.id).filter(|id| !id.is_empty()),
                s.label,
                s.fingerprint,
            ),
            None => (None, None, None, None),
        };
        let actor = e.actor.unwrap_or_default();
        AuditEventRecord {
            id: e.id.to_string(),
            at,
            source: e.source.into(),
            requester,
            action,
            outcome: e.outcome.into(),
            subject_kind,
            subject_id,
            subject_label,
            subject_fingerprint,
            caller: actor.caller,
            actor_pid: actor.pid,
            actor_executable: actor.executable,
            actor_bundle_id: actor.bundle_id,
            actor_team_id: actor.team_id,
            actor_chain: actor.chain,
            detail: e.detail.into_iter().collect(),
            message: e.message,
        }
    }
}

/// Filter for `list_audit_events`. Empty fields mean no constraint.
#[derive(uniffi::Record)]
pub struct AuditFilterInput {
    pub since_rfc3339: Option<String>,
    pub until_rfc3339: Option<String>,
    /// Dotted action strings. Unknown values are ignored.
    pub actions: Vec<String>,
    pub categories: Vec<AuditCategory>,
    pub kind: Option<AuditActionKind>,
    pub requesters: Vec<AuditRequesterKind>,
    pub outcomes: Vec<AuditOutcomeKind>,
    pub query: Option<String>,
    /// Entity id to match in the event detail. See `audit::DetailId`.
    pub detail_id: Option<AuditDetailIdInput>,
    pub limit: Option<u32>,
    pub offset: u32,
}

/// Entity id to match in the event detail, such as a `passkey_credential_id`.
/// See `audit::DetailId`.
#[derive(uniffi::Record)]
pub struct AuditDetailIdInput {
    /// Detail key of a single id, such as `passkey_credential_id`.
    pub key: String,
    pub id: String,
}

impl From<AuditFilterInput> for audit::AuditFilter {
    fn from(input: AuditFilterInput) -> Self {
        audit::AuditFilter {
            since: input
                .since_rfc3339
                .as_deref()
                .and_then(audit::parse_rfc3339),
            until: input
                .until_rfc3339
                .as_deref()
                .and_then(audit::parse_rfc3339),
            actions: input
                .actions
                .iter()
                .filter_map(|a| audit::Action::parse(a))
                .collect(),
            categories: input.categories.into_iter().map(Into::into).collect(),
            kind: input.kind.map(Into::into),
            requesters: input.requesters.into_iter().map(Into::into).collect(),
            outcomes: input.outcomes.into_iter().map(Into::into).collect(),
            query: input.query.filter(|q| !q.is_empty()),
            detail_id: input.detail_id.map(|d| audit::DetailId::new(d.key, d.id)),
            limit: input.limit.map(|l| l as usize),
            offset: input.offset as usize,
        }
    }
}

/// Which grant lifecycle event the app is recording.
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum GrantEventKind {
    Created,
    Reused,
    Expired,
}

/// Which kind of key a grant is for.
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum GrantSubjectKind {
    SshKey,
    GpgKey,
    Vault,
    AgeIdentity,
}

/// Identifies the key a grant event is about. `id` is the canonical
/// `SHA256:...` fingerprint for an SSH key and the keygrip for a GPG key, so a
/// grant event names its key the same way the agent's `ssh.sign` or the
/// pinentry's own events do.
#[derive(uniffi::Record, Clone)]
pub struct GrantSubjectInput {
    pub kind: GrantSubjectKind,
    pub id: String,
    pub label: Option<String>,
}

/// Which vault state transition the app is recording.
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum VaultEventKind {
    Unlocked,
    Locked,
    Autolocked,
}

#[uniffi::export(async_runtime = "tokio")]
impl AxoPass {
    /// Read audit events, newest first. Not gated on an unlocked vault: the
    /// file is plaintext and readable by anything running as this user.
    pub async fn list_audit_events(
        &self,
        filter: AuditFilterInput,
    ) -> Result<Vec<AuditEventRecord>, FfiError> {
        let filter: audit::AuditFilter = filter.into();
        let page = tokio::task::spawn_blocking(move || audit::read(&filter))
            .await
            .map_err(|e| FfiError::Internal(e.to_string()))?;
        Ok(page.events.into_iter().map(Into::into).collect())
    }

    /// Every audit action with its category, kind, and description, grouped
    /// by category in display order.
    pub fn audit_actions(&self) -> Vec<AuditActionInfo> {
        audit::Action::ALL
            .iter()
            .map(|action| AuditActionInfo {
                action: action.as_str().to_string(),
                category: action.category().into(),
                kind: action.kind().into(),
                description: action.description().to_string(),
            })
            .collect()
    }

    /// Path of the current month's audit file, for a "Reveal in Finder"
    /// button.
    pub fn audit_log_path(&self) -> String {
        audit::audit_log_path().display().to_string()
    }

    /// Whether the audit log records names, paths, and hosts. Stored in the
    /// protected settings in the keychain, which `ap` reads through the app on
    /// every write.
    pub fn audit_include_details(&self) -> bool {
        ProtectedSettings::load().audit_include_details
    }

    /// Turn recording of account details in the audit log on or off. Does not
    /// change events already written. See `clear_audit_details`.
    pub fn set_audit_include_details(&self, on: bool) -> Result<(), FfiError> {
        ProtectedSettings::update(|settings| settings.audit_include_details = on)
            .map(|_| ())
            .map_err(|e| FfiError::Internal(e.to_string()))
    }

    /// Rewrite the audit files without account details. Returns the number of
    /// events changed.
    pub async fn clear_audit_details(&self) -> Result<u64, FfiError> {
        tokio::task::spawn_blocking(audit::clear_details)
            .await
            .map_err(|e| FfiError::Internal(e.to_string()))?
            .map(|changed| changed as u64)
            .map_err(|e| FfiError::Internal(e.to_string()))
    }

    /// Record a grant lifecycle event. These explain why a key use raised no
    /// prompt: the agent logs the signature, the app logs the reused grant.
    ///
    /// `scope` names the operation the grant covers when one subject carries
    /// more than one, e.g. `list` and `read` against the same vault. Nil where
    /// the subject is the whole grant.
    ///
    /// `peer` is the process the broker verified when it served the request
    /// that created or reused the grant, so a grant event describes the
    /// requester as fully as the key-use event it explains. An expiry carries
    /// the last requester, since nothing is in flight when the clock runs out.
    /// Falls back to `caller` alone when the app has no peer for the grant.
    pub fn record_grant_event(
        &self,
        kind: GrantEventKind,
        subject: GrantSubjectInput,
        caller: Option<String>,
        scope: Option<String>,
        peer: Option<RequestActor>,
    ) {
        let action = match kind {
            GrantEventKind::Created => audit::Action::AuthGrantCreated,
            GrantEventKind::Reused => audit::Action::AuthGrantReused,
            GrantEventKind::Expired => audit::Action::AuthGrantExpired,
        };
        let actor = match peer {
            Some(peer) => Some(audit::Actor::from(peer)),
            None => caller.map(|caller| audit::Actor {
                caller: Some(caller),
                ..Default::default()
            }),
        };

        let subject_kind = match subject.kind {
            GrantSubjectKind::SshKey => audit::SubjectKind::SshKey,
            GrantSubjectKind::GpgKey => audit::SubjectKind::GpgKey,
            GrantSubjectKind::Vault => audit::SubjectKind::Vault,
            GrantSubjectKind::AgeIdentity => audit::SubjectKind::AgeIdentity,
        };
        // An SSH fingerprint arrives with or without the `SHA256:` prefix
        // depending on the path that produced it. Normalize to the canonical
        // form so it matches the agent's `ssh.sign` events.
        let id = match subject.kind {
            GrantSubjectKind::SshKey
                if !subject.id.starts_with("SHA256:") && !subject.id.starts_with("ssh-key-") =>
            {
                format!("SHA256:{}", subject.id)
            },
            _ => subject.id,
        };
        let mut s = audit::Subject::new(subject_kind, id.clone());
        // For an SSH key the id is the canonical fingerprint. Record it in the
        // fingerprint field too, so it matches the agent's `ssh.sign` events.
        if subject.kind == GrantSubjectKind::SshKey && id.starts_with("SHA256:") {
            s = s.fingerprint(id);
        }
        if let Some(label) = subject.label.filter(|l| !l.is_empty()) {
            s = s.label(label);
        }

        // A subject alone does not identify a grant: one vault carries a
        // separate grant per action, so the scope is what tells a listing's
        // approval from a read's.
        audit::record(
            audit::AuditEvent::new(audit::process_source(), action, audit::Outcome::Succeeded)
                .maybe_subject(Some(s))
                .maybe_actor(actor)
                .maybe_detail("scope", scope.filter(|s| !s.is_empty())),
        );
    }

    /// Record a vault state transition the app drives. `trigger` names the
    /// cause of an automatic lock (`timer`, `sleep`, `screen_lock`).
    pub fn record_vault_event(&self, kind: VaultEventKind, trigger: Option<String>) {
        let action = match kind {
            VaultEventKind::Unlocked => audit::Action::VaultUnlock,
            VaultEventKind::Locked => audit::Action::VaultLock,
            VaultEventKind::Autolocked => audit::Action::VaultAutolock,
        };
        let mut event =
            audit::AuditEvent::new(audit::process_source(), action, audit::Outcome::Succeeded);
        if let Some(trigger) = trigger {
            event = event.detail("trigger", trigger);
        }
        audit::record(event);
    }
}
