//! The audit event schema.
//!
//! An `AuditEvent` records one use of a key or secret: who asked, for what,
//! and how it ended. Values are never recorded, only identifiers and labels.
//! Bytes being signed, passphrases, credential values, age plaintext, session
//! ids and vault file keys must never appear in any field.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU8, Ordering};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

/// The current schema version. Bump when a field changes meaning.
pub const SCHEMA_VERSION: u8 = 1;

/// One audit record. Serialized as a single JSON line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Schema version.
    pub v: u8,

    /// Event id. A v7 UUID, so ids sort by creation time.
    pub id: Uuid,

    /// When the event was recorded.
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,

    /// The process that wrote the event.
    pub source: Source,

    /// What happened.
    pub action: Action,

    /// How it ended.
    pub outcome: Outcome,

    /// The thing that was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<Subject>,

    /// Who asked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<Actor>,

    /// Action-specific, always non-secret, key/value detail.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub detail: BTreeMap<String, String>,

    /// Error text for `Failed` and `Denied` outcomes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl AuditEvent {
    /// Start a new event, stamped now with a fresh id.
    pub fn new(source: Source, action: Action, outcome: Outcome) -> Self {
        AuditEvent {
            v: SCHEMA_VERSION,
            id: Uuid::now_v7(),
            at: OffsetDateTime::now_utc(),
            source,
            action,
            outcome,
            subject: None,
            actor: None,
            detail: BTreeMap::new(),
            message: None,
        }
    }

    pub fn subject(mut self, subject: Subject) -> Self {
        self.subject = Some(subject);
        self
    }

    pub fn maybe_subject(mut self, subject: Option<Subject>) -> Self {
        self.subject = subject;
        self
    }

    pub fn actor(mut self, actor: Actor) -> Self {
        self.actor = Some(actor);
        self
    }

    pub fn maybe_actor(mut self, actor: Option<Actor>) -> Self {
        self.actor = actor;
        self
    }

    pub fn detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.detail.insert(key.into(), value.into());
        self
    }

    pub fn maybe_detail(
        mut self,
        key: impl Into<String>,
        value: Option<impl Into<String>>,
    ) -> Self {
        if let Some(value) = value {
            self.detail.insert(key.into(), value.into());
        }
        self
    }

    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    /// The timestamp as an RFC 3339 string.
    pub fn at_rfc3339(&self) -> String {
        self.at.format(&Rfc3339).unwrap_or_default()
    }
}

/// Parse an RFC 3339 timestamp, for filter inputs crossing the FFI boundary.
pub fn parse_rfc3339(s: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(s, &Rfc3339).ok()
}

/// The process that recorded the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// The SSH agent, `ap ssh-agent`.
    Agent,
    /// The pinentry helper, `ap pinentry`.
    Pinentry,
    /// The SwiftUI app.
    App,
    /// Any other `ap` subcommand.
    Cli,
    /// The SSH askpass helper, `ap ssh-askpass`.
    Askpass,
}

impl Source {
    fn from_u8(v: u8) -> Source {
        match v {
            0 => Source::Agent,
            1 => Source::Pinentry,
            2 => Source::App,
            4 => Source::Askpass,
            _ => Source::Cli,
        }
    }
}

/// The source stamped on events that do not name one themselves. Set once at
/// process start: the app sets `App`, `ap` sets `Cli`, the agent and pinentry
/// name themselves per event.
static PROCESS_SOURCE: AtomicU8 = AtomicU8::new(3);

/// Record which process this is, for events that call [`process_source`].
pub fn set_process_source(source: Source) {
    PROCESS_SOURCE.store(source as u8, Ordering::Relaxed);
}

/// The current process's default event source.
pub fn process_source() -> Source {
    Source::from_u8(PROCESS_SOURCE.load(Ordering::Relaxed))
}

/// How an event ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Completed successfully.
    Succeeded,
    /// The user dismissed a prompt.
    Cancelled,
    /// Rejected by policy or a key constraint.
    Denied,
    /// An error stopped it.
    Failed,
}

/// What happened. Serialized as a dotted string, e.g. `ssh.sign`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    #[serde(rename = "ssh.sign")]
    SshSign,
    #[serde(rename = "ssh.passphrase")]
    SshPassphrase,
    #[serde(rename = "ssh.key_add")]
    SshKeyAdd,
    #[serde(rename = "ssh.key_remove")]
    SshKeyRemove,
    #[serde(rename = "ssh.session_bind")]
    SshSessionBind,
    #[serde(rename = "ssh.agent_start")]
    SshAgentStart,
    #[serde(rename = "ssh.agent_stop")]
    SshAgentStop,

    #[serde(rename = "gpg.passphrase")]
    GpgPassphrase,
    #[serde(rename = "gpg.confirm")]
    GpgConfirm,
    #[serde(rename = "gpg.message")]
    GpgMessage,
    #[serde(rename = "gpg.passphrase_saved")]
    GpgPassphraseSaved,
    #[serde(rename = "gpg.agent_conf_changed")]
    GpgAgentConfChanged,

    #[serde(rename = "secret.read")]
    SecretRead,
    #[serde(rename = "secret.inject")]
    SecretInject,
    #[serde(rename = "secret.exec")]
    SecretExec,
    #[serde(rename = "age.decrypt")]
    AgeDecrypt,
    #[serde(rename = "age.encrypt")]
    AgeEncrypt,

    #[serde(rename = "vault.unlock")]
    VaultUnlock,
    #[serde(rename = "vault.lock")]
    VaultLock,
    #[serde(rename = "vault.autolock")]
    VaultAutolock,
    #[serde(rename = "vault.item_created")]
    VaultItemCreated,
    #[serde(rename = "vault.item_updated")]
    VaultItemUpdated,
    #[serde(rename = "vault.item_deleted")]
    VaultItemDeleted,
    #[serde(rename = "vault.created")]
    VaultCreated,
    #[serde(rename = "vault.exported")]
    VaultExported,
    #[serde(rename = "vault.imported")]
    VaultImported,

    #[serde(rename = "auth.grant_created")]
    AuthGrantCreated,
    #[serde(rename = "auth.grant_reused")]
    AuthGrantReused,
    #[serde(rename = "auth.grant_expired")]
    AuthGrantExpired,

    #[serde(rename = "broker.peer_rejected")]
    BrokerPeerRejected,
}

impl Action {
    /// The dotted string form, matching the serde representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::SshSign => "ssh.sign",
            Action::SshPassphrase => "ssh.passphrase",
            Action::SshKeyAdd => "ssh.key_add",
            Action::SshKeyRemove => "ssh.key_remove",
            Action::SshSessionBind => "ssh.session_bind",
            Action::SshAgentStart => "ssh.agent_start",
            Action::SshAgentStop => "ssh.agent_stop",
            Action::GpgPassphrase => "gpg.passphrase",
            Action::GpgConfirm => "gpg.confirm",
            Action::GpgMessage => "gpg.message",
            Action::GpgPassphraseSaved => "gpg.passphrase_saved",
            Action::GpgAgentConfChanged => "gpg.agent_conf_changed",
            Action::SecretRead => "secret.read",
            Action::SecretInject => "secret.inject",
            Action::SecretExec => "secret.exec",
            Action::AgeDecrypt => "age.decrypt",
            Action::AgeEncrypt => "age.encrypt",
            Action::VaultUnlock => "vault.unlock",
            Action::VaultLock => "vault.lock",
            Action::VaultAutolock => "vault.autolock",
            Action::VaultItemCreated => "vault.item_created",
            Action::VaultItemUpdated => "vault.item_updated",
            Action::VaultItemDeleted => "vault.item_deleted",
            Action::VaultCreated => "vault.created",
            Action::VaultExported => "vault.exported",
            Action::VaultImported => "vault.imported",
            Action::AuthGrantCreated => "auth.grant_created",
            Action::AuthGrantReused => "auth.grant_reused",
            Action::AuthGrantExpired => "auth.grant_expired",
            Action::BrokerPeerRejected => "broker.peer_rejected",
        }
    }

    /// Parse the dotted string form.
    pub fn parse(s: &str) -> Option<Self> {
        serde_json::from_value(serde_json::Value::String(s.to_string())).ok()
    }
}

/// The kind of thing a `Subject` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    SshKey,
    GpgKey,
    Credential,
    Vault,
    AgeIdentity,
}

/// The thing that was used. Names it, never its value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    pub kind: SubjectKind,

    /// A stable identifier: key label, keygrip, `vault/item/credential`, or a
    /// vault key.
    pub id: String,

    /// A comment or title, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// SHA-256 fingerprint, for SSH keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

impl Subject {
    pub fn new(kind: SubjectKind, id: impl Into<String>) -> Self {
        Subject {
            kind,
            id: id.into(),
            label: None,
            fingerprint: None,
        }
    }

    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    pub fn maybe_label(mut self, label: Option<String>) -> Self {
        self.label = label;
        self
    }

    pub fn fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.fingerprint = Some(fingerprint.into());
        self
    }
}

/// Who asked, resolved from a verified caller chain.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Actor {
    /// The rendered caller string, e.g. `VS Code (git)`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,

    /// Bundle identifier, from the code signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle_id: Option<String>,

    /// Team identifier, from the code signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,

    /// The user-visible process chain, innermost first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<String>,
}
