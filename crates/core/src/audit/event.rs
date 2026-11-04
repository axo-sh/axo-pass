//! The audit event schema.
//!
//! An `AuditEvent` records one use of a key or secret: who asked, for what,
//! and how it ended. Values are never recorded, only identifiers and labels.
//! Bytes being signed, passphrases, credential values, age plaintext, session
//! ids and vault file keys must never appear in any field.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::core::app_broker::{
    AGENT_EXECUTABLE_NAME, AUTOFILL_EXTENSION_NAME, BROWSER_HOST_EXECUTABLE_NAME,
};
use crate::core::provenance::ProcessNode;
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::passkey;

/// The current schema version. Bump when a field changes meaning.
pub const SCHEMA_VERSION: u8 = 1;

/// Detail key of the WebAuthn credential id of a passkey, in base64url without
/// padding. The id is unchanged by renames and by moves between vaults.
pub const PASSKEY_CREDENTIAL_ID: &str = "passkey_credential_id";

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

/// Ids of the vault, item, and credential an event names. Ids stay the same
/// across renames and moves, unlike the key path in the subject.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SubjectIds {
    pub vault_id: Option<Uuid>,
    pub item_id: Option<Uuid>,
    pub credential_id: Option<Uuid>,
}

impl SubjectIds {
    pub fn vault(vault_id: Uuid) -> Self {
        Self {
            vault_id: Some(vault_id),
            ..Self::default()
        }
    }

    pub fn item(vault_id: Uuid, item_id: Uuid) -> Self {
        Self {
            item_id: Some(item_id),
            ..Self::vault(vault_id)
        }
    }

    pub fn credential(vault_id: Uuid, item_id: Uuid, credential_id: Uuid) -> Self {
        Self {
            credential_id: Some(credential_id),
            ..Self::item(vault_id, item_id)
        }
    }
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

    /// Record this event from an async context. See `audit::record_async`.
    pub async fn record_async(self) {
        super::record_async(self).await
    }

    /// Record the vault, item, and credential ids of the subject in `detail`,
    /// as short ids.
    pub fn subject_ids(self, ids: SubjectIds) -> Self {
        self.maybe_id("vault_id", ids.vault_id)
            .maybe_id("item_id", ids.item_id)
            .maybe_id("credential_id", ids.credential_id)
    }

    /// Record `id` in `detail` as a short id, if set.
    pub fn maybe_id(self, key: impl Into<String>, id: Option<Uuid>) -> Self {
        self.maybe_detail(key, id.map(ShortId::encode_uuid))
    }

    /// Record the WebAuthn credential id of a passkey under
    /// [`PASSKEY_CREDENTIAL_ID`].
    pub fn passkey_credential_id(self, id: &[u8]) -> Self {
        self.detail(PASSKEY_CREDENTIAL_ID, passkey::encode_credential_id(id))
    }

    /// Record the WebAuthn credential ids of several passkeys as a
    /// comma-separated list under the plural of [`PASSKEY_CREDENTIAL_ID`].
    /// Records nothing if `ids` is empty.
    pub fn passkey_credential_ids<'a>(self, ids: impl IntoIterator<Item = &'a [u8]>) -> Self {
        let list: Vec<String> = ids.into_iter().map(passkey::encode_credential_id).collect();
        self.maybe_detail(
            format!("{PASSKEY_CREDENTIAL_ID}s"),
            (!list.is_empty()).then(|| list.join(",")),
        )
    }

    /// The timestamp as an RFC 3339 string.
    pub fn at_rfc3339(&self) -> String {
        self.at.format(&Rfc3339).unwrap_or_default()
    }

    /// Who asked for the event. An app event is named by the verified peer
    /// executable in its actor. The SSH agent and pinentry also run as `ap`, so
    /// an `ap` event about a GPG key, or one that uses or grants an SSH key,
    /// names a GPG or SSH client. An `ap` event that changes an SSH key names
    /// the CLI.
    pub fn requester(&self) -> Requester {
        match self.source {
            Source::Cli => return Requester::Cli,
            // `ap ssh-agent start` and `stop` run the agent lifecycle.
            Source::Agent
                if matches!(self.action, Action::SshAgentStart | Action::SshAgentStop) =>
            {
                return Requester::Cli;
            },
            Source::Agent | Source::Askpass => return Requester::SshClient,
            Source::Pinentry => return Requester::GpgClient,
            Source::App => {},
        }
        let Some(actor) = &self.actor else {
            return Requester::App;
        };
        let executable = actor
            .executable
            .as_deref()
            .and_then(|path| Path::new(path).file_name())
            .and_then(|name| name.to_str());
        let key_client = match self.subject.as_ref().map(|s| s.kind) {
            Some(SubjectKind::SshKey) => Some(Requester::SshClient),
            Some(SubjectKind::GpgKey) => Some(Requester::GpgClient),
            _ => None,
        };
        match (executable, key_client) {
            // `ap` has no GPG commands, so an `ap` event about a GPG key comes
            // from pinentry.
            (Some(AGENT_EXECUTABLE_NAME), Some(Requester::GpgClient)) => Requester::GpgClient,
            (Some(AGENT_EXECUTABLE_NAME), Some(client))
                if self.action.kind() != ActionKind::Change =>
            {
                client
            },
            (Some(AGENT_EXECUTABLE_NAME), _) => Requester::Cli,
            (Some(BROWSER_HOST_EXECUTABLE_NAME), _) => Requester::Browser,
            (Some(AUTOFILL_EXTENSION_NAME), _) => Requester::Autofill,
            (_, Some(client)) => client,
            _ => Requester::Other,
        }
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
    #[serde(rename = "ssh.managed_key_create")]
    SshManagedKeyCreate,
    #[serde(rename = "ssh.managed_key_delete")]
    SshManagedKeyDelete,
    #[serde(rename = "ssh.app_grant_add")]
    SshAppGrantAdd,
    #[serde(rename = "ssh.app_grant_remove")]
    SshAppGrantRemove,
    #[serde(rename = "ssh.session_bind")]
    SshSessionBind,
    #[serde(rename = "ssh.passphrase_deleted")]
    SshPassphraseDeleted,
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
    #[serde(rename = "gpg.passphrase_deleted")]
    GpgPassphraseDeleted,
    #[serde(rename = "gpg.agent_conf_changed")]
    GpgAgentConfChanged,

    #[serde(rename = "age.decrypt")]
    AgeDecrypt,
    #[serde(rename = "age.encrypt")]
    AgeEncrypt,
    #[serde(rename = "age.key_create")]
    AgeKeyCreate,
    #[serde(rename = "age.key_delete")]
    AgeKeyDelete,

    #[serde(rename = "vault.unlock")]
    VaultUnlock,
    #[serde(rename = "vault.lock")]
    VaultLock,
    #[serde(rename = "vault.autolock")]
    VaultAutolock,
    #[serde(rename = "vault.created")]
    VaultCreated,
    #[serde(rename = "vault.updated")]
    VaultUpdated,
    #[serde(rename = "vault.deleted")]
    VaultDeleted,
    #[serde(rename = "vault.linked")]
    VaultLinked,
    #[serde(rename = "vault.exported")]
    VaultExported,
    #[serde(rename = "vault.imported")]
    VaultImported,
    #[serde(rename = "vault.version_restored")]
    VaultVersionRestored,
    #[serde(rename = "vault.versions_erased")]
    VaultVersionsErased,
    #[serde(rename = "vault.unreadable_moved")]
    VaultUnreadableMoved,
    #[serde(rename = "vault.resigned")]
    VaultResigned,

    #[serde(rename = "item.listed")]
    ItemListed,
    #[serde(rename = "item.created")]
    ItemCreated,
    #[serde(rename = "item.updated")]
    ItemUpdated,
    #[serde(rename = "item.deleted")]
    ItemDeleted,
    #[serde(rename = "item.restored")]
    ItemRestored,
    #[serde(rename = "item.purged")]
    ItemPurged,
    #[serde(rename = "item.merged")]
    ItemMerged,
    #[serde(rename = "item.websites_changed")]
    ItemWebsitesChanged,
    #[serde(rename = "item.converted")]
    ItemConverted,

    #[serde(rename = "credential.read")]
    CredentialRead,
    #[serde(rename = "credential.exec")]
    CredentialExec,
    #[serde(rename = "credential.inject")]
    CredentialInject,
    #[serde(rename = "credential.created")]
    CredentialCreated,
    #[serde(rename = "credential.updated")]
    CredentialUpdated,
    #[serde(rename = "credential.deleted")]
    CredentialDeleted,
    #[serde(rename = "credential.restored")]
    CredentialRestored,
    #[serde(rename = "credential.purged")]
    CredentialPurged,
    #[serde(rename = "credential.history_restored")]
    CredentialHistoryRestored,
    #[serde(rename = "credential.history_purged")]
    CredentialHistoryPurged,
    #[serde(rename = "credential.role_changed")]
    CredentialRoleChanged,

    #[serde(rename = "passkey.registered")]
    PasskeyRegistered,
    #[serde(rename = "passkey.asserted")]
    PasskeyAsserted,
    #[serde(rename = "passkey.moved")]
    PasskeyMoved,
    #[serde(rename = "passkey.reported")]
    PasskeyReported,
    #[serde(rename = "passkey.renamed")]
    PasskeyRenamed,

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
            Action::SshManagedKeyCreate => "ssh.managed_key_create",
            Action::SshManagedKeyDelete => "ssh.managed_key_delete",
            Action::SshAppGrantAdd => "ssh.app_grant_add",
            Action::SshAppGrantRemove => "ssh.app_grant_remove",
            Action::SshSessionBind => "ssh.session_bind",
            Action::SshPassphraseDeleted => "ssh.passphrase_deleted",
            Action::SshAgentStart => "ssh.agent_start",
            Action::SshAgentStop => "ssh.agent_stop",
            Action::GpgPassphrase => "gpg.passphrase",
            Action::GpgConfirm => "gpg.confirm",
            Action::GpgMessage => "gpg.message",
            Action::GpgPassphraseSaved => "gpg.passphrase_saved",
            Action::GpgPassphraseDeleted => "gpg.passphrase_deleted",
            Action::GpgAgentConfChanged => "gpg.agent_conf_changed",
            Action::AgeDecrypt => "age.decrypt",
            Action::AgeEncrypt => "age.encrypt",
            Action::AgeKeyCreate => "age.key_create",
            Action::AgeKeyDelete => "age.key_delete",
            Action::VaultUnlock => "vault.unlock",
            Action::VaultLock => "vault.lock",
            Action::VaultAutolock => "vault.autolock",
            Action::VaultCreated => "vault.created",
            Action::VaultUpdated => "vault.updated",
            Action::VaultDeleted => "vault.deleted",
            Action::VaultLinked => "vault.linked",
            Action::VaultExported => "vault.exported",
            Action::VaultImported => "vault.imported",
            Action::VaultVersionRestored => "vault.version_restored",
            Action::VaultVersionsErased => "vault.versions_erased",
            Action::VaultUnreadableMoved => "vault.unreadable_moved",
            Action::VaultResigned => "vault.resigned",
            Action::ItemListed => "item.listed",
            Action::ItemCreated => "item.created",
            Action::ItemUpdated => "item.updated",
            Action::ItemDeleted => "item.deleted",
            Action::ItemRestored => "item.restored",
            Action::ItemPurged => "item.purged",
            Action::ItemMerged => "item.merged",
            Action::ItemWebsitesChanged => "item.websites_changed",
            Action::ItemConverted => "item.converted",
            Action::CredentialRead => "credential.read",
            Action::CredentialExec => "credential.exec",
            Action::CredentialInject => "credential.inject",
            Action::CredentialCreated => "credential.created",
            Action::CredentialUpdated => "credential.updated",
            Action::CredentialDeleted => "credential.deleted",
            Action::CredentialRestored => "credential.restored",
            Action::CredentialPurged => "credential.purged",
            Action::CredentialHistoryRestored => "credential.history_restored",
            Action::CredentialHistoryPurged => "credential.history_purged",
            Action::CredentialRoleChanged => "credential.role_changed",
            Action::PasskeyRegistered => "passkey.registered",
            Action::PasskeyAsserted => "passkey.asserted",
            Action::PasskeyMoved => "passkey.moved",
            Action::PasskeyReported => "passkey.reported",
            Action::PasskeyRenamed => "passkey.renamed",
            Action::AuthGrantCreated => "auth.grant_created",
            Action::AuthGrantReused => "auth.grant_reused",
            Action::AuthGrantExpired => "auth.grant_expired",
            Action::BrokerPeerRejected => "broker.peer_rejected",
        }
    }

    /// Every action, grouped by category in display order. A new action must
    /// be added here to appear in the audit log help.
    pub const ALL: [Action; 64] = [
        Action::SshSign,
        Action::SshPassphrase,
        Action::SshKeyAdd,
        Action::SshKeyRemove,
        Action::SshManagedKeyCreate,
        Action::SshManagedKeyDelete,
        Action::SshAppGrantAdd,
        Action::SshAppGrantRemove,
        Action::SshPassphraseDeleted,
        Action::SshSessionBind,
        Action::SshAgentStart,
        Action::SshAgentStop,
        Action::GpgPassphrase,
        Action::GpgConfirm,
        Action::GpgMessage,
        Action::GpgPassphraseSaved,
        Action::GpgPassphraseDeleted,
        Action::GpgAgentConfChanged,
        Action::AgeDecrypt,
        Action::AgeEncrypt,
        Action::AgeKeyCreate,
        Action::AgeKeyDelete,
        Action::VaultUnlock,
        Action::VaultLock,
        Action::VaultAutolock,
        Action::VaultCreated,
        Action::VaultUpdated,
        Action::VaultDeleted,
        Action::VaultLinked,
        Action::VaultExported,
        Action::VaultImported,
        Action::VaultVersionRestored,
        Action::VaultVersionsErased,
        Action::VaultUnreadableMoved,
        Action::VaultResigned,
        Action::ItemListed,
        Action::ItemCreated,
        Action::ItemUpdated,
        Action::ItemDeleted,
        Action::ItemRestored,
        Action::ItemPurged,
        Action::ItemMerged,
        Action::ItemWebsitesChanged,
        Action::ItemConverted,
        Action::CredentialRead,
        Action::CredentialExec,
        Action::CredentialInject,
        Action::CredentialCreated,
        Action::CredentialUpdated,
        Action::CredentialDeleted,
        Action::CredentialRestored,
        Action::CredentialPurged,
        Action::CredentialHistoryRestored,
        Action::CredentialHistoryPurged,
        Action::CredentialRoleChanged,
        Action::PasskeyRegistered,
        Action::PasskeyAsserted,
        Action::PasskeyMoved,
        Action::PasskeyReported,
        Action::PasskeyRenamed,
        Action::AuthGrantCreated,
        Action::AuthGrantReused,
        Action::AuthGrantExpired,
        Action::BrokerPeerRejected,
    ];

    /// Parse the dotted string form.
    pub fn parse(s: &str) -> Option<Self> {
        serde_json::from_value(serde_json::Value::String(s.to_string())).ok()
    }

    /// What the action records, for the audit log help.
    pub fn description(&self) -> &'static str {
        match self {
            Action::SshSign => "Signed with an SSH key, such as for an ssh login or a git push.",
            Action::SshPassphrase => {
                "Gave ssh the passphrase of an encrypted SSH key through askpass."
            },
            Action::SshKeyAdd => "Added a key to the SSH agent, such as with ssh-add.",
            Action::SshKeyRemove => "Removed a key from the SSH agent.",
            Action::SshManagedKeyCreate => "Created an SSH key stored by Axo Pass.",
            Action::SshManagedKeyDelete => "Deleted an SSH key stored by Axo Pass.",
            Action::SshAppGrantAdd => "Let an app use an SSH key without a prompt.",
            Action::SshAppGrantRemove => "Removed an app's access to an SSH key without a prompt.",
            Action::SshSessionBind => {
                "Bound an SSH connection to the server's host key, for destination constraints."
            },
            Action::SshPassphraseDeleted => "Deleted a saved SSH key passphrase from the keychain.",
            Action::SshAgentStart => "Started the SSH agent.",
            Action::SshAgentStop => "Stopped the SSH agent.",
            Action::GpgPassphrase => "Gave gpg-agent the passphrase of a GPG key through pinentry.",
            Action::GpgConfirm => "Asked for confirmation on behalf of gpg-agent.",
            Action::GpgMessage => "Showed a message on behalf of gpg-agent.",
            Action::GpgPassphraseSaved => "Saved a GPG key passphrase in the keychain.",
            Action::GpgPassphraseDeleted => "Deleted a saved GPG key passphrase from the keychain.",
            Action::GpgAgentConfChanged => {
                "Set Axo Pass as the pinentry program in gpg-agent.conf."
            },
            Action::AgeDecrypt => "Decrypted data with an age identity.",
            Action::AgeEncrypt => "Encrypted data to one or more age recipients.",
            Action::AgeKeyCreate => "Created an age identity.",
            Action::AgeKeyDelete => "Deleted an age identity.",
            Action::VaultUnlock => "Unlocked the app and its vaults.",
            Action::VaultLock => "Locked the app and its vaults.",
            Action::VaultAutolock => {
                "Locked the app automatically, after the timeout, on sleep, or on screen lock."
            },
            Action::VaultCreated => "Created a vault.",
            Action::VaultUpdated => "Renamed a vault or changed its key.",
            Action::VaultDeleted => "Deleted a vault. The vault file is moved to the Trash.",
            Action::VaultLinked => "Added an external vault file.",
            Action::VaultExported => "Exported vaults to an encrypted bundle.",
            Action::VaultImported => "Imported vaults from an encrypted bundle.",
            Action::VaultVersionRestored => {
                "Replaced a vault with a version retained from before an earlier save."
            },
            Action::VaultVersionsErased => "Deleted every retained version of a vault.",
            Action::VaultUnreadableMoved => {
                "Moved the vault files that this Mac's keys cannot read to the unreadable folder, before new keys were created."
            },
            Action::VaultResigned => {
                "Signed every vault file and retained version again with a new device signing key, after the old key was lost."
            },
            Action::ItemListed => {
                "Listed the items in a vault, or the logins for a site. No values are read."
            },
            Action::ItemCreated => "Created an item.",
            Action::ItemUpdated => "Renamed an item, or wrote a credential of an existing item.",
            Action::ItemDeleted => "Moved an item to the deleted items.",
            Action::ItemRestored => "Restored a deleted item.",
            Action::ItemPurged => "Permanently deleted an item.",
            Action::ItemMerged => "Moved the credentials of one item into another.",
            Action::ItemWebsitesChanged => "Changed the websites an item is filled on.",
            Action::ItemConverted => "Gave an item the roles and websites of a login.",
            Action::CredentialRead => {
                "Read a credential value, such as with ap read, an AutoFill fill, or a one-time code."
            },
            Action::CredentialExec => "Read credential values for a command run with ap exec.",
            Action::CredentialInject => {
                "Read credential values for a template filled with ap inject."
            },
            Action::CredentialCreated => "Created a credential.",
            Action::CredentialUpdated => "Changed the value, title, key, or kind of a credential.",
            Action::CredentialDeleted => "Moved a credential to the deleted credentials.",
            Action::CredentialRestored => "Restored a deleted credential.",
            Action::CredentialPurged => "Permanently deleted a credential.",
            Action::CredentialHistoryRestored => "Made a previous value of a credential current.",
            Action::CredentialHistoryPurged => {
                "Permanently deleted a previous value of a credential."
            },
            Action::CredentialRoleChanged => {
                "Set or cleared the username, password, or one-time code role of a credential."
            },
            Action::PasskeyRegistered => "Created a passkey for a website.",
            Action::PasskeyAsserted => "Signed in to a website with a passkey.",
            Action::PasskeyMoved => "Moved a passkey to another item.",
            Action::PasskeyReported => {
                "A website reported that a passkey is unknown, listed the passkeys it accepts, or reported a new account name."
            },
            Action::PasskeyRenamed => "Applied an account name a website reported to a passkey.",
            Action::AuthGrantCreated => "Approved access that can be reused for a short time.",
            Action::AuthGrantReused => "Used an earlier approval, so no prompt was shown.",
            Action::AuthGrantExpired => "An earlier approval ran out.",
            Action::BrokerPeerRejected => {
                "Refused a request from a process that failed verification."
            },
        }
    }

    /// Category of the action, matching the namespace of its dotted form.
    pub fn category(&self) -> Category {
        match self {
            Action::SshSign
            | Action::SshPassphrase
            | Action::SshKeyAdd
            | Action::SshKeyRemove
            | Action::SshManagedKeyCreate
            | Action::SshManagedKeyDelete
            | Action::SshAppGrantAdd
            | Action::SshAppGrantRemove
            | Action::SshPassphraseDeleted
            | Action::SshSessionBind
            | Action::SshAgentStart
            | Action::SshAgentStop => Category::Ssh,
            Action::GpgPassphrase
            | Action::GpgConfirm
            | Action::GpgMessage
            | Action::GpgPassphraseSaved
            | Action::GpgPassphraseDeleted
            | Action::GpgAgentConfChanged => Category::Gpg,
            Action::AgeDecrypt
            | Action::AgeEncrypt
            | Action::AgeKeyCreate
            | Action::AgeKeyDelete => Category::Age,
            Action::VaultUnlock
            | Action::VaultLock
            | Action::VaultAutolock
            | Action::VaultCreated
            | Action::VaultUpdated
            | Action::VaultDeleted
            | Action::VaultLinked
            | Action::VaultExported
            | Action::VaultImported
            | Action::VaultVersionRestored
            | Action::VaultVersionsErased
            | Action::VaultUnreadableMoved
            | Action::VaultResigned => Category::Vault,
            Action::ItemListed
            | Action::ItemCreated
            | Action::ItemUpdated
            | Action::ItemDeleted
            | Action::ItemRestored
            | Action::ItemPurged
            | Action::ItemMerged
            | Action::ItemWebsitesChanged
            | Action::ItemConverted => Category::Item,
            Action::CredentialRead
            | Action::CredentialExec
            | Action::CredentialInject
            | Action::CredentialCreated
            | Action::CredentialUpdated
            | Action::CredentialDeleted
            | Action::CredentialRestored
            | Action::CredentialPurged
            | Action::CredentialHistoryRestored
            | Action::CredentialHistoryPurged
            | Action::CredentialRoleChanged => Category::Credential,
            Action::PasskeyRegistered
            | Action::PasskeyAsserted
            | Action::PasskeyMoved
            | Action::PasskeyReported
            | Action::PasskeyRenamed => Category::Passkey,
            Action::AuthGrantCreated | Action::AuthGrantReused | Action::AuthGrantExpired => {
                Category::Grant
            },
            Action::BrokerPeerRejected => Category::Broker,
        }
    }

    /// Whether the action uses a key or secret, changes stored state, or
    /// neither.
    pub fn kind(&self) -> ActionKind {
        match self {
            Action::SshSign
            | Action::SshPassphrase
            | Action::GpgPassphrase
            | Action::GpgConfirm
            | Action::AgeDecrypt
            | Action::AgeEncrypt
            | Action::VaultExported
            | Action::ItemListed
            | Action::CredentialRead
            | Action::CredentialExec
            | Action::CredentialInject
            | Action::PasskeyAsserted => ActionKind::Access,
            Action::SshKeyAdd
            | Action::SshKeyRemove
            | Action::SshManagedKeyCreate
            | Action::SshManagedKeyDelete
            | Action::SshAppGrantAdd
            | Action::SshAppGrantRemove
            | Action::SshPassphraseDeleted
            | Action::GpgPassphraseSaved
            | Action::GpgPassphraseDeleted
            | Action::GpgAgentConfChanged
            | Action::AgeKeyCreate
            | Action::AgeKeyDelete
            | Action::VaultCreated
            | Action::VaultUpdated
            | Action::VaultDeleted
            | Action::VaultLinked
            | Action::VaultImported
            | Action::VaultVersionRestored
            | Action::VaultVersionsErased
            | Action::VaultUnreadableMoved
            | Action::VaultResigned
            | Action::ItemCreated
            | Action::ItemUpdated
            | Action::ItemDeleted
            | Action::ItemRestored
            | Action::ItemPurged
            | Action::ItemMerged
            | Action::ItemWebsitesChanged
            | Action::ItemConverted
            | Action::CredentialCreated
            | Action::CredentialUpdated
            | Action::CredentialDeleted
            | Action::CredentialRestored
            | Action::CredentialPurged
            | Action::CredentialHistoryRestored
            | Action::CredentialHistoryPurged
            | Action::CredentialRoleChanged
            | Action::PasskeyRegistered
            | Action::PasskeyMoved
            | Action::PasskeyRenamed => ActionKind::Change,
            Action::SshSessionBind
            | Action::SshAgentStart
            | Action::SshAgentStop
            | Action::GpgMessage
            | Action::VaultUnlock
            | Action::VaultLock
            | Action::VaultAutolock
            | Action::AuthGrantCreated
            | Action::AuthGrantReused
            | Action::AuthGrantExpired
            | Action::PasskeyReported
            | Action::BrokerPeerRejected => ActionKind::Other,
        }
    }
}

/// Action category. Each category is one namespace of the dotted action form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
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

/// What an action does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionKind {
    /// Uses a key or secret, or reveals what a vault holds.
    Access,
    /// Changes stored keys, vaults, items, or credentials.
    Change,
    /// Vault state, agent lifecycle, grants, and rejected peers.
    Other,
}

/// Who asked for an event. Derived from the source, actor, and subject.
/// `Source` names the process that wrote the event, which for a broker request
/// is the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requester {
    /// The app itself, with no other process involved.
    App,
    /// An `ap` command.
    Cli,
    /// The browser extension, through the native messaging host.
    Browser,
    /// The AutoFill credential provider extension.
    Autofill,
    /// A process using an SSH key through the agent or askpass, such as `ssh`
    /// or `git`.
    SshClient,
    /// A process using a GPG key through gpg-agent and pinentry, such as `gpg`
    /// or `git`.
    GpgClient,
    /// Any other process, such as a rejected broker peer.
    Other,
}

/// The kind of thing a `Subject` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    SshKey,
    GpgKey,
    Credential,
    Item,
    Vault,
    AgeIdentity,
}

/// The thing that was used. Names it, never its value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    pub kind: SubjectKind,

    /// A stable identifier: key label, keygrip, `vault/item/credential`,
    /// `vault/item`, or a vault key.
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

    /// The same chain with per-process detail. Carried in-process to the prompt
    /// UI, never written to the audit log.
    #[serde(skip)]
    pub chain_detail: Vec<ProcessNode>,
}
