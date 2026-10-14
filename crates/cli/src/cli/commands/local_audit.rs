//! Audit events for vault access without the app broker.
//!
//! A build that is not staged in an app bundle has no broker to reach, so `ap`
//! unlocks the vault itself. The broker records access it serves. These events
//! record the access `ap` does locally.

use axo_pass_core::audit::{self, Action, Actor, AuditEvent, Outcome, Subject, SubjectKind};
use axo_pass_core::core::provenance::Provenance;

/// Process that called `ap`, as an audit actor. Resolve it once per command
/// and pass it to each event, since resolving walks the process tree.
pub fn caller_actor() -> Option<Actor> {
    Provenance::resolve_current_parent().map(|p| Actor::from_provenance(&p))
}

/// Audit event for local vault access by `ap`.
pub fn local_event(
    action: Action,
    outcome: Outcome,
    vault_key: &str,
    subject: Subject,
    actor: Option<&Actor>,
) -> AuditEvent {
    AuditEvent::new(audit::process_source(), action, outcome)
        .subject(subject)
        .maybe_actor(actor.cloned())
        .detail("vault", vault_key)
        .detail("via", "local")
}

/// Audit subject for a credential, named `vault/item/credential`.
pub fn credential_subject(vault_key: &str, item_key: &str, credential_key: &str) -> Subject {
    Subject::new(
        SubjectKind::Credential,
        format!("{vault_key}/{item_key}/{credential_key}"),
    )
}
