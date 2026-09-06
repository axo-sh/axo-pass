//! Audit-log helpers for the SSH agent.
//!
//! The agent holds the full `PeerIdentity` for the requesting process, so it
//! is the process that records signing and key-management events with complete
//! provenance.

use axo_pass_core::audit::{
    self, Action, Actor, AuditEvent, Outcome, Source, Subject, SubjectKind,
};
use ssh_agent_lib::error::AgentError;
use ssh_key::public::KeyData;
use ssh_key::{HashAlg, Signature};

use crate::cli::commands::ssh_agent::userauth_request::UserauthRequest;

/// Classify a `sign` result into an audit outcome and message.
pub fn sign_outcome(result: &Result<Signature, AgentError>) -> (Outcome, Option<String>) {
    match result {
        Ok(_) => (Outcome::Succeeded, None),
        Err(e) => {
            let message = e.to_string();
            let lower = message.to_lowercase();
            let outcome = if lower.contains("locked") {
                Outcome::Cancelled
            } else if lower.contains("failed to parse userauth request") {
                Outcome::Failed
            } else {
                Outcome::Denied
            };
            (outcome, Some(message))
        },
    }
}

/// Record one `ssh.sign` event for a completed request.
pub fn record_sign(
    actor: Option<&Actor>,
    caller: Option<&str>,
    pubkey: &KeyData,
    request_data: &[u8],
    managed: bool,
    comment: Option<&str>,
    key_label: Option<&str>,
    result: &Result<Signature, AgentError>,
) {
    let fingerprint = pubkey.fingerprint(HashAlg::Sha256).to_string();
    let (outcome, message) = sign_outcome(result);

    let mut subject =
        Subject::new(SubjectKind::SshKey, fingerprint.clone()).fingerprint(fingerprint);
    if let Some(comment) = comment.filter(|c| !c.is_empty()) {
        subject = subject.label(comment);
    }

    let mut event = AuditEvent::new(Source::Agent, Action::SshSign, outcome)
        .subject(subject)
        .detail("algorithm", pubkey.algorithm().to_string())
        .detail("managed", managed.to_string());
    if let Some(key_label) = key_label {
        event = event.detail("key_label", key_label.to_string());
    }

    if let Ok(req) = UserauthRequest::parse(request_data) {
        if let Some(user) = req.user {
            event = event.detail("user", user);
        }
        if let Some(hostkey) = req.hostkey {
            event = event.detail(
                "hostkey_fingerprint",
                hostkey.fingerprint(HashAlg::Sha256).to_string(),
            );
        }
    }

    event = attach_actor(event, actor, caller);
    if let Some(message) = message {
        event = event.message(message);
    }
    audit::record(event);
}

/// Record an `ssh.key_add` or `ssh.key_remove` event.
pub fn record_key_change(
    action: Action,
    actor: Option<&Actor>,
    caller: Option<&str>,
    pubkey: &KeyData,
    comment: Option<&str>,
    detail: &[(&str, String)],
) {
    let fingerprint = pubkey.fingerprint(HashAlg::Sha256).to_string();
    let mut subject =
        Subject::new(SubjectKind::SshKey, fingerprint.clone()).fingerprint(fingerprint);
    if let Some(comment) = comment.filter(|c| !c.is_empty()) {
        subject = subject.label(comment);
    }
    let mut event = AuditEvent::new(Source::Agent, action, Outcome::Succeeded).subject(subject);
    for (key, value) in detail {
        event = event.detail(*key, value.clone());
    }
    event = attach_actor(event, actor, caller);
    audit::record(event);
}

/// Record a lifecycle event with no subject, e.g. agent start/stop or session
/// bind.
pub fn record_lifecycle(
    action: Action,
    outcome: Outcome,
    actor: Option<&Actor>,
    caller: Option<&str>,
) {
    let event = attach_actor(
        AuditEvent::new(Source::Agent, action, outcome),
        actor,
        caller,
    );
    audit::record(event);
}

fn attach_actor(event: AuditEvent, actor: Option<&Actor>, caller: Option<&str>) -> AuditEvent {
    match actor {
        Some(actor) => event.actor(actor.clone()),
        None => event.maybe_actor(caller.map(|c| Actor {
            caller: Some(c.to_string()),
            ..Default::default()
        })),
    }
}
