//! Audit-log helpers for the SSH agent.
//!
//! The agent holds the full `PeerIdentity` for the requesting process, so it
//! is the process that records signing and key-management events with complete
//! provenance.

use axo_pass_core::audit::{
    self, Action, Actor, AuditEvent, Outcome, Source, Subject, SubjectKind,
};
use axo_pass_core::ssh::known_hosts::KnownHosts;
use ssh_agent_lib::error::AgentError;
use ssh_key::public::KeyData;
use ssh_key::{HashAlg, Signature};

use crate::cli::commands::ssh_agent::session_binding::SessionBinding;
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

/// Where the key that signs is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignKeySource {
    /// A key added with `ssh-add`, held by the agent.
    Agent,
    /// A key configured for auto-load, read from `~/.ssh` and held by the
    /// agent.
    AutoLoad,
    /// A Secure Enclave key held by the app.
    SecureEnclave,
    /// An SSH key stored in a vault, signed with by the app.
    Vault,
}

impl SignKeySource {
    /// Value of the `key_source` detail.
    pub fn as_str(self) -> &'static str {
        match self {
            SignKeySource::Agent => "agent",
            SignKeySource::AutoLoad => "auto_load",
            SignKeySource::SecureEnclave => "secure_enclave",
            SignKeySource::Vault => "vault",
        }
    }
}

/// Record one `ssh.sign` event for a completed request.
///
/// A vault key signature is recorded by the app instead, which knows the ids of
/// the vault, item, and credential. Nothing is recorded here for it.
#[allow(clippy::too_many_arguments)]
pub fn record_sign(
    actor: Option<&Actor>,
    caller: Option<&str>,
    pubkey: &KeyData,
    request_data: &[u8],
    source: SignKeySource,
    comment: Option<&str>,
    key_label: Option<&str>,
    sessions: &[SessionBinding],
    result: &Result<Signature, AgentError>,
) {
    if source == SignKeySource::Vault {
        return;
    }
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
        .detail("key_source", source.as_str());
    if let Some(key_label) = key_label {
        event = event.detail("key_label", key_label.to_string());
    }

    if let Ok(req) = UserauthRequest::parse(request_data) {
        if let Some(user) = req.user {
            event = event.detail("user", user);
        }
        if let Some(hostkey) = req.hostkey {
            event = event
                .detail(
                    "hostkey_fingerprint",
                    hostkey.fingerprint(HashAlg::Sha256).to_string(),
                )
                .maybe_detail("host", host_name(&hostkey, sessions));
        }
    }

    event = attach_actor(event, actor, caller);
    if let Some(message) = message {
        event = event.message(message);
    }
    audit::record(event);
}

/// The server's host name, from a session binding for its host key or else
/// from `known_hosts`. Hashed `known_hosts` entries give no name.
pub(crate) fn host_name(hostkey: &KeyData, sessions: &[SessionBinding]) -> Option<String> {
    if let Some(binding) = sessions.iter().find(|s| s.inner.host_key == *hostkey) {
        // The binding already looked the host key up in `known_hosts`.
        return binding.host_name.clone();
    }
    KnownHosts::load_from_user_ssh_dir()
        .ok()?
        .find_host_by_key(hostkey)
        .into_iter()
        .next()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_source_names() {
        let names: Vec<_> = [
            SignKeySource::Agent,
            SignKeySource::AutoLoad,
            SignKeySource::SecureEnclave,
            SignKeySource::Vault,
        ]
        .into_iter()
        .map(SignKeySource::as_str)
        .collect();

        assert_eq!(names, ["agent", "auto_load", "secure_enclave", "vault"]);
    }
}
