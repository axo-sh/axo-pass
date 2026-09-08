//! `ap ssh-askpass <prompt>`: what `SSH_ASKPASS` should point at.
//!
//! `ssh` and `ssh-add` invoke this when they need a passphrase or password
//! with no terminal to prompt on (`SSH_ASKPASS_REQUIRE=force`), passing the
//! prompt text as the only argument and reading the answer back from stdout.
//!
//! Wire it up by putting this in your shell config:
//!
//! ```text
//! export SSH_ASKPASS="/Applications/Axo Pass.app/Contents/Resources/ap-ssh-askpass"
//! export SSH_ASKPASS_REQUIRE=force
//! ```
//!
//! `SSH_ASKPASS` takes a bare path and no arguments, hence the wrapper script.
//!
//! Prompts are handled by the app, which we reach over the broker socket, the
//! same as `ap pinentry`.

use std::io::Write;

use axo_pass_core::audit::{
    self, Action, Actor, AuditEvent, Outcome, Source, Subject, SubjectKind,
};
use axo_pass_core::core::app_broker::{self, BrokerError, PassphraseKind, PassphrasePrompt};
use axo_pass_core::core::provenance::Provenance;
use axo_pass_core::ssh::askpass::key_id_from_prompt;
use secrecy::ExposeSecret;

pub async fn run(prompt: String) {
    let prompt = prompt.trim().to_string();
    let key_id = key_id_from_prompt(&prompt);
    log::debug!("ssh-askpass: {prompt} [key: {key_id:?}]");

    // Resolved once: this process asks a single question and exits, so the
    // chain does not change under us. See `BrokerPinentryHandler::new` for why
    // this is as far as the process tree goes.
    let provenance = Provenance::resolve_current_parent()
        .inspect(|provenance| log::debug!("ssh-askpass caller: {provenance:#?}"));
    let caller = provenance.as_ref().and_then(|p| p.caller());
    let caller_chain = provenance.map(|p| p.chain_nodes()).unwrap_or_default();

    let request = PassphrasePrompt {
        kind: PassphraseKind::Ssh,
        key_id: key_id.clone(),
        description: None,
        prompt: Some(prompt),
        error_message: None,
        caller: caller.clone(),
        caller_chain,
    };

    let result = tokio::task::spawn_blocking(move || app_broker::request_ssh_passphrase(&request))
        .await
        .unwrap_or_else(|e| Err(BrokerError::Failed(format!("Task failed: {e}"))));

    record_passphrase(key_id.as_deref(), caller.as_deref(), &result);

    match result {
        Ok(passphrase) => {
            // ssh reads one line and strips the trailing newline, so emit one.
            let mut stdout = std::io::stdout();
            if let Err(e) = stdout
                .write_all(passphrase.expose_secret().as_bytes())
                .and_then(|_| stdout.write_all(b"\n"))
                .and_then(|_| stdout.flush())
            {
                log::error!("ssh-askpass: failed to write passphrase: {e}");
                std::process::exit(1);
            }
        },
        Err(BrokerError::Cancelled) => {
            log::debug!("ssh-askpass: cancelled");
            std::process::exit(1);
        },
        Err(e) => {
            log::error!("ssh-askpass failed: {e}");
            std::process::exit(1);
        },
    }
}

/// Record one `ssh.passphrase` event for a completed askpass request.
///
/// The actor carries only a single-level caller string: this helper resolves
/// just its immediate parent, unlike the agent, which holds the full peer
/// identity.
fn record_passphrase(
    key_id: Option<&str>,
    caller: Option<&str>,
    result: &Result<secrecy::SecretString, BrokerError>,
) {
    let (outcome, message) = match result {
        Ok(_) => (Outcome::Succeeded, None),
        Err(BrokerError::Cancelled) => (Outcome::Cancelled, None),
        Err(e) => (Outcome::Failed, Some(e.to_string())),
    };

    let subject = key_id.map(|id| {
        let fingerprint = if id.starts_with("SHA256:") {
            id.to_string()
        } else {
            format!("SHA256:{id}")
        };
        Subject::new(SubjectKind::SshKey, fingerprint.clone()).fingerprint(fingerprint)
    });

    let mut event = AuditEvent::new(Source::Askpass, Action::SshPassphrase, outcome)
        .maybe_subject(subject)
        .maybe_actor(caller.map(|c| Actor {
            caller: Some(c.to_string()),
            ..Default::default()
        }));
    if let Some(message) = message {
        event = event.message(message);
    }
    audit::record(event);
}
