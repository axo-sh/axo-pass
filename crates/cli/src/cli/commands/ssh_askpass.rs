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
    let caller = Provenance::resolve_current_parent()
        .inspect(|provenance| log::debug!("ssh-askpass caller: {provenance:#?}"))
        .and_then(|provenance| provenance.caller());

    let request = PassphrasePrompt {
        kind: PassphraseKind::Ssh,
        key_id,
        description: None,
        prompt: Some(prompt),
        error_message: None,
        caller,
    };

    let result = tokio::task::spawn_blocking(move || app_broker::request_ssh_passphrase(&request))
        .await
        .unwrap_or_else(|e| Err(BrokerError::Failed(format!("Task failed: {e}"))));

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
