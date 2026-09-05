//! `ap pinentry`: the pinentry gpg-agent runs.
//!
//! Wire it up by putting this in `~/.gnupg/gpg-agent.conf`:
//!
//! ```text
//! pinentry-program /Applications/Axo Pass.app/Contents/Resources/ap-pinentry
//! ```
//!
//! `pinentry-program` takes a path and no arguments, hence the wrapper script.
//!
//! Prompts are handled by the app, which `ap` reaches over the broker
//! socket. Stdout is the how we communicate with gpg-agent, i.e. only the
//! assuan protocol messages may be written to stdout here. Logging goes to
//! stderr which gpg-agent ignores.

use axo_pass_core::gpg::pinentry::{BrokerPinentryHandler, PinentryServer};

pub async fn run() {
    let mut server = match PinentryServer::new(tokio::io::stdin(), tokio::io::stdout()).await {
        Ok(server) => server,
        Err(e) => {
            log::error!("Failed to start pinentry: {e}");
            std::process::exit(1);
        },
    };

    let mut handler = BrokerPinentryHandler::new();
    if let Err(e) = server.run(&mut handler).await {
        log::error!("pinentry exited: {e}");
        std::process::exit(1);
    }
}
