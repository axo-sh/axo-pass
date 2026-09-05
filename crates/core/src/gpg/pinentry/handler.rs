//! Handle gpg-agent's pinentry commands via the app over rpc over the broker
//! socket.

use std::io;

use secrecy::SecretString;

use crate::core::app_broker::{self, BrokerError, PassphrasePrompt};
use crate::core::provenance::Provenance;
use crate::gpg::pinentry::server::PinentryServerHandler;

pub struct BrokerPinentryHandler {
    caller: Option<String>,
}

impl Default for BrokerPinentryHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl BrokerPinentryHandler {
    pub fn new() -> Self {
        // Resolved once, at startup: gpg-agent runs one pinentry per request,
        // so the chain does not change under us. It reaches gpg-agent and
        // whatever launched it, which is as far as the process tree goes: the
        // program that wanted the signature talks to the agent over its own
        // socket and is not our ancestor.
        let caller = Provenance::resolve_current_parent()
            .inspect(|provenance| log::debug!("pinentry caller: {provenance:#?}"))
            .and_then(|provenance| provenance.caller());
        Self { caller }
    }

    fn prompt(
        &self,
        desc: Option<&str>,
        prompt: Option<&str>,
        keyinfo: Option<&str>,
        error_message: Option<&str>,
    ) -> PassphrasePrompt {
        PassphrasePrompt {
            key_id: key_id_from_keyinfo(keyinfo),
            description: desc.map(String::from),
            prompt: prompt.map(String::from),
            error_message: error_message.map(String::from),
            caller: self.caller.clone(),
        }
    }
}

/// The key grip out of `SETKEYINFO`.
///
/// The value has the form `X/HEXSTRING`, where `X` is `n`, `s` or `u` and the
/// hex string is the key grip. That is not the OpenPGP key ID; it maps to a key
/// with `gpg --with-keygrip --list-secret-keys`. It names the keychain entry,
/// so it only has to be stable, not meaningful.
fn key_id_from_keyinfo(keyinfo: Option<&str>) -> Option<String> {
    keyinfo
        .and_then(|keyinfo| keyinfo.rsplit('/').next())
        .filter(|key_id| !key_id.is_empty())
        .map(String::from)
}

impl PinentryServerHandler for BrokerPinentryHandler {
    async fn get_pin(
        &mut self,
        desc: Option<&str>,
        prompt: Option<&str>,
        keyinfo: Option<&str>,
        error_message: Option<&str>,
    ) -> io::Result<SecretString> {
        let request = self.prompt(desc, prompt, keyinfo, error_message);
        // The broker blocks on the user answering a prompt, so it runs off the
        // reactor.
        tokio::task::spawn_blocking(move || app_broker::request_passphrase(&request))
            .await
            .map_err(io::Error::other)?
            .map_err(to_io_error)
    }

    async fn confirm(&mut self, desc: Option<&str>) -> io::Result<bool> {
        let desc = desc.map(String::from);
        tokio::task::spawn_blocking(move || app_broker::request_confirm(desc.as_deref()))
            .await
            .map_err(io::Error::other)?
            .map_err(to_io_error)
    }

    async fn message(&mut self, desc: Option<&str>) -> io::Result<()> {
        let desc = desc.map(String::from);
        tokio::task::spawn_blocking(move || app_broker::request_message(desc.as_deref()))
            .await
            .map_err(io::Error::other)?
            .map_err(to_io_error)
    }
}

/// A cancelled prompt is caused by user action, so it maps to `Interrupted` and
/// reaches gpg as an assuan error rather than as a passphrase.
fn to_io_error(error: BrokerError) -> io::Error {
    match error {
        BrokerError::Cancelled => io::Error::new(io::ErrorKind::Interrupted, error),
        e => io::Error::other(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_key_grip_out_of_keyinfo() {
        assert_eq!(
            key_id_from_keyinfo(Some("n/1234ABCD")),
            Some("1234ABCD".to_string())
        );
        // Some agents send the grip alone.
        assert_eq!(
            key_id_from_keyinfo(Some("1234ABCD")),
            Some("1234ABCD".to_string())
        );
        assert_eq!(key_id_from_keyinfo(Some("n/")), None);
        assert_eq!(key_id_from_keyinfo(None), None);
    }
}
