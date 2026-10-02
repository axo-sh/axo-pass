//! Loading auto-load keys on first use. See [`axo_pass_core::ssh::autoload`].

use std::os::fd::BorrowedFd;

use axo_pass_core::core::app_broker::{self, BrokerError, PassphraseKind, PassphrasePrompt};
use axo_pass_core::core::config::AppConfig;
use axo_pass_core::core::provenance::ProcessNode;
use axo_pass_core::ssh::autoload::{self, AutoloadKey};
use axo_pass_core::ssh::utils::compute_sha256_fingerprint;
use secrecy::{ExposeSecret, SecretString};
use ssh_agent_lib::proto;
use ssh_key::HashAlg;
use ssh_key::public::KeyData;

use crate::cli::commands::ssh_agent::managed_credential::call_broker;
use crate::cli::commands::ssh_agent::stored_credential::StoredCredential;

/// The configured auto-load keys, read from `config.toml` as it is now.
pub fn list_autoload_keys() -> Vec<AutoloadKey> {
    autoload::list(&AppConfig::load_fresh())
}

/// Whether `pubkey` is configured for auto-load. Checks the fingerprint only,
/// not the key file, so it also holds for a copy added by hand from elsewhere.
pub fn is_autoload_key(pubkey: &KeyData) -> bool {
    let fingerprint = pubkey.fingerprint(HashAlg::Sha256).to_string();
    AppConfig::load_fresh()
        .ssh_autoload
        .contains_key(&fingerprint)
}

/// The configured auto-load key for `pubkey`, if any.
pub fn find_autoload_key(pubkey: &KeyData) -> Option<AutoloadKey> {
    list_autoload_keys()
        .into_iter()
        .find(|key| key.public_key.key_data() == pubkey)
}

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("User declined to unlock {0}")]
    Cancelled(String),
    #[error("{0}")]
    Failed(String),
}

/// Read `key` from disk, asking the app for its passphrase if it is encrypted.
/// Blocks while the user answers. The resulting credential is marked
/// auto-load, so every use is confirmed unless an app grant applies.
pub fn load(
    key: &AutoloadKey,
    caller: Option<&str>,
    caller_chain: &[ProcessNode],
    requester: Option<BorrowedFd<'_>>,
) -> Result<StoredCredential, LoadError> {
    let path = key.path.display().to_string();
    let encrypted =
        autoload::is_encrypted(&key.path).map_err(|e| LoadError::Failed(format!("{e:#}")))?;

    let passphrase = if encrypted {
        Some(request_passphrase(key, caller, caller_chain, requester)?)
    } else {
        None
    };
    let private = autoload::read_private_key(
        &key.path,
        &key.fingerprint,
        passphrase.as_ref().map(|p| p.expose_secret()),
    )
    .map_err(|e| LoadError::Failed(format!("{e:#}")))?;

    let comment = if private.comment().is_empty() {
        key.public_key.comment().to_string()
    } else {
        private.comment().to_string()
    };
    log::debug!("Loaded auto-load key {} from {path}", key.fingerprint);

    let mut credential = StoredCredential::from(proto::PrivateCredential::Key {
        privkey: private.key_data().clone(),
        comment,
    });
    credential.autoload = true;
    Ok(credential)
}

/// Ask the app for the passphrase. The key id is the one `ap ssh-askpass` and
/// the SSH pane use, so a saved passphrase unlocks behind Touch ID.
fn request_passphrase(
    key: &AutoloadKey,
    caller: Option<&str>,
    caller_chain: &[ProcessNode],
    requester: Option<BorrowedFd<'_>>,
) -> Result<SecretString, LoadError> {
    let prompt = PassphrasePrompt {
        kind: PassphraseKind::Ssh,
        key_id: Some(compute_sha256_fingerprint(key.public_key.key_data())),
        description: None,
        prompt: Some(format!(
            "Enter passphrase for key '{}':",
            key.path.display()
        )),
        error_message: None,
        caller: caller.map(String::from),
        caller_chain: caller_chain.to_vec(),
    };
    call_broker(|| app_broker::request_ssh_passphrase(&prompt, requester)).map_err(|e| match e {
        BrokerError::Cancelled | BrokerError::RequesterDisconnected => {
            LoadError::Cancelled(key.path.display().to_string())
        },
        e => LoadError::Failed(format!("Could not get the passphrase: {e}")),
    })
}
