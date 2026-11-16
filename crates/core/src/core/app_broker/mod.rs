//! Proxies prompts and keychain reads to the app, which holds the
//! `keychain-access-groups` entitlement. `ap` does not and cannot hold
//! entitlements.
//!
//! Three callers use the broker: the SSH agent, for managed Secure Enclave
//! keys; `ap ssh-askpass`, for SSH key passphrases (see [`ssh`]); and `ap
//! pinentry`, for GPG passphrases (see [`gpg`]).
//!
//! Requests are served whether or not the vault is unlocked. Signing and
//! passphrase will prompt, but just listing identities will not.
//!
//! With no app running, `ap` will launch it and waits for the socket, so
//! `ssh-add -l` or a `git commit -S` against a closed app starts it rather than
//! failing.
//!
//! The broker identifies the peer before reading a request: it must be the `ap`
//! staged in this bundle, signed by the same team. See `agent_policy`.

use std::path::PathBuf;
use std::sync::Arc;

use thiserror::Error;

use crate::core::dirs::{app_data_dir, app_group_identifier};
use crate::secrets::vaults::VaultCatalog;

mod access;
pub mod age;
pub mod browser_host;
pub mod browser_manifest;
pub mod browsers;
mod client;
mod dispatch;
pub mod gpg;
mod in_flight;
pub mod keychain;
mod login_index;
mod mach;
mod placement;
mod server;
pub mod ssh;
#[cfg(test)]
mod tests;
pub mod vault;
mod wire;

pub use age::{
    BrokerAgeKey, request_age_identity, request_age_keys, request_create_age_key,
    request_delete_age_key,
};
pub(crate) use client::app_bundle_path;
pub use gpg::{
    CollectedPassphrase, ConfirmPrompt, PassphraseAuthorizer, PassphraseKind, PassphrasePrompt,
    request_confirm, request_message, request_passphrase,
};
pub use keychain::{
    BrokerPasswordEntry, KeychainLister, SystemKeychain, request_delete_managed_key,
    request_keychain_passwords,
};
pub use login_index::{IndexedPasskey, LoginIndex};
pub use placement::{
    PasskeyChoices, PasskeyPlacement, PlacementLogin, PlacementVault, VaultChoices,
};
pub use server::serve;
pub use ssh::{
    ManagedIdentity, SignAuthorizer, SignPrompt, SignPurpose, list_identities,
    request_authorize_key_use, request_signature, request_ssh_passphrase,
};
pub use vault::{
    BrokerCredential, BrokerVaultItem, ClientIdentity, ExportSummary, FileReadSummary, LoginPage,
    PasskeyAccountChoice, ResolvePurpose, VaultAccessPrompt, VaultAction, VaultAuthorization,
    VaultAuthorizer, VaultRef, WireLogin, request_add_external_vault, request_assert_passkey,
    request_create_passkey, request_export_vaults, request_import_items, request_import_vaults,
    request_read_vault_file, request_resolve_secrets, request_vault_items, request_vault_secret,
    request_write_vault_secret,
};
pub use wire::{
    WireDropped, WireExportMode, WireFileFailure, WireImportIdentity, WireImportSelection,
    WireImportSummary, WireImportTarget,
};

/// The AutoFill credential provider extension, staged under `Contents/PlugIns`.
/// Matches the `target_name` of the `[[extensions]]` entry in strudel.toml.
pub const AUTOFILL_EXTENSION_NAME: &str = "AxoPassAutoFill";

/// The agent ships inside the app bundle, beside the app's own executable.
pub const AGENT_EXECUTABLE_NAME: &str = "ap";

/// The browser native messaging host, staged beside the app's own executable.
pub const BROWSER_HOST_EXECUTABLE_NAME: &str = "AxoPassBrowserHost";

pub fn broker_socket_path() -> PathBuf {
    // typically: ~/Library/Application Support/Axo Pass/app-broker.sock
    app_data_dir().join("app-broker.sock")
}

/// The Mach service the AutoFill extension reaches the broker on. A sandboxed
/// process may look up a Mach service whose name starts with an App Group it
/// belongs to. `None` for an unsigned build, which has no team identifier and
/// therefore no App Group.
pub fn autofill_service_name() -> Option<String> {
    Some(format!("{}.broker", app_group_identifier()?))
}

/// Passed to the app by [`launch_app`] to say the launch is only to serve the
/// broker, so the app stays headless: no window, no Dock icon, no focus taken.
pub const LAUNCH_FLAG: &str = "--broker";

#[derive(Debug, Error)]
pub enum BrokerError {
    /// No app is listening and none could be started. The request fails,
    /// since only the app can reach the keychain.
    #[error("App broker unavailable")]
    Unavailable,

    /// The app accepted the connection and then went away before answering.
    /// Distinct from [`BrokerError::Unavailable`]: an app was there, so falling
    /// back to a local unlock would only fail again with a worse message.
    #[error("App broker closed the connection")]
    Disconnected,

    #[error("User cancelled the prompt")]
    Cancelled,

    /// The client the request was made for disconnected before the app
    /// answered, so the request was dropped. See [`send_request_for`].
    #[error("The requesting client disconnected")]
    RequesterDisconnected,

    #[error("Axo Pass failed: {0}")]
    Failed(String),
}

/// How a prompt ended.
///
/// The app distinguishes an approval from a dismissed prompt. Only an approval
/// starts the clocks that bound how long it is reused, and only an approval is
/// reported to the user.
#[derive(Debug, Clone)]
pub enum PromptOutcome {
    Succeeded,
    Cancelled,
    Failed(String),
}

/// The app's side of every request the broker serves.
#[derive(Clone)]
pub struct Authorizers {
    pub sign: Arc<dyn SignAuthorizer>,
    pub passphrase: Arc<dyn PassphraseAuthorizer>,
    pub vault: Arc<dyn VaultAuthorizer>,
    /// Reads the saved passwords. Real builds pass [`SystemKeychain`]; this is
    /// a field so tests can route the request without touching the developer's
    /// own keychain.
    pub keychain: Arc<dyn KeychainLister>,
    /// The logins the app indexed at its last unlock. The app fills it, and the
    /// broker lists from it for the clients allowed to list without a prompt.
    pub logins: Arc<LoginIndex>,
    /// Where vault requests find vaults. Real builds pass
    /// [`VaultCatalog::app`]. This is a field so tests can serve requests
    /// against a temp directory.
    pub vaults: VaultCatalog,
}
