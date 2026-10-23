//! The vault side of the broker: every `ap` command that needs the vault
//! encryption key runs through here. Reads (`ap item list`, `ap item get`, `ap
//! read`, `ap exec`, `ap inject`), the single write (`ap item set`), and vault
//! management (`ap vault export`, `ap vault import`, `ap vault add`).
//!
//! `ap` holds no keychain entitlements, so it cannot read or create the vault
//! encryption key itself. It hands the request to the app, which unlocks the
//! vault on a context it owns and returns the result. A read or a write prompts
//! every time; a listing may reuse a recent approval.
//!
//! The app verifies the peer before it serves a request, so it holds the full
//! provenance for the process that asked. It is therefore the process that
//! records the `credential.read`, `item.listed`, `vault.exported`,
//! `vault.imported` and `vault.linked` events, the same way the SSH agent
//! records `ssh.sign`. Export and import also emit the per-vault events that
//! the core records internally, sourced to the app.

use std::path::PathBuf;

use async_trait::async_trait;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use super::PromptOutcome;
use super::placement::{PasskeyChoices, PasskeyPlacement};
use super::wire::WireImportIdentity;
#[cfg(doc)]
use super::wire::WireRequest;
use crate::audit::Actor;
use crate::core::auth::ForeignContext;
use crate::core::provenance::ProcessNode;
use crate::secrets::vaults::bundle::ExportMode;
use crate::secrets::vaults::{Site, passkey};

mod audit;
mod logins;
mod manage;
mod passkeys;
mod requests;
mod secrets;
mod serve;
#[cfg(test)]
mod tests;

pub(super) use logins::{list_logins_locked, write_vault_key};
pub(super) use passkeys::{list_passkeys_locked, passkey_choices, record_passkey_report};
pub use requests::{
    request_add_external_vault, request_assert_passkey, request_create_passkey,
    request_export_vaults, request_import_vaults, request_resolve_secrets, request_vault_items,
    request_vault_secret, request_write_vault_secret,
};
pub(super) use serve::{authorize_and_serve, authorize_and_serve_logins};

/// One `axo://` reference to resolve, as it crosses the socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultRef {
    pub vault_key: String,
    pub item_key: String,
    pub credential_key: String,
}

/// The login fields a write carries beyond the password, as they cross the
/// socket. The app writes them with the password and assigns the role slots.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WireLogin {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub websites: Vec<String>,
}

/// Which command asked for a batch resolve, so the app records the matching
/// audit action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolvePurpose {
    /// `ap exec`.
    Exec,
    /// `ap inject`.
    Inject,
    /// `ap read` with more than one reference. One prompt covers the batch.
    Read,
}

/// What the app is being asked to do with the vault. Grants are keyed on the
/// action as well as the vault, so authorizing a listing does not also
/// authorize a read of the same vault.
#[derive(Debug, Clone)]
pub enum VaultAction {
    /// `ap item list`: return the item overview, never a secret.
    ListItems,

    /// `ap read`: return one credential's secret value.
    ReadSecret {
        item_key: String,
        credential_key: String,
    },

    /// The logins that match a page, across every vault, with usernames but no
    /// passwords.
    ///
    /// With `all`, the logins that do not match come back too, without their
    /// websites.
    ListLogins { page: LoginPage, all: bool },

    /// The username and password of one login. Prompts every time. `account`
    /// is the client's label for the login, shown in the prompt only.
    ///
    /// With `unmatched`, the login may be one that is not stored for the page.
    /// The user is asked to confirm it.
    FillLogin {
        page: LoginPage,
        record_id: String,
        account: Option<String>,
        unmatched: bool,
    },

    /// The current one-time code of one login. Prompts every time.
    GenerateTotp { page: LoginPage, record_id: String },

    /// Save a login captured from a form on `page` as a new item. Prompts every
    /// time. `username` is shown in the prompt. The password travels in
    /// [`SaveLoginPayload`].
    SaveLogin {
        page: LoginPage,
        username: Option<String>,
    },

    /// Replace the password of one login with the one a form on `page`
    /// submitted. Prompts every time. `account` is the client's label for the
    /// login, shown in the prompt only. The password travels in
    /// [`UpdateLoginPayload`].
    UpdateLoginPassword {
        page: LoginPage,
        record_id: String,
        account: Option<String>,
    },

    /// `ap exec` / `ap inject`: resolve many `axo://` references at once,
    /// possibly across several vaults, behind one prompt.
    ResolveSecrets {
        purpose: ResolvePurpose,
        refs: Vec<VaultRef>,
    },

    /// `ap item set`: write one credential's secret value, creating the item
    /// or credential if it does not exist. The value itself is not carried
    /// here; it travels in [`WriteSecretPayload`] so it never reaches the
    /// app's prompt delegate.
    WriteSecret {
        item_key: String,
        credential_key: String,
    },

    /// `ap vault export`: unlock every named vault and write an encrypted
    /// bundle. Reads all secrets, so it prompts every time. The destination
    /// path and the export passphrase travel in [`ExportPayload`].
    ExportVaults { vault_keys: Vec<String> },

    /// `ap vault import`: re-wrap the selected vaults from a bundle with the
    /// local encryption key and write them to the vaults directory. The bundle
    /// path, decryption identity and selection travel in [`ImportPayload`].
    ImportVaults { count: usize },

    /// `ap vault add`: unlock the vault at `path` to validate it, then register
    /// it as an external vault in the app config.
    AddVault { path: String },

    /// The AutoFill extension's passkey registration: run the WebAuthn
    /// authenticator against an unlocked vault and return the attestation. The
    /// request data travels in [`CreatePasskeyPayload`]. The prompt offers the
    /// vault and the login to store the passkey in, and the app returns the
    /// user's choice through [`VaultAuthorizer::passkey_placement`].
    CreatePasskey {
        rp_id: String,
        /// The account the passkey is for, shown in the prompt.
        user_name: String,
        choices: PasskeyChoices,
    },

    /// The AutoFill extension's passkey assertion: sign the challenge with a
    /// stored passkey's private key. The request data travels in
    /// [`AssertPasskeyPayload`].
    AssertPasskey {
        rp_id: String,
        /// Account of the passkey the request names, shown in the prompt. Read
        /// from the login index. `None` if the request matches several
        /// indexed passkeys or none.
        user_name: Option<String>,
    },
}

/// The page a login request is for, reduced to what the prompt shows and a
/// grant is keyed on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginPage {
    /// The frame's URL as the client sent it. Matching uses this.
    pub frame_url: String,
    /// The frame's origin, `scheme://host[:port]`. The path and query are left
    /// out because they can carry tokens, and this is what audit records.
    pub frame_origin: String,
    /// The frame's host, with one leading `www.` removed.
    pub host: String,
    /// The frame's registrable domain.
    pub domain: String,
    /// The top-level host, when the form is in a frame of another host.
    pub top_host: Option<String>,
    /// True when the top-level page is on a different registrable domain than
    /// the frame. A frame on a sibling subdomain is not cross-site.
    pub cross_site: bool,
    /// False when the frame is on `http:`.
    pub secure: bool,
    /// The name of the app that asked, as the AutoFill extension reported it.
    /// `None` means a browser. It is a display hint and is never used to
    /// decide anything.
    pub requester: Option<String>,
}

impl LoginPage {
    /// Describe the page. Fails when the frame is not an http(s) site, since
    /// nothing matches one.
    pub fn parse(url: &str, frame_url: &str, requester: Option<String>) -> Result<Self, String> {
        let frame = Site::parse(frame_url)
            .ok_or_else(|| "AutoFill only fills http and https pages".to_string())?;
        let top = Site::parse(url);
        let cross_site = top.as_ref().is_some_and(|top| top.domain != frame.domain);
        let top_host = top.map(|top| top.host).filter(|host| *host != frame.host);
        let frame_origin = url::Url::parse(frame_url.trim())
            .map(|parsed| parsed.origin().ascii_serialization())
            .unwrap_or_else(|_| format!("https://{}", frame.host));
        Ok(Self {
            frame_url: frame_url.to_string(),
            frame_origin,
            host: frame.host,
            domain: frame.domain,
            top_host,
            cross_site,
            secure: frame.secure,
            requester: requester.filter(|name| !name.trim().is_empty()),
        })
    }

    /// Refuse a page whose form is in a frame of another site. A fill or a
    /// one-time code is released only to a form on the site that is visible in
    /// the top-level page.
    pub fn require_same_site(self) -> Result<Self, String> {
        if self.cross_site {
            let top = self.top_host.as_deref().unwrap_or("another site");
            return Err(format!(
                "AutoFill does not fill a form on {} inside a page on {top}",
                self.host
            ));
        }
        Ok(self)
    }
}

/// Who a request is for, as far as the broker can tell. It decides whether an
/// approval may be reused and what the audit event records about the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientIdentity {
    /// A process the broker verified from its own peer. Its process chain
    /// identifies it.
    Process,
    /// A browser that our browser host verified as its parent. `extension` is
    /// what the browser passed the host. The host cannot verify it, so it is
    /// recorded and never used to decide anything.
    Browser {
        name: String,
        team_id: String,
        extension: Option<String>,
    },
    /// A browser host that could not verify its parent. No approval is reused
    /// for it.
    Unverified { extension: Option<String> },
}

/// The secret an [`VaultAction::WriteSecret`] writes, kept out of
/// [`VaultAccessPrompt`] so it is not handed to the app for the prompt.
#[derive(Clone)]
pub struct WriteSecretPayload {
    pub title: String,
    pub value: SecretString,
    /// When set, the written credential is the item's password and the item
    /// is written as a login.
    pub login: Option<WireLogin>,
}

/// Where an [`VaultAction::ExportVaults`] writes and how the bundle key is
/// protected. Kept out of [`VaultAccessPrompt`], like [`WriteSecretPayload`].
#[derive(Clone)]
pub struct ExportPayload {
    pub dest_path: PathBuf,
    pub mode: ExportMode,
    /// False leaves passkeys out of the bundle.
    pub include_passkeys: bool,
}

/// The bundle an [`VaultAction::ImportVaults`] reads, its decryption identity
/// and the id-to-key selection. Kept out of [`VaultAccessPrompt`].
#[derive(Clone)]
pub struct ImportPayload {
    pub import_path: PathBuf,
    pub identity: WireImportIdentity,
    /// `(bundle vault id, target key)` pairs.
    pub selection: Vec<(String, String)>,
}

/// The WebAuthn registration request for an [`VaultAction::CreatePasskey`],
/// kept out of [`VaultAccessPrompt`].
#[derive(Clone)]
pub struct CreatePasskeyPayload {
    pub request: passkey::CreatePasskeyRequest,
}

/// The WebAuthn assertion request for an [`VaultAction::AssertPasskey`], kept
/// out of [`VaultAccessPrompt`].
#[derive(Clone)]
pub struct AssertPasskeyPayload {
    pub request: passkey::AssertPasskeyRequest,
    /// The extension had no account list to offer. If several passkeys match,
    /// the user picks one in the prompt after the vaults unlock.
    pub choose_account: bool,
    /// Vault of the passkey chosen in the prompt. If set, only this vault is
    /// unlocked to sign.
    pub vault_key: Option<String>,
}

/// One passkey offered in the prompt when the user picks the account to sign
/// in with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyAccountChoice {
    pub credential_id: Vec<u8>,
    pub user_name: String,
    pub vault_key: String,
}

/// The password a browser captured for [`VaultAction::SaveLogin`].
#[derive(Clone)]
pub struct SaveLoginPayload {
    pub password: SecretString,
}

/// The new password for [`VaultAction::UpdateLoginPassword`].
#[derive(Clone)]
pub struct UpdateLoginPayload {
    pub password: SecretString,
}

/// A payload that does not belong in [`VaultAccessPrompt`] because it carries a
/// secret or would clutter the prompt.
#[derive(Clone)]
pub(super) enum VaultPayload {
    Write(WriteSecretPayload),
    SaveLogin(SaveLoginPayload),
    UpdateLogin(UpdateLoginPayload),
    Export(ExportPayload),
    Import(ImportPayload),
    CreatePasskey(CreatePasskeyPayload),
    AssertPasskey(AssertPasskeyPayload),
}

/// What the app needs to describe the prompt for a vault access.
#[derive(Debug, Clone)]
pub struct VaultAccessPrompt {
    /// The vault a single-vault access names. For
    /// [`VaultAction::ResolveSecrets`], the distinct vault keys joined with
    /// `, `, since one resolve can span several vaults.
    pub vault_key: String,

    /// Who asked, as `ap` resolved it. Carries the same delegated trust as
    /// [`WireRequest::Sign`]'s caller.
    pub caller: Option<String>,

    /// The full requesting process chain. For a vault access `ap` is the
    /// broker's own peer, so this is the peer's resolved chain rather than a
    /// delegated one. Shown when the user expands the prompt.
    pub caller_chain: Vec<ProcessNode>,

    /// How the client is identified for reusing approvals and for audit.
    pub client: ClientIdentity,

    pub action: VaultAction,
}

/// One vault item as it crosses the socket: the overview only, never a secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerVaultItem {
    pub key: String,
    pub title: String,
    pub credentials: Vec<BrokerCredential>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerCredential {
    pub key: String,
    pub title: String,
}

/// Supplies an `LAContext` to unlock the vault on, and learns how the attempt
/// ended so it can take its prompt down.
#[async_trait]
pub trait VaultAuthorizer: Send + Sync + 'static {
    /// Prepare a context for `prompt` and put the prompt on screen. The broker
    /// unlocks on the returned context, which is what makes the attached
    /// `LAAuthenticationView` draw. `peer` is the process the broker verified.
    async fn begin(&self, prompt: VaultAccessPrompt, peer: Actor)
    -> Result<ForeignContext, String>;

    /// The client disconnected while `begin` was still waiting on the user.
    /// Dismiss the prompt so `begin` returns early. `begin` is still awaited,
    /// and `end` still called, afterward.
    async fn abandon(&self);

    /// Where the user chose to store a passkey, read after `begin` returns for
    /// a [`VaultAction::CreatePasskey`]. `None` means the user did not choose,
    /// and the prompt's default placement applies. The broker checks the answer
    /// against the choices it offered.
    async fn passkey_placement(&self, _prompt: &VaultAccessPrompt) -> Option<PasskeyPlacement> {
        None
    }

    /// Ask the user which of `accounts` to sign in with, after `begin` returns
    /// for a [`VaultAction::AssertPasskey`]. Returns an index into `accounts`.
    /// `None` means the user cancelled.
    async fn choose_passkey(
        &self,
        _prompt: &VaultAccessPrompt,
        _accounts: Vec<PasskeyAccountChoice>,
    ) -> Option<usize> {
        None
    }

    /// The attempt finished. Always called once `begin` has been called, so the
    /// app can take the prompt down and settle the authorization it handed out.
    async fn end(&self, prompt: VaultAccessPrompt, outcome: PromptOutcome);

    /// A site report about a passkey was recorded. The app refreshes what it
    /// shows and what it offers in AutoFill. The vaults are unchanged.
    async fn passkey_reports_changed(&self) {}
}
