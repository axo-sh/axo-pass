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
use super::placement::{PasskeyChoices, PasskeyPlacement, VaultChoices};
#[cfg(doc)]
use super::wire::WireRequest;
use super::wire::{WireImportIdentity, WireImportSelection, WireImportTarget};
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

pub(super) use logins::{list_logins_locked, serve_granted_listing, vault_choices};
pub(super) use passkeys::{list_passkeys_locked, passkey_choices, record_passkey_report};
pub use requests::{
    ExportSummary, FileReadSummary, request_add_external_vault, request_assert_passkey,
    request_create_passkey, request_export_vaults, request_import_items, request_import_vaults,
    request_read_vault_file, request_resolve_secrets, request_vault_items, request_vault_secret,
    request_write_vault_secret,
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
    /// `ap env`.
    Env,
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

    /// `ap item read --output`: decrypt one file credential to `dest_path`.
    /// The app writes the file, so the contents never cross the socket.
    ReadFile {
        item_key: String,
        credential_key: String,
        dest_path: String,
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
        /// What the login index knows about the login. The broker fills it in
        /// before the prompt. `None` if the login is not indexed.
        details: Option<LoginDetails>,
    },

    /// The current one-time code of one login. Prompts every time.
    GenerateTotp { page: LoginPage, record_id: String },

    /// Save a login captured from a form on `page` as a new item. Prompts every
    /// time. `username` is shown in the prompt. The password travels in
    /// [`SaveLoginPayload`]. The prompt offers the vault to save the login in,
    /// and the app returns the user's choice through
    /// [`VaultAuthorizer::save_vault`].
    SaveLogin {
        page: LoginPage,
        username: Option<String>,
        choices: VaultChoices,
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

    /// `ap vault import-1password`: add the items of a `.1pif` export to a
    /// vault the app reads and writes. The prompt's vault key is the
    /// existing vault, or the name of the new vault if `new_vault` is set.
    /// The export path and options travel in [`ImportItemsPayload`].
    ImportItems { new_vault: bool },

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

/// A login as the access prompt describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginDetails {
    pub title: String,
    pub username: Option<String>,
    pub vault_name: Option<String>,
    /// Hosts the login is saved for, without duplicates.
    pub hosts: Vec<String>,
}

/// The page a login request is for, reduced to what the prompt shows and a
/// grant is keyed on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginPage {
    /// The top-level page URL as the client sent it. Matching uses it only for
    /// a cross-site frame, whose login must be stored for both sites.
    pub url: String,
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
            url: url.to_string(),
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

    /// Top-level host for messages about a cross-site frame.
    pub fn top_label(&self) -> &str {
        self.top_host.as_deref().unwrap_or("another site")
    }

    /// Refuse a login picked from the logins that do not match, if the form is
    /// in a frame of another site. A cross-site frame is filled only with a
    /// login stored for both sites, so a pick from "All logins" never applies.
    pub fn refuse_unmatched_cross_site(self, unmatched: bool) -> Result<Self, String> {
        if self.cross_site && unmatched {
            return Err(self.unmatched_cross_site_message());
        }
        Ok(self)
    }

    /// Refusal of a login picked from "All logins" for a cross-site frame.
    pub fn unmatched_cross_site_message(&self) -> String {
        format!(
            "AutoFill fills a form on {host} inside a page on {top} only with a login saved for \
             both sites. Add {host} and {top} to the login's websites to fill it here.",
            host = self.host,
            top = self.top_label(),
        )
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

/// The bundle an [`VaultAction::ImportVaults`] reads, its decryption identity,
/// and the selected vaults. Kept out of [`VaultAccessPrompt`].
#[derive(Clone)]
pub struct ImportPayload {
    pub import_path: PathBuf,
    pub identity: WireImportIdentity,
    pub selection: Vec<WireImportSelection>,
}

/// The export an [`VaultAction::ImportItems`] reads and where it writes. Kept
/// out of [`VaultAccessPrompt`].
#[derive(Clone)]
pub struct ImportItemsPayload {
    pub import_path: PathBuf,
    pub include_trashed: bool,
    pub target: WireImportTarget,
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
    ImportItems(ImportItemsPayload),
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

impl VaultAccessPrompt {
    /// Whether an earlier approval may answer this request, and whether this
    /// request may leave one behind. False for a fill or a one-time code in a
    /// cross-site frame, which always prompts.
    pub fn may_reuse_approval(&self) -> bool {
        match &self.action {
            VaultAction::FillLogin { page, .. } | VaultAction::GenerateTotp { page, .. } => {
                !page.cross_site
            },
            _ => true,
        }
    }
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

/// What the app returned for a prompt: the context to unlock on, and whether an
/// approval the user gave earlier answered the request with no prompt.
pub struct VaultAuthorization {
    pub context: ForeignContext,
    pub reused: bool,
}

impl From<ForeignContext> for VaultAuthorization {
    fn from(context: ForeignContext) -> Self {
        Self {
            context,
            reused: false,
        }
    }
}

/// Supplies an `LAContext` to unlock the vault on, and learns how the attempt
/// ended so it can take its prompt down.
#[async_trait]
pub trait VaultAuthorizer: Send + Sync + 'static {
    /// Prepare a context for `prompt` and put the prompt on screen. The broker
    /// unlocks on the returned context, which is what makes the attached
    /// `LAAuthenticationView` draw. `peer` is the process the broker verified.
    async fn begin(
        &self,
        prompt: VaultAccessPrompt,
        peer: Actor,
    ) -> Result<VaultAuthorization, String>;

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

    /// The vault the user chose to save a login in, read after `begin` returns
    /// for a [`VaultAction::SaveLogin`]. `None` means the user did not choose,
    /// and the prompt's default vault applies. The broker checks the answer
    /// against the vaults it offered.
    async fn save_vault(&self, _prompt: &VaultAccessPrompt) -> Option<String> {
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

    /// The broker filled a login for a verified browser from an approval the
    /// user gave earlier, so no prompt was shown. `account` is the filled
    /// username. Called after `end`. The app reports the fill, since nothing
    /// else on screen shows it.
    async fn notify_preapproved(&self, _prompt: VaultAccessPrompt, _account: Option<String>) {}

    /// A site report about a passkey was recorded. The app refreshes what it
    /// shows and what it offers in AutoFill. The vaults are unchanged.
    async fn passkey_reports_changed(&self) {}
}
