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
//! records the `secret.read`, `vault.items_listed`, `vault.exported`,
//! `vault.imported` and `vault.linked` events, the same way the SSH agent
//! records `ssh.sign`. Export and import also emit the per-vault events that
//! the core records internally, sourced to the app.

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use super::login_index::LoginIndex;
use super::placement::{PasskeyChoices, PasskeyPlacement, PlacementVault};
use super::{
    Authorizers, BrokerError, BrowserClient, ConfirmPrompt, InFlightRequest, PromptOutcome,
    WireRequest, WireResponse, send_request,
};
use crate::audit::{self, Action, Actor, AuditEvent, Outcome, Subject, SubjectKind};
use crate::core::auth::{AuthContext, ForeignContext};
use crate::core::config::APP_CONFIG;
use crate::core::dirs::vaults_dir;
use crate::core::provenance::ProcessNode;
use crate::secrets::vaults::vault_export::{ExportMode, ImportIdentity, WorkFactor};
use crate::secrets::vaults::{
    DEFAULT_VAULT, FieldKind, MatchKind, Site, VaultWrapper, VaultsManager, autofill, passkey,
};

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
    AssertPasskey { rp_id: String },
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

/// How the export bundle key is protected, as it crosses the socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WireExportMode {
    /// A passphrase and the resolved scrypt `log_n`.
    Passphrase { passphrase: String, work_factor: u8 },
    /// An age recipient (`age1...`).
    Recipient { recipient: String },
}

impl From<WireExportMode> for ExportMode {
    fn from(mode: WireExportMode) -> Self {
        match mode {
            WireExportMode::Passphrase {
                passphrase,
                work_factor,
            } => ExportMode::Passphrase {
                passphrase: passphrase.into(),
                work_factor: WorkFactor::Custom(work_factor),
            },
            WireExportMode::Recipient { recipient } => ExportMode::Recipient(recipient),
        }
    }
}

/// How the import bundle is decrypted, as it crosses the socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WireImportIdentity {
    Passphrase {
        passphrase: String,
    },
    /// An age secret key (`AGE-SECRET-KEY-1...`).
    Identity {
        identity: String,
    },
}

impl TryFrom<WireImportIdentity> for ImportIdentity {
    type Error = String;

    fn try_from(identity: WireImportIdentity) -> Result<Self, Self::Error> {
        match identity {
            WireImportIdentity::Passphrase { passphrase } => {
                Ok(ImportIdentity::Passphrase(passphrase.into()))
            },
            WireImportIdentity::Identity { identity } => age::x25519::Identity::from_str(&identity)
                .map(ImportIdentity::Identity)
                .map_err(|e| format!("Invalid age identity: {e}")),
        }
    }
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

    /// The attempt finished. Always called once `begin` has been called, so the
    /// app can take the prompt down and settle the authorization it handed out.
    async fn end(&self, prompt: VaultAccessPrompt, outcome: PromptOutcome);
}

/// Ask the app to unlock a vault and return its item overview. Blocking: it may
/// wait for the user to answer a prompt, so call it from a thread that can
/// block. Starts the app if it is not already running.
pub fn request_vault_items(
    vault_key: &str,
    caller: Option<&str>,
) -> Result<Vec<BrokerVaultItem>, BrokerError> {
    let request = WireRequest::ListVaultItems {
        vault_key: vault_key.to_string(),
        caller: caller.map(String::from),
    };
    match send_request(&request)? {
        WireResponse::VaultItems { items } => Ok(items),
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to vault listing".to_string(),
        )),
    }
}

/// Ask the app to unlock a vault and return one credential's secret. `None`
/// means the credential does not exist. Blocking, same as
/// [`request_vault_items`].
pub fn request_vault_secret(
    vault_key: &str,
    item_key: &str,
    credential_key: &str,
    caller: Option<&str>,
) -> Result<Option<SecretString>, BrokerError> {
    let request = WireRequest::ReadVaultSecret {
        vault_key: vault_key.to_string(),
        item_key: item_key.to_string(),
        credential_key: credential_key.to_string(),
        caller: caller.map(String::from),
    };
    match send_request(&request)? {
        WireResponse::VaultSecret { value } => Ok(value.map(SecretString::from)),
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to vault secret read".to_string(),
        )),
    }
}

/// Ask the app to resolve many `axo://` references at once, behind one prompt.
/// The returned vector is positionally matched to `refs`; `None` means that
/// reference does not resolve. Blocking, same as [`request_vault_items`].
pub fn request_resolve_secrets(
    refs: &[VaultRef],
    purpose: ResolvePurpose,
    caller: Option<&str>,
) -> Result<Vec<Option<SecretString>>, BrokerError> {
    let request = WireRequest::ResolveSecrets {
        refs: refs.to_vec(),
        purpose,
        caller: caller.map(String::from),
    };
    match send_request(&request)? {
        WireResponse::ResolvedSecrets { values } => Ok(values
            .into_iter()
            .map(|v| v.map(SecretString::from))
            .collect()),
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to secret resolution".to_string(),
        )),
    }
}

/// Ask the app to unlock a vault and write one credential's secret value,
/// creating the item or credential if needed. Returns whether the item was
/// newly created. Blocking, same as [`request_vault_items`].
pub fn request_write_vault_secret(
    vault_key: &str,
    item_key: &str,
    credential_key: &str,
    title: &str,
    value: &SecretString,
    login: Option<WireLogin>,
    caller: Option<&str>,
) -> Result<bool, BrokerError> {
    let request = WireRequest::WriteVaultSecret {
        vault_key: vault_key.to_string(),
        item_key: item_key.to_string(),
        credential_key: credential_key.to_string(),
        title: title.to_string(),
        value: value.expose_secret().to_string(),
        login,
        caller: caller.map(String::from),
    };
    match send_request(&request)? {
        WireResponse::VaultWritten { created } => Ok(created),
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to vault secret write".to_string(),
        )),
    }
}

/// Ask the app to unlock every named vault and write an encrypted bundle to
/// `dest_path`. Blocking, same as [`request_vault_items`].
pub fn request_export_vaults(
    vault_keys: &[String],
    dest_path: &str,
    mode: WireExportMode,
    include_passkeys: bool,
    caller: Option<&str>,
) -> Result<u32, BrokerError> {
    let request = WireRequest::ExportVaults {
        vault_keys: vault_keys.to_vec(),
        dest_path: dest_path.to_string(),
        mode,
        exclude_passkeys: !include_passkeys,
        caller: caller.map(String::from),
    };
    match send_request(&request)? {
        WireResponse::VaultsExported { count } => Ok(count),
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to vault export".to_string(),
        )),
    }
}

/// Ask the app to import the selected vaults from a bundle, re-wrapping each
/// file key with the local encryption key. `selection` is `(bundle vault id,
/// target key)` pairs. Returns the keys of the imported vaults. Blocking, same
/// as [`request_vault_items`].
pub fn request_import_vaults(
    import_path: &str,
    identity: WireImportIdentity,
    selection: &[(String, String)],
    caller: Option<&str>,
) -> Result<Vec<String>, BrokerError> {
    let request = WireRequest::ImportVaults {
        import_path: import_path.to_string(),
        identity,
        selection: selection.to_vec(),
        caller: caller.map(String::from),
    };
    match send_request(&request)? {
        WireResponse::VaultsImported { keys } => Ok(keys),
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to vault import".to_string(),
        )),
    }
}

/// Ask the app to unlock the vault at `path` to validate it, then register it
/// as an external vault. Returns the vault key and name. Blocking, same as
/// [`request_vault_items`].
pub fn request_add_external_vault(
    path: &str,
    caller: Option<&str>,
) -> Result<(String, Option<String>), BrokerError> {
    let request = WireRequest::AddExternalVault {
        path: path.to_string(),
        caller: caller.map(String::from),
    };
    match send_request(&request)? {
        WireResponse::VaultLinked { vault_key, name } => Ok((vault_key, name)),
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to vault add".to_string(),
        )),
    }
}

/// Ask the app to register a passkey against an unlocked vault and return the
/// attestation. Blocking, same as [`request_vault_items`].
pub fn request_create_passkey(
    request: passkey::CreatePasskeyRequest,
    caller: Option<&str>,
) -> Result<passkey::CreatePasskeyResponse, BrokerError> {
    let wire = WireRequest::CreatePasskey {
        rp_id: request.rp_id.clone(),
        rp_name: request.rp_name.clone(),
        user_handle: b64_encode(&request.user_handle),
        user_name: request.user_name.clone(),
        user_display_name: request.user_display_name.clone(),
        client_data_hash: b64_encode(&request.client_data_hash),
        algorithms: request.algorithms.clone(),
        excluded_credentials: request
            .excluded_credentials
            .iter()
            .map(|c| b64_encode(c))
            .collect(),
        origin: None,
        caller: caller.map(String::from),
        client: BrowserClient::default(),
    };
    match send_request(&wire)? {
        WireResponse::PasskeyRegistered {
            credential_id,
            attestation_object,
        } => Ok(passkey::CreatePasskeyResponse {
            credential_id: b64_decode(&credential_id)?,
            attestation_object: b64_decode(&attestation_object)?,
        }),
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to passkey registration".to_string(),
        )),
    }
}

/// Ask the app to sign an assertion challenge with a stored passkey. Blocking,
/// same as [`request_vault_items`].
pub fn request_assert_passkey(
    request: passkey::AssertPasskeyRequest,
    caller: Option<&str>,
) -> Result<passkey::AssertPasskeyResponse, BrokerError> {
    let wire = WireRequest::AssertPasskey {
        rp_id: request.rp_id.clone(),
        client_data_hash: b64_encode(&request.client_data_hash),
        allowed_credentials: request
            .allowed_credentials
            .iter()
            .map(|c| b64_encode(c))
            .collect(),
        origin: None,
        caller: caller.map(String::from),
        client: BrowserClient::default(),
    };
    match send_request(&wire)? {
        WireResponse::PasskeyAsserted {
            credential_id,
            user_handle,
            authenticator_data,
            signature,
        } => Ok(passkey::AssertPasskeyResponse {
            credential_id: b64_decode(&credential_id)?,
            user_handle: b64_decode(&user_handle)?,
            authenticator_data: b64_decode(&authenticator_data)?,
            signature: b64_decode(&signature)?,
        }),
        WireResponse::Cancelled => Err(BrokerError::Cancelled),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to passkey assertion".to_string(),
        )),
    }
}

fn b64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn b64_decode(value: &str) -> Result<Vec<u8>, BrokerError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|e| BrokerError::Failed(format!("Malformed base64 in passkey response: {e}")))
}

/// Raise the app's prompt and return the context to unlock on. When the user
/// declines, the response to send instead.
async fn authorize(
    authorizer: &dyn VaultAuthorizer,
    prompt: &VaultAccessPrompt,
    actor: &Actor,
    in_flight: &InFlightRequest,
) -> Result<ForeignContext, WireResponse> {
    if in_flight.is_abandoned() {
        return Err(WireResponse::Cancelled);
    }
    // The app evaluates inside `begin`, holding the auth lock, so it is
    // dismissed rather than dropped when the client disconnects.
    let begin = authorizer.begin(prompt.clone(), actor.clone());
    let context = match in_flight.abandoning(begin, authorizer.abandon()).await {
        Ok(context) => context,
        Err(message) => {
            log::debug!("App broker vault authorization declined: {message}");
            record_access(prompt, actor, Outcome::Denied, None, Some(&message));
            authorizer
                .end(prompt.clone(), PromptOutcome::Failed(message.clone()))
                .await;
            return Err(WireResponse::Failed { message });
        },
    };
    // An import unlocks and writes one vault at a time on this context, so
    // invalidating it partway would leave some vaults imported and others not.
    if !matches!(prompt.action, VaultAction::ImportVaults { .. }) {
        in_flight.attach(&context);
    }
    Ok(context)
}

/// Serve a login request: a listing, a fill, a one-time code, a save, or a
/// password update. The same as [`authorize_and_serve`], plus one step: a
/// request the broker doubts is returned or written only after the user
/// confirms it, once the vault is open and the broker can tell. A login that
/// matches the page only through its `Url` field is one such case, and so is a
/// password update from a page the login is not stored for.
pub(super) async fn authorize_and_serve_logins(
    authorizers: &Authorizers,
    prompt: VaultAccessPrompt,
    actor: Actor,
    payload: Option<VaultPayload>,
    in_flight: &InFlightRequest,
) -> WireResponse {
    let authorizer = &*authorizers.vault;
    let confirmer = &*authorizers.passphrase;
    let context = match authorize(authorizer, &prompt, &actor, in_flight).await {
        Ok(context) => context,
        Err(response) => return response,
    };

    let job = prompt.clone();
    let index = Arc::clone(&authorizers.logins);
    let result = tokio::task::spawn_blocking(move || serve_logins(&job, context, payload, &index))
        .await
        .unwrap_or_else(|e| Err(format!("Vault task failed: {e}")));

    let served = match result {
        Ok(served) => {
            let confirmed = match served.confirm {
                Some(question) => {
                    in_flight
                        .unless_abandoned(confirmer.confirm(question))
                        .await
                        == Some(true)
                },
                None => true,
            };
            if !confirmed {
                log::debug!("App broker login request was not confirmed");
                Err(None)
            } else {
                match served.commit {
                    Some(commit) => tokio::task::spawn_blocking(commit)
                        .await
                        .unwrap_or_else(|e| Err(format!("Vault task failed: {e}")))
                        .map_err(Some),
                    None => Ok(served.response),
                }
            }
        },
        Err(message) => Err(Some(message)),
    };

    let (response, outcome) = match served {
        Ok(response) => {
            record_access(&prompt, &actor, Outcome::Succeeded, Some(&response), None);
            (response, PromptOutcome::Succeeded)
        },
        Err(None) => {
            record_access(
                &prompt,
                &actor,
                Outcome::Denied,
                None,
                Some("Not confirmed"),
            );
            (WireResponse::Cancelled, PromptOutcome::Cancelled)
        },
        Err(Some(message)) => {
            record_access(&prompt, &actor, Outcome::Failed, None, Some(&message));
            (
                WireResponse::Failed {
                    message: message.clone(),
                },
                PromptOutcome::Failed(message),
            )
        },
    };
    authorizer.end(prompt, outcome).await;
    response
}

pub(super) async fn authorize_and_serve(
    authorizer: &dyn VaultAuthorizer,
    mut prompt: VaultAccessPrompt,
    actor: Actor,
    mut payload: Option<VaultPayload>,
    in_flight: &InFlightRequest,
) -> WireResponse {
    let context = match authorize(authorizer, &prompt, &actor, in_flight).await {
        Ok(context) => context,
        Err(response) => return response,
    };

    // A registration is stored where the user chose in the prompt. The choice
    // is checked against what the prompt offered.
    if let VaultAction::CreatePasskey { choices, .. } = &prompt.action {
        let chosen = match authorizer.passkey_placement(&prompt).await {
            Some(placement) => choices.validate(placement),
            None => Ok(choices.default_placement()),
        };
        match chosen {
            Ok(placement) => {
                prompt.vault_key = placement.vault_key.clone();
                if let Some(VaultPayload::CreatePasskey(create)) = payload.as_mut() {
                    create.request.target = placement.target();
                }
            },
            Err(message) => {
                record_access(&prompt, &actor, Outcome::Failed, None, Some(&message));
                authorizer
                    .end(prompt, PromptOutcome::Failed(message.clone()))
                    .await;
                return WireResponse::Failed { message };
            },
        }
    }

    let job = prompt.clone();
    let rt = tokio::runtime::Handle::current();
    let result = tokio::task::spawn_blocking(move || serve_on_context(job, context, payload, rt))
        .await
        .unwrap_or_else(|e| Err(format!("Vault task failed: {e}")));

    let (response, outcome) = match result {
        Ok(response) => {
            record_access(&prompt, &actor, Outcome::Succeeded, Some(&response), None);
            (response, PromptOutcome::Succeeded)
        },
        Err(message) => {
            record_access(&prompt, &actor, Outcome::Failed, None, Some(&message));
            (
                WireResponse::Failed {
                    message: message.clone(),
                },
                PromptOutcome::Failed(message),
            )
        },
    };
    authorizer.end(prompt, outcome).await;
    response
}

/// Record one vault access. Values never appear: a read is named by its
/// `vault/item/credential` path, and a listing by its item count.
fn record_access(
    prompt: &VaultAccessPrompt,
    actor: &Actor,
    outcome: Outcome,
    response: Option<&WireResponse>,
    message: Option<&str>,
) {
    let vault_key = &prompt.vault_key;
    let (action, subject) = match &prompt.action {
        VaultAction::ListItems => (
            Action::VaultItemsListed,
            Subject::new(SubjectKind::Vault, vault_key.clone()),
        ),
        VaultAction::ReadSecret {
            item_key,
            credential_key,
        } => (
            Action::SecretRead,
            Subject::new(
                SubjectKind::Credential,
                format!("{vault_key}/{item_key}/{credential_key}"),
            ),
        ),
        VaultAction::ListLogins { page, .. } => (
            Action::VaultItemsListed,
            Subject::new(SubjectKind::Vault, page.host.clone()),
        ),
        VaultAction::FillLogin { record_id, .. } | VaultAction::GenerateTotp { record_id, .. } => (
            Action::SecretRead,
            Subject::new(SubjectKind::Credential, record_id.clone()),
        ),
        VaultAction::SaveLogin { .. } => (
            Action::VaultItemCreated,
            Subject::new(SubjectKind::Vault, vault_key.clone()),
        ),
        VaultAction::UpdateLoginPassword { record_id, .. } => (
            Action::VaultItemUpdated,
            Subject::new(SubjectKind::Credential, record_id.clone()),
        ),
        VaultAction::ResolveSecrets { purpose, .. } => {
            let action = match purpose {
                ResolvePurpose::Exec => Action::SecretExec,
                ResolvePurpose::Inject => Action::SecretInject,
                ResolvePurpose::Read => Action::SecretRead,
            };
            (action, Subject::new(SubjectKind::Vault, vault_key.clone()))
        },
        VaultAction::WriteSecret {
            item_key,
            credential_key,
        } => (
            Action::VaultItemUpdated,
            Subject::new(
                SubjectKind::Credential,
                format!("{vault_key}/{item_key}/{credential_key}"),
            ),
        ),
        VaultAction::ExportVaults { .. } => (
            Action::VaultExported,
            Subject::new(SubjectKind::Vault, vault_key.clone()),
        ),
        VaultAction::ImportVaults { .. } => (
            Action::VaultImported,
            Subject::new(SubjectKind::Vault, vault_key.clone()),
        ),
        VaultAction::AddVault { path } => (
            Action::VaultLinked,
            Subject::new(SubjectKind::Vault, path.clone()),
        ),
        VaultAction::CreatePasskey { rp_id, .. } => (
            Action::PasskeyRegistered,
            Subject::new(SubjectKind::Credential, rp_id.clone()),
        ),
        VaultAction::AssertPasskey { rp_id } => (
            Action::PasskeyAsserted,
            Subject::new(SubjectKind::Credential, rp_id.clone()),
        ),
    };

    // A write that created the item records `vault.item_created` instead. The
    // serve step reports which through the response.
    let action = match (&prompt.action, response) {
        (VaultAction::WriteSecret { .. }, Some(WireResponse::VaultWritten { created: true })) => {
            Action::VaultItemCreated
        },
        _ => action,
    };

    let mut event = AuditEvent::new(audit::process_source(), action, outcome)
        .subject(subject)
        .actor(actor.clone())
        .detail("vault", vault_key.clone())
        .detail("via", "broker");
    if let VaultAction::ResolveSecrets { refs, .. } = &prompt.action {
        event = event.detail("secret_count", refs.len().to_string());
    }
    match &prompt.action {
        VaultAction::ListLogins { page, all } => {
            event = event.detail("login_request", "list");
            if *all {
                event = event.detail("all_logins", "true");
            }
            event = login_page_details(event, page);
        },
        VaultAction::FillLogin {
            page, unmatched, ..
        } => {
            event = event.detail("login_request", "fill");
            if *unmatched {
                event = event.detail("unmatched", "true");
            }
            event = login_page_details(event, page);
        },
        VaultAction::GenerateTotp { page, .. } => {
            event = event.detail("login_request", "totp");
            event = login_page_details(event, page);
        },
        VaultAction::SaveLogin { page, .. } => {
            event = event.detail("login_request", "save");
            event = login_page_details(event, page);
        },
        VaultAction::UpdateLoginPassword { page, .. } => {
            event = event.detail("login_request", "update");
            event = login_page_details(event, page);
        },
        _ => {},
    }
    event = client_details(event, &prompt.client);
    match response {
        Some(WireResponse::VaultItems { items }) => {
            event = event.detail("item_count", items.len().to_string());
        },
        Some(WireResponse::Logins { logins, others }) => {
            event = event.detail("item_count", (logins.len() + others.len()).to_string());
        },
        Some(WireResponse::VaultSecret { value }) => {
            event = event.detail("found", value.is_some().to_string());
        },
        Some(WireResponse::ResolvedSecrets { values }) => {
            let resolved = values.iter().filter(|v| v.is_some()).count();
            event = event.detail("resolved_count", resolved.to_string());
        },
        Some(WireResponse::VaultWritten { created }) => {
            event = event.detail("created", created.to_string());
        },
        Some(WireResponse::VaultsExported { count }) => {
            event = event.detail("vault_count", count.to_string());
        },
        Some(WireResponse::VaultsImported { keys }) => {
            event = event.detail("vault_count", keys.len().to_string());
        },
        _ => {},
    }
    if let Some(message) = message {
        event = event.message(message.to_string());
    }
    audit::record(event);
}

/// The browser's name and signing team, and the extension the browser reported,
/// for a request that came through the browser host.
fn client_details(event: AuditEvent, client: &ClientIdentity) -> AuditEvent {
    let extension = |event: AuditEvent, extension: &Option<String>| match extension {
        Some(extension) => event.detail("extension", extension.clone()),
        None => event,
    };
    match client {
        ClientIdentity::Process => event,
        ClientIdentity::Browser {
            name,
            team_id,
            extension: reported,
        } => extension(
            event
                .detail("browser", name.clone())
                .detail("browser_team_id", team_id.clone()),
            reported,
        ),
        ClientIdentity::Unverified {
            extension: reported,
        } => extension(event.detail("browser", "unverified"), reported),
    }
}

/// The service host, the frame URL, and the top-level host of a login request.
/// Never a username or a value.
fn login_page_details(event: AuditEvent, page: &LoginPage) -> AuditEvent {
    let event = event
        .detail("service_host", page.host.clone())
        .detail("frame_origin", page.frame_origin.clone());
    match &page.top_host {
        Some(top_host) => event.detail("top_host", top_host.clone()),
        None => event,
    }
}

/// Load the vault from disk and serve the request on the app's context.
///
/// The vault is loaded fresh from disk and, for a write, saved straight back,
/// so this does not touch the app's in-memory vault state. The app's own CRUD
/// re-reads the file before every mutation (`with_unlocked_vault` calls
/// `unlock` each time), so a later UI edit does not clobber a write made here.
fn serve_on_context(
    prompt: VaultAccessPrompt,
    context: ForeignContext,
    payload: Option<VaultPayload>,
    rt: tokio::runtime::Handle,
) -> Result<WireResponse, String> {
    match &prompt.action {
        VaultAction::ResolveSecrets { refs, .. } => return resolve_secrets(refs, context),
        VaultAction::ListLogins { .. }
        | VaultAction::FillLogin { .. }
        | VaultAction::GenerateTotp { .. }
        | VaultAction::SaveLogin { .. }
        | VaultAction::UpdateLoginPassword { .. } => {
            return Err("Login requests are served by serve_logins".to_string());
        },
        VaultAction::CreatePasskey { .. } => {
            let Some(VaultPayload::CreatePasskey(p)) = payload else {
                return Err("Missing passkey registration payload".to_string());
            };
            return create_passkey(&prompt.vault_key, p.request, context, &rt);
        },
        VaultAction::AssertPasskey { .. } => {
            let Some(VaultPayload::AssertPasskey(p)) = payload else {
                return Err("Missing passkey assertion payload".to_string());
            };
            return assert_passkey(p.request, context, &rt);
        },
        VaultAction::ExportVaults { vault_keys } => {
            let Some(VaultPayload::Export(export)) = payload else {
                return Err("Missing export payload".to_string());
            };
            return export_vaults(vault_keys, export, context);
        },
        VaultAction::ImportVaults { .. } => {
            let Some(VaultPayload::Import(import)) = payload else {
                return Err("Missing import payload".to_string());
            };
            return import_vaults(import, context);
        },
        VaultAction::AddVault { path } => return add_external_vault(path, context),
        _ => {},
    }

    let write = match payload {
        Some(VaultPayload::Write(write)) => Some(write),
        None => None,
        Some(_) => return Err("Wrong payload for this vault action".to_string()),
    };

    let mut vw = VaultWrapper::load(&vaults_dir(), Some(prompt.vault_key.clone()))
        .map_err(|e| format!("Failed to load vault: {e}"))?;
    vw.unlock_on(AuthContext::Foreign(context))
        .map_err(|e| format!("Failed to unlock vault: {e}"))?;

    match prompt.action {
        VaultAction::ListItems => Ok(WireResponse::VaultItems {
            items: collect_items(&vw)?,
        }),
        VaultAction::ReadSecret {
            item_key,
            credential_key,
        } => {
            let value = vw
                .get_secret(&item_key, &credential_key)
                .map_err(|e| format!("Failed to get secret: {e}"))?
                .map(|secret| secret.expose_secret().to_string());
            Ok(WireResponse::VaultSecret { value })
        },
        VaultAction::WriteSecret {
            item_key,
            credential_key,
        } => {
            let payload = write.ok_or("Missing write payload")?;
            if let Some(login) = payload.login {
                let created = vw.get_item_overview(&item_key).ok().flatten().is_none();
                autofill::write_login(
                    &mut vw,
                    autofill::LoginWrite {
                        item_key: &item_key,
                        title: &payload.title,
                        password_key: &credential_key,
                        password: payload.value,
                        username: login.username.as_deref(),
                        websites: &login.websites,
                        match_kind: MatchKind::Domain,
                    },
                )
                .map_err(|e| format!("Failed to write login: {e}"))?;
                vw.save()
                    .map_err(|e| format!("Failed to save vault: {e}"))?;
                return Ok(WireResponse::VaultWritten { created });
            }
            // Keep an existing credential's kind so a value-only update does
            // not reset it; a new credential falls back to the default.
            let existing = vw
                .get_secret_overview(&item_key, &credential_key)
                .ok()
                .flatten();
            let created =
                existing.is_none() && vw.get_item_overview(&item_key).ok().flatten().is_none();
            let kind = existing
                .map(|o| o.kind.clone())
                .unwrap_or_else(FieldKind::default);
            vw.add_secret(
                &item_key,
                &credential_key,
                &payload.title,
                kind,
                payload.value,
            )
            .map_err(|e| format!("Failed to add secret: {e}"))?;
            vw.save()
                .map_err(|e| format!("Failed to save vault: {e}"))?;
            Ok(WireResponse::VaultWritten { created })
        },
        VaultAction::ResolveSecrets { .. }
        | VaultAction::ListLogins { .. }
        | VaultAction::FillLogin { .. }
        | VaultAction::GenerateTotp { .. }
        | VaultAction::SaveLogin { .. }
        | VaultAction::UpdateLoginPassword { .. }
        | VaultAction::ExportVaults { .. }
        | VaultAction::ImportVaults { .. }
        | VaultAction::AddVault { .. }
        | VaultAction::CreatePasskey { .. }
        | VaultAction::AssertPasskey { .. } => unreachable!("handled above"),
    }
}

/// The result of a login request, and the question the user must answer before
/// it is returned, when there is one.
struct LoginServed {
    response: WireResponse,
    confirm: Option<ConfirmPrompt>,
    /// Runs once the user has confirmed, for a request that changes a vault. It
    /// writes nothing before then. Its result replaces `response`.
    commit: Option<Commit>,
}

type Commit = Box<dyn FnOnce() -> Result<WireResponse, String> + Send>;

impl LoginServed {
    fn new(response: WireResponse) -> Self {
        Self {
            response,
            confirm: None,
            commit: None,
        }
    }
}

/// Serve a login request on the app's context. A vault that fails to load or
/// unlock is skipped rather than failing the request, so one broken vault does
/// not take AutoFill down.
fn serve_logins(
    prompt: &VaultAccessPrompt,
    context: ForeignContext,
    payload: Option<VaultPayload>,
    index: &LoginIndex,
) -> Result<LoginServed, String> {
    match (&prompt.action, payload) {
        (VaultAction::SaveLogin { page, username }, Some(VaultPayload::SaveLogin(save))) => {
            return save_login(prompt, page, username.as_deref(), save, context, index);
        },
        (
            VaultAction::UpdateLoginPassword {
                page, record_id, ..
            },
            Some(VaultPayload::UpdateLogin(update)),
        ) => return update_login_password(page, record_id, update, context),
        (VaultAction::SaveLogin { .. } | VaultAction::UpdateLoginPassword { .. }, _) => {
            return Err("Missing login payload".to_string());
        },
        _ => {},
    }

    let mut vm = VaultsManager::new();
    let vault_keys: Vec<String> = vm.iter_vault_keys().collect();
    let mut logins = Vec::new();
    let mut everything = Vec::new();

    for vault_key in vault_keys {
        let Some(vw) = vm.get_vault_mut(&vault_key) else {
            continue;
        };
        if let Err(e) = vw.unlock_on(AuthContext::Foreign(context.clone())) {
            log::error!("Failed to unlock vault {vault_key}: {e}");
            continue;
        }
        match &prompt.action {
            VaultAction::ListLogins { page, all } => {
                match autofill::collect_items(vw, Some(&page.frame_url)) {
                    Ok(found) => logins.extend(found),
                    Err(e) => log::error!("Failed to collect logins in {vault_key}: {e}"),
                }
                if *all {
                    match autofill::collect_items(vw, None) {
                        Ok(found) => everything.extend(found),
                        Err(e) => log::error!("Failed to collect logins in {vault_key}: {e}"),
                    }
                }
            },
            action => {
                if let Some(served) = serve_record(vw, action)? {
                    return Ok(served);
                }
            },
        }
    }

    match prompt.action {
        VaultAction::ListLogins { .. } => {
            logins.sort_by_key(autofill::AutofillItem::sort_key);
            // Only logins set up for AutoFill are listed. An item with a
            // confidential field but no website is a secret, not a login.
            everything.retain(|item| {
                !item.websites.is_empty() && !logins.iter().any(|m| m.record_id == item.record_id)
            });
            everything.sort_by_key(|item| item.title.to_lowercase());
            Ok(LoginServed::new(WireResponse::Logins {
                logins: logins
                    .iter()
                    .filter_map(autofill::AutofillItem::summary)
                    .collect(),
                others: everything
                    .iter()
                    .map(autofill::AutofillItem::other)
                    .collect(),
            }))
        },
        _ => Err("No login matches that record on this page".to_string()),
    }
}

/// Serve a fill or a one-time code from `vw`, when the record is a login in it
/// that matches the page. The match is decided here, from the vault, whatever
/// the client believes.
fn serve_record(vw: &VaultWrapper, action: &VaultAction) -> Result<Option<LoginServed>, String> {
    use secrecy::ExposeSecret;

    let (page, record_id, totp, unmatched) = match action {
        VaultAction::FillLogin {
            page,
            record_id,
            unmatched,
            ..
        } => (page, record_id, false, *unmatched),
        VaultAction::GenerateTotp { page, record_id } => (page, record_id, true, false),
        _ => return Err("Not a login record request".to_string()),
    };
    let found = autofill::find_login(vw, record_id, &page.frame_url)
        .map_err(|e| format!("Failed to look up the login: {e}"))?;
    // A login picked from the list of logins that do not match is filled only
    // after the user confirms it.
    let (item, other_site) = match found {
        Some(item) => (item, false),
        None if unmatched => {
            match autofill::find_login_record(vw, record_id)
                .map_err(|e| format!("Failed to look up the login: {e}"))?
            {
                Some(item) => (item, true),
                None => return Ok(None),
            }
        },
        None => return Ok(None),
    };

    let confirm = if other_site {
        Some(ConfirmPrompt {
            description: Some(format!(
                "\"{}\" is saved for {}, not {}.\n\nFill it on {}?",
                item.title,
                stored_hosts(&item),
                page.host,
                page.host
            )),
            ok_label: Some("Fill".to_string()),
            cancel_label: Some("Cancel".to_string()),
        })
    } else {
        item.websites_from_url_fields.then(|| ConfirmPrompt {
            description: Some(format!(
                "\"{}\" lists no website. It matches {} only through a URL field.\n\nFill it on {}?",
                item.title, page.host, page.host
            )),
            ok_label: Some("Fill".to_string()),
            cancel_label: Some("Cancel".to_string()),
        })
    };

    let response = if totp {
        let code = autofill::login_totp(vw, &item).map_err(|e| e.to_string())?;
        WireResponse::TotpCode { code }
    } else {
        let secrets = autofill::read_login(vw, &item)
            .map_err(|e| format!("Failed to read the login: {e}"))?
            .ok_or_else(|| "That login no longer has a password".to_string())?;
        WireResponse::LoginFill {
            username: secrets.username,
            password: secrets.password.expose_secret().to_string(),
        }
    };
    Ok(Some(LoginServed {
        response,
        confirm,
        commit: None,
    }))
}

/// The hosts a login is stored for, as a comma-separated list for a question to
/// the user.
fn stored_hosts(item: &autofill::AutofillItem) -> String {
    let sites: Vec<String> = item
        .websites
        .iter()
        .map(|website| Site::parse(&website.url).map_or(website.url.clone(), |s| s.host))
        .collect();
    if sites.is_empty() {
        "no website".to_string()
    } else {
        sites.join(", ")
    }
}

/// The vaults and logins a passkey for `rp_id` may be stored in, for the
/// registration prompt. The logins come from the index, so a cold start offers
/// only "New login".
pub(super) fn passkey_choices(rp_id: &str, user_name: &str, index: &LoginIndex) -> PasskeyChoices {
    let vm = VaultsManager::new();
    let vaults = vm
        .iter_vaults()
        .map(|(key, vw)| PlacementVault {
            key: key.clone(),
            name: vw.vault_name().map(String::from),
        })
        .collect();
    PasskeyChoices::build(rp_id, user_name, &index.places(), vaults, write_vault_key())
}

/// Save a captured login as a new item in the vault the prompt named.
fn save_login(
    prompt: &VaultAccessPrompt,
    page: &LoginPage,
    username: Option<&str>,
    save: SaveLoginPayload,
    context: ForeignContext,
    index: &LoginIndex,
) -> Result<LoginServed, String> {
    let mut vw = VaultWrapper::load(&vaults_dir(), Some(prompt.vault_key.clone()))
        .map_err(|e| format!("Failed to load vault: {e}"))?;
    vw.unlock_on(AuthContext::Foreign(context))
        .map_err(|e| format!("Failed to unlock vault: {e}"))?;

    let item = autofill::save_login(&mut vw, &page.frame_origin, username, save.password)
        .map_err(|e| format!("Failed to write login: {e}"))?;
    vw.save()
        .map_err(|e| format!("Failed to save vault: {e}"))?;

    let record_id = item.record_id.clone();
    index.upsert(item);
    Ok(LoginServed::new(WireResponse::LoginSaved { record_id }))
}

/// Find the login `record_id` names in whichever vault holds it and prepare to
/// replace its password. The login need not be stored for `page`: a password
/// captured on another site is a reason to ask the user, not to refuse. The
/// write is returned as a commit, so nothing changes before the user confirms.
fn update_login_password(
    page: &LoginPage,
    record_id: &str,
    update: UpdateLoginPayload,
    context: ForeignContext,
) -> Result<LoginServed, String> {
    let mut vm = VaultsManager::new();
    let vault_keys: Vec<String> = vm.iter_vault_keys().collect();

    let mut found = None;
    for vault_key in vault_keys {
        let Some(vw) = vm.get_vault_mut(&vault_key) else {
            continue;
        };
        if let Err(e) = vw.unlock_on(AuthContext::Foreign(context.clone())) {
            log::error!("Failed to unlock vault {vault_key}: {e}");
            continue;
        }
        match autofill::find_login_record(vw, record_id) {
            Ok(Some(item)) => {
                found = Some((vault_key, item));
                break;
            },
            Ok(None) => {},
            Err(e) => log::error!("Failed to look up a login in {vault_key}: {e}"),
        }
    }
    let Some((vault_key, item)) = found else {
        return Err("No login matches that record".to_string());
    };

    let confirm = (!autofill::is_stored_for(&item, &page.frame_url)).then(|| {
        let stored = stored_hosts(&item);
        ConfirmPrompt {
            description: Some(format!(
                "A form on {host} submitted a new password for \"{title}\", which is saved for \
                 {stored}, not {host}.\n\nUpdate its password?",
                host = page.host,
                title = item.title,
            )),
            ok_label: Some("Update".to_string()),
            cancel_label: Some("Cancel".to_string()),
        }
    });

    let commit: Commit = Box::new(move || {
        let vw = vm
            .get_vault_mut(&vault_key)
            .ok_or_else(|| format!("Vault {vault_key} is no longer available"))?;
        autofill::update_login_password(vw, &item, update.password)
            .map_err(|e| format!("Failed to update the password: {e}"))?;
        vw.save()
            .map_err(|e| format!("Failed to save vault: {e}"))?;
        Ok(WireResponse::Acknowledged)
    });
    Ok(LoginServed {
        response: WireResponse::Acknowledged,
        confirm,
        commit: Some(commit),
    })
}

/// The accounts for `page` from the login index, for a client that may list
/// without a prompt. `indexed` is false when nothing has been indexed since the
/// app started, so the client knows to ask with a prompt instead.
pub(super) fn list_logins_locked(
    prompt: &VaultAccessPrompt,
    actor: &Actor,
    index: &LoginIndex,
) -> WireResponse {
    let VaultAction::ListLogins { page, .. } = &prompt.action else {
        return WireResponse::Failed {
            message: "Not a login listing".to_string(),
        };
    };
    let found = index.lookup(&page.frame_url);
    let response = WireResponse::LockedLogins {
        indexed: found.is_some(),
        logins: found.unwrap_or_default(),
    };
    record_locked_listing(prompt, actor, &response);
    response
}

/// Record a listing served from the index. It reads no vault, so it is not an
/// access, but it still tells a client which accounts exist for a site.
fn record_locked_listing(prompt: &VaultAccessPrompt, actor: &Actor, response: &WireResponse) {
    let VaultAction::ListLogins { page, .. } = &prompt.action else {
        return;
    };
    let mut event = AuditEvent::new(
        audit::process_source(),
        Action::VaultItemsListed,
        Outcome::Succeeded,
    )
    .subject(Subject::new(SubjectKind::Vault, page.host.clone()))
    .actor(actor.clone())
    .detail("via", "broker")
    .detail("login_request", "list_locked");
    event = login_page_details(event, page);
    event = client_details(event, &prompt.client);
    if let WireResponse::LockedLogins { logins, indexed } = response {
        event = event
            .detail("item_count", logins.len().to_string())
            .detail("indexed", indexed.to_string());
    }
    audit::record(event);
}

/// The vault a new item from a client is written to: the default vault when it
/// exists or there are no vaults, otherwise the first one. The broker names
/// this vault in the prompt, so it is chosen before the prompt rather than
/// after.
pub(super) fn write_vault_key() -> String {
    let keys: Vec<String> = VaultsManager::new().iter_vault_keys().collect();
    if keys.is_empty() || keys.iter().any(|k| k == DEFAULT_VAULT) {
        DEFAULT_VAULT.to_string()
    } else {
        keys.into_iter().next().unwrap()
    }
}

/// Register a passkey in `vault_key` on the app's context.
fn create_passkey(
    vault_key: &str,
    request: passkey::CreatePasskeyRequest,
    context: ForeignContext,
    rt: &tokio::runtime::Handle,
) -> Result<WireResponse, String> {
    let mut vm = VaultsManager::new();
    let mut created;
    // With no vaults yet, `write_vault_key` names the default vault, which
    // loading creates.
    let vw = match vm.get_vault_mut(vault_key) {
        Some(vw) => vw,
        None => {
            created = VaultWrapper::load(&vaults_dir(), Some(vault_key.to_string()))
                .map_err(|e| format!("Failed to load vault {vault_key}: {e}"))?;
            &mut created
        },
    };
    vw.unlock_on(AuthContext::Foreign(context))
        .map_err(|e| format!("Failed to unlock vault {vault_key}: {e}"))?;

    let response = rt
        .block_on(passkey::create_from_wire(vw, request))
        .map_err(|e| format!("Failed to register the passkey: {e}"))?;
    Ok(WireResponse::PasskeyRegistered {
        credential_id: b64_encode(&response.credential_id),
        attestation_object: b64_encode(&response.attestation_object),
    })
}

/// Sign an assertion challenge with a stored passkey. The credential may be in
/// any vault, so each is tried until one holds a passkey for the relying party.
fn assert_passkey(
    request: passkey::AssertPasskeyRequest,
    context: ForeignContext,
    rt: &tokio::runtime::Handle,
) -> Result<WireResponse, String> {
    let mut vm = VaultsManager::new();
    let vault_keys: Vec<String> = vm.iter_vault_keys().collect();

    let mut last_error = None;
    for vault_key in vault_keys {
        let Some(vw) = vm.get_vault_mut(&vault_key) else {
            continue;
        };
        if let Err(e) = vw.unlock_on(AuthContext::Foreign(context.clone())) {
            log::error!("Failed to unlock vault {vault_key} for a passkey assertion: {e}");
            continue;
        }
        let holds_credential = passkey::list(vw)
            .map(|passkeys| passkeys.iter().any(|s| s.passkey.rp_id == request.rp_id))
            .unwrap_or(false);
        if !holds_credential {
            continue;
        }
        match rt.block_on(passkey::assert_from_wire(vw, request.clone())) {
            Ok(response) => {
                return Ok(WireResponse::PasskeyAsserted {
                    credential_id: b64_encode(&response.credential_id),
                    user_handle: b64_encode(&response.user_handle),
                    authenticator_data: b64_encode(&response.authenticator_data),
                    signature: b64_encode(&response.signature),
                });
            },
            Err(e) => last_error = Some(e.to_string()),
        }
    }

    Err(last_error.unwrap_or_else(|| "No stored passkey matched the request".to_string()))
}

/// Unlock every named vault on the app's context and write the export bundle.
fn export_vaults(
    vault_keys: &[String],
    export: ExportPayload,
    context: ForeignContext,
) -> Result<WireResponse, String> {
    let mut vm = VaultsManager::new();
    vm.export_bundle_on(
        vault_keys,
        &export.dest_path,
        export.mode,
        export.include_passkeys,
        AuthContext::Foreign(context),
        |_| {},
    )
    .map_err(|e| format!("Failed to export vaults: {e}"))?;
    Ok(WireResponse::VaultsExported {
        count: vault_keys.len() as u32,
    })
}

/// Re-open the bundle and import the selected vaults, re-wrapping each file key
/// with the local encryption key on the app's context.
fn import_vaults(import: ImportPayload, context: ForeignContext) -> Result<WireResponse, String> {
    let identity =
        ImportIdentity::try_from(import.identity).map_err(|e| format!("Invalid identity: {e}"))?;

    let mut selection: std::collections::BTreeMap<uuid::Uuid, String> =
        std::collections::BTreeMap::new();
    for (id, key) in import.selection {
        let id = uuid::Uuid::parse_str(&id).map_err(|e| format!("Invalid vault id {id}: {e}"))?;
        selection.insert(id, key);
    }

    let mut vm = VaultsManager::new();
    let bundle = vm
        .open_bundle(&import.import_path, identity)
        .map_err(|e| format!("Failed to open bundle: {e}"))?;
    let keys = vm
        .import_bundle_on(bundle, &selection, AuthContext::Foreign(context))
        .map_err(|e| format!("Failed to import bundle: {e}"))?;
    Ok(WireResponse::VaultsImported { keys })
}

/// Unlock the vault at `path` to validate it, then register it as an external
/// vault in the app config.
fn add_external_vault(path: &str, context: ForeignContext) -> Result<WireResponse, String> {
    let path = Path::new(path)
        .canonicalize()
        .map_err(|e| format!("Could not resolve path {path}: {e}"))?;

    let mut vw = VaultWrapper::load_from_path(None, &path)
        .map_err(|e| format!("Not a valid vault file: {e}"))?;
    vw.unlock_on(AuthContext::Foreign(context))
        .map_err(|e| format!("Failed to unlock vault: {e}"))?;

    let name = vw.vault_name().map(str::to_string);
    APP_CONFIG
        .lock()
        .map_err(|e| format!("Failed to lock config: {e}"))?
        .add_external_vault(&vw.key, path)
        .map_err(|e| format!("Failed to add vault: {e}"))?;

    Ok(WireResponse::VaultLinked {
        vault_key: vw.key.clone(),
        name,
    })
}

/// Resolve every reference, unlocking each distinct vault once on the app's
/// context. The result is positionally matched to `refs`. A reference whose
/// vault fails to load or unlock resolves to `None` rather than failing the
/// whole batch.
fn resolve_secrets(refs: &[VaultRef], context: ForeignContext) -> Result<WireResponse, String> {
    use std::collections::HashMap;

    let vaults_dir = vaults_dir();
    let mut vaults: HashMap<String, Option<VaultWrapper>> = HashMap::new();
    let mut values = Vec::with_capacity(refs.len());

    for r in refs {
        let vw = vaults.entry(r.vault_key.clone()).or_insert_with(|| {
            match VaultWrapper::load(&vaults_dir, Some(r.vault_key.clone())) {
                Ok(mut vw) => match vw.unlock_on(AuthContext::Foreign(context.clone())) {
                    Ok(()) => Some(vw),
                    Err(e) => {
                        log::error!("Failed to unlock vault {}: {e}", r.vault_key);
                        None
                    },
                },
                Err(e) => {
                    log::error!("Failed to load vault {}: {e}", r.vault_key);
                    None
                },
            }
        });

        let value = match vw {
            Some(vw) => match vw.get_secret(&r.item_key, &r.credential_key) {
                Ok(secret) => secret.map(|s| s.expose_secret().to_string()),
                Err(e) => {
                    log::error!(
                        "Failed to get secret {}/{}/{}: {e}",
                        r.vault_key,
                        r.item_key,
                        r.credential_key
                    );
                    None
                },
            },
            None => None,
        };
        values.push(value);
    }

    Ok(WireResponse::ResolvedSecrets { values })
}

fn collect_items(vw: &VaultWrapper) -> Result<Vec<BrokerVaultItem>, String> {
    let mut items: Vec<BrokerVaultItem> = vw
        .list_items()
        .map_err(|e| format!("Failed to list items: {e}"))?
        .into_iter()
        .map(|item| BrokerVaultItem {
            key: item.key.clone(),
            title: item.title.clone(),
            credentials: item
                .credentials
                .values()
                .map(|c| BrokerCredential {
                    key: c.key.clone(),
                    title: c.title.clone(),
                })
                .collect(),
        })
        .collect();
    items.sort_by_key(|a| a.title.to_lowercase());
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault_with_github() -> (VaultWrapper, String) {
        let mut vw = VaultWrapper::new_for_test("personal");
        autofill::write_login(
            &mut vw,
            autofill::LoginWrite {
                item_key: "github",
                title: "GitHub",
                password_key: "password",
                password: SecretString::from("pw"),
                username: Some("tp"),
                websites: &["github.com".to_string()],
                match_kind: MatchKind::Domain,
            },
        )
        .unwrap();
        let record_id = autofill::collect_items(&vw, None).unwrap()[0]
            .record_id
            .clone();
        (vw, record_id)
    }

    fn fill(record_id: &str, frame_url: &str, unmatched: bool) -> VaultAction {
        VaultAction::FillLogin {
            page: LoginPage::parse(frame_url, frame_url, None).unwrap(),
            record_id: record_id.to_string(),
            account: None,
            unmatched,
        }
    }

    #[test]
    fn a_fill_on_the_matching_site_needs_no_question() {
        let (vw, record_id) = vault_with_github();
        let served = serve_record(&vw, &fill(&record_id, "https://gist.github.com", false))
            .unwrap()
            .unwrap();
        assert!(served.confirm.is_none());
    }

    #[test]
    fn a_fill_on_another_site_is_refused_unless_the_client_asks_for_it() {
        let (vw, record_id) = vault_with_github();
        let page = "https://example.org";
        assert!(
            serve_record(&vw, &fill(&record_id, page, false))
                .unwrap()
                .is_none()
        );

        let served = serve_record(&vw, &fill(&record_id, page, true))
            .unwrap()
            .unwrap();
        let question = served.confirm.expect("the user must confirm");
        let text = question.description.unwrap();
        assert!(
            text.contains("github.com") && text.contains("example.org"),
            "{text}"
        );
        assert!(matches!(served.response, WireResponse::LoginFill { .. }));
    }

    #[test]
    fn an_unmatched_fill_still_needs_a_record_that_exists() {
        let (vw, _) = vault_with_github();
        let missing = format!(
            "{}/{}/{}",
            vw.vault_id().unwrap(),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4()
        );
        assert!(
            serve_record(&vw, &fill(&missing, "https://example.org", true))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_one_time_code_is_never_served_for_another_site() {
        let (vw, record_id) = vault_with_github();
        let action = VaultAction::GenerateTotp {
            page: LoginPage::parse("https://example.org", "https://example.org", None).unwrap(),
            record_id,
        };
        assert!(serve_record(&vw, &action).unwrap().is_none());
    }
}
