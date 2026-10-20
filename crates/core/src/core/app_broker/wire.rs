//! The wire format between the broker's clients and the app.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as b64;
use serde::{Deserialize, Serialize};

use super::ssh::{ManagedIdentity, SignPurpose};
use super::{age, keychain, vault};
use crate::core::provenance::ProcessNode;
use crate::secrets::password::PasswordPolicy;
use crate::secrets::vaults::passkey::{
    PrfAssertionInput, PrfRegistrationInput, PrfRegistrationOutput, PrfValues,
};
use crate::secrets::vaults::totp::TotpCode;
use crate::secrets::vaults::{LoginSummary, OtherLogin};

/// What our browser host reports about the browser that started it. The broker
/// reads it only from a peer it verified as the host, and ignores it from any
/// other.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct BrowserClient {
    /// Set only when the host checked its parent's code signature against its
    /// fixed list of browsers. A host that could not check sends none.
    #[serde(default)]
    pub(super) browser: Option<VerifiedBrowser>,

    /// The extension id or origin the browser passed to the host. The host
    /// cannot verify it, so it is recorded for audit and never decides
    /// anything.
    #[serde(default)]
    pub(super) extension: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct VerifiedBrowser {
    /// The browser's display name, for example "Google Chrome".
    pub(super) name: String,
    /// The team identifier of the browser's code signature.
    pub(super) team_id: String,
}

/// The wire format: one JSON line each way, one request per connection.
#[derive(Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case")]
pub(super) enum WireRequest {
    ListIdentities,
    Sign {
        key_label: String,

        /// Canonical `SHA256:...` fingerprint of the key, resolved by the agent
        /// so the app's grant events name the key the same way its `ssh.sign`
        /// events do.
        #[serde(default)]
        fingerprint: Option<String>,

        /// The key's OpenSSH comment, when it has one.
        #[serde(default)]
        comment: Option<String>,

        /// Who asked the agent for the signature, resolved by the agent from
        /// its own peer's audit token.
        ///
        /// The broker cannot derive this itself. The requesting process talks
        /// to the agent, not to the broker, so the broker's peer is always the
        /// agent, whose process chain leads back to launchd. The value is
        /// trusted by delegation: the broker only accepts connections from an
        /// agent it has identified as our own signed code, and that agent
        /// resolves the caller from its own peer's audit token. A build with no
        /// code signature to check breaks that chain, which is what the warning
        /// in `agent_policy` reports.
        caller: Option<String>,

        /// The requesting process chain, resolved by the agent the same way and
        /// with the same delegated trust as `caller`. Lets the prompt show the
        /// full ancestry, which the broker cannot derive since its peer is the
        /// agent.
        #[serde(default)]
        caller_chain: Vec<ProcessNode>,

        /// What the signature is for, read by the agent from the request. The
        /// agent reads it rather than the broker, because only the agent holds
        /// the session bindings that name the destination host.
        #[serde(default)]
        purpose: Option<SignPurpose>,

        /// Base64 of the bytes to sign.
        data: String,

        /// The agent sign request's flags, e.g. `SSH_AGENT_RSA_SHA2_512`.
        #[serde(default)]
        flags: u32,
    },

    /// A GPG passphrase, either unlocked from the keychain behind a biometric
    /// prompt or typed by the user. See [`PassphrasePrompt`].
    GetPassphrase {
        key_id: Option<String>,
        description: Option<String>,
        prompt: Option<String>,
        error_message: Option<String>,
        /// Delegated the same way as [`WireRequest::Sign`]'s caller.
        caller: Option<String>,
        /// Delegated the same way as [`WireRequest::Sign`]'s caller_chain.
        #[serde(default)]
        caller_chain: Vec<ProcessNode>,
    },

    /// A passphrase for `SSH_ASKPASS`: either unlocked from the keychain
    /// behind a biometric prompt or typed by the user. See
    /// [`ssh::get_passphrase`].
    GetSshPassphrase {
        /// The keychain fingerprint of the key this prompt names, resolved by
        /// `ap ssh-askpass` from the prompt text. Absent for a prompt that
        /// names no key, e.g. `user@host's password:`.
        key_id: Option<String>,
        /// ssh's own prompt text.
        prompt: String,
        /// Comment of the key, shown as its name in the prompt.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        /// Delegated the same way as [`WireRequest::Sign`]'s caller.
        caller: Option<String>,
        /// Delegated the same way as [`WireRequest::Sign`]'s caller_chain.
        #[serde(default)]
        caller_chain: Vec<ProcessNode>,
    },

    /// A confirm-on-use prompt for a key held by the agent, added with
    /// `ssh-add -c`. The agent still signs; the app only draws the prompt and
    /// evaluates the auth check on a context it owns. The key cannot be used
    /// when the app does not answer.
    AuthorizeKeyUse {
        /// Canonical `SHA256:...` fingerprint, resolved by the agent.
        #[serde(default)]
        fingerprint: Option<String>,

        /// The key's OpenSSH comment, when it has one.
        #[serde(default)]
        comment: Option<String>,

        /// Who asked, delegated the same way as [`WireRequest::Sign`]'s caller.
        #[serde(default)]
        caller: Option<String>,

        /// Delegated the same way as [`WireRequest::Sign`]'s caller_chain.
        #[serde(default)]
        caller_chain: Vec<ProcessNode>,

        /// See [`WireRequest::Sign`]'s purpose.
        #[serde(default)]
        purpose: Option<SignPurpose>,

        /// Whether an app grant may answer this prompt, and the prompt may
        /// offer one. True for an auto-loaded key. False for a key added with
        /// `ssh-add -c`, which prompts on every use.
        #[serde(default)]
        allow_grants: bool,
    },

    /// `ap item list`: unlock a vault and return its item overview, never a
    /// secret.
    ListVaultItems {
        vault_key: String,
        /// Delegated the same way as [`WireRequest::Sign`]'s caller.
        #[serde(default)]
        caller: Option<String>,
    },

    /// `ap read`: unlock a vault and return one credential's secret value.
    ReadVaultSecret {
        vault_key: String,
        item_key: String,
        credential_key: String,
        /// Delegated the same way as [`WireRequest::Sign`]'s caller.
        #[serde(default)]
        caller: Option<String>,
    },

    /// The logins that match `frame_url`, across every vault. Each carries its
    /// record id, username, title, and the stored website that matched. No
    /// password is included. See [`WireRequest::FillLogin`].
    ListLogins {
        /// The page's top-level URL. Shown in the prompt when the form is in a
        /// frame of another site.
        url: String,
        /// The URL of the frame that holds the form. Matching uses this one.
        frame_url: String,
        /// Also list the logins that do not match, so the user can still pick
        /// one. They come back without their websites, and filling one asks
        /// the user to confirm. See [`WireRequest::FillLogin`]'s `unmatched`.
        #[serde(default)]
        all: bool,
        /// The name of the app the request is for, when it is not a browser.
        /// A display hint, like `account` on [`WireRequest::FillLogin`]. Only
        /// the AutoFill extension may send one. A request from any other client
        /// is for a browser.
        #[serde(default)]
        requester: Option<String>,
        /// Delegated the same way as [`WireRequest::Sign`]'s caller.
        #[serde(default)]
        caller: Option<String>,
        /// See [`BrowserClient`].
        #[serde(default)]
        client: BrowserClient,
    },

    /// [`WireRequest::ListLogins`] answered from the app's login index, with no
    /// prompt and no vault access. Only the AutoFill extension and a browser
    /// host with a verified browser may send it: it tells the client which
    /// accounts exist for a site without the user's approval, so any other
    /// client is refused. It never lists logins for a page other than
    /// `frame_url`.
    ListLoginsLocked {
        url: String,
        frame_url: String,
        /// See [`WireRequest::ListLogins`].
        #[serde(default)]
        requester: Option<String>,
        /// Delegated the same way as [`WireRequest::Sign`]'s caller.
        #[serde(default)]
        caller: Option<String>,
        /// See [`BrowserClient`].
        #[serde(default)]
        client: BrowserClient,
    },

    /// The username and password of one login. The broker re-checks that the
    /// record is a login with a website matching `frame_url`, so a client
    /// cannot fill a record by guessing its id.
    FillLogin {
        url: String,
        frame_url: String,
        /// `<vault uuid>/<item uuid>/<password credential uuid>`, as returned
        /// by [`WireRequest::ListLogins`].
        record_id: String,
        /// The account name the client showed the user. The prompt displays
        /// it so the user sees which login is being filled before the vault
        /// opens. It is a hint from the client and is never used to decide
        /// anything.
        #[serde(default)]
        account: Option<String>,
        /// The client is filling a login from the list of logins that do not
        /// match the page. Without it, a record that does not match
        /// `frame_url` is refused. With it, the broker asks the user to
        /// confirm before it returns the login.
        #[serde(default)]
        unmatched: bool,
        /// See [`WireRequest::ListLogins`].
        #[serde(default)]
        requester: Option<String>,
        /// Delegated the same way as [`WireRequest::Sign`]'s caller.
        #[serde(default)]
        caller: Option<String>,
        /// See [`BrowserClient`].
        #[serde(default)]
        client: BrowserClient,
    },

    /// The current one-time code of one login, checked the same way as
    /// [`WireRequest::FillLogin`].
    GenerateTotp {
        url: String,
        frame_url: String,
        record_id: String,
        /// See [`WireRequest::ListLogins`].
        #[serde(default)]
        requester: Option<String>,
        /// Delegated the same way as [`WireRequest::Sign`]'s caller.
        #[serde(default)]
        caller: Option<String>,
        /// See [`BrowserClient`].
        #[serde(default)]
        client: BrowserClient,
    },

    /// A random password from the core generator, for a browser's
    /// `new-password` field. It reads no vault and saves nothing, so it
    /// raises no prompt.
    GeneratePassword {
        /// The default policy when absent.
        #[serde(default)]
        policy: Option<PasswordPolicy>,
        /// Delegated the same way as [`WireRequest::Sign`]'s caller.
        #[serde(default)]
        caller: Option<String>,
    },

    /// Save a login a browser captured from a form submission as a new item.
    /// The website is stored with `host` matching. The user is always prompted,
    /// since script on the page can fake a submission.
    SaveLogin {
        url: String,
        frame_url: String,
        #[serde(default)]
        username: Option<String>,
        password: String,
        /// Delegated the same way as [`WireRequest::Sign`]'s caller.
        #[serde(default)]
        caller: Option<String>,
        /// See [`BrowserClient`].
        #[serde(default)]
        client: BrowserClient,
    },

    /// Replace the password of one login with the one a browser captured from a
    /// form submission. The user is always prompted, and is asked again when
    /// the login is not stored for `frame_url`.
    UpdateLoginPassword {
        url: String,
        frame_url: String,
        record_id: String,
        password: String,
        /// The account name the client showed the user. The prompt displays
        /// it. It is never used to decide anything.
        #[serde(default)]
        account: Option<String>,
        /// Delegated the same way as [`WireRequest::Sign`]'s caller.
        #[serde(default)]
        caller: Option<String>,
        /// See [`BrowserClient`].
        #[serde(default)]
        client: BrowserClient,
    },

    /// `ap exec` / `ap inject`: resolve many `axo://` references at once,
    /// possibly across several vaults, behind one prompt.
    ResolveSecrets {
        refs: Vec<vault::VaultRef>,
        purpose: vault::ResolvePurpose,
        /// Delegated the same way as [`WireRequest::Sign`]'s caller.
        #[serde(default)]
        caller: Option<String>,
    },

    /// `ap item set`: unlock a vault and write one credential's secret value,
    /// creating the item or credential if it does not exist.
    WriteVaultSecret {
        vault_key: String,
        item_key: String,
        credential_key: String,
        title: String,
        value: String,
        /// Present when the value is a login's password and the item is
        /// written as a login.
        #[serde(default)]
        login: Option<vault::WireLogin>,
        /// Delegated the same way as [`WireRequest::Sign`]'s caller.
        #[serde(default)]
        caller: Option<String>,
    },

    /// `ap vault export`: unlock every named vault and write an encrypted
    /// bundle to `dest_path`.
    ExportVaults {
        vault_keys: Vec<String>,
        dest_path: String,
        mode: vault::WireExportMode,
        /// Leave passkeys out of the bundle. They are included by default.
        #[serde(default)]
        exclude_passkeys: bool,
        #[serde(default)]
        caller: Option<String>,
    },

    /// `ap vault import`: import the selected vaults from a bundle, re-wrapping
    /// each file key with the local encryption key.
    ImportVaults {
        import_path: String,
        identity: vault::WireImportIdentity,
        /// `(bundle vault id, target key)` pairs.
        selection: Vec<(String, String)>,
        #[serde(default)]
        caller: Option<String>,
    },

    /// `ap vault add`: unlock the vault at `path` to validate it, then register
    /// it as an external vault in the app config.
    AddExternalVault {
        path: String,
        #[serde(default)]
        caller: Option<String>,
    },

    /// `ap age recipients` / resolving an age recipient: list the saved age
    /// keys, public halves only. Raises no prompt.
    ListAgeKeys {
        #[serde(default)]
        caller: Option<String>,
    },

    /// `ap age encrypt -r <name>` / `ap age decrypt -r <name>`: unlock one age
    /// key's secret identity, behind a biometric prompt.
    GetAgeIdentity {
        key_id: String,
        #[serde(default)]
        caller: Option<String>,
    },

    /// `ap age keygen`: create a new age key. Raises no prompt.
    CreateAgeKey {
        key_id: String,
        #[serde(default)]
        caller: Option<String>,
    },

    /// `ap age delete`: remove an age key. Raises no prompt.
    DeleteAgeKey {
        key_id: String,
        #[serde(default)]
        caller: Option<String>,
    },

    /// `ap keychain generic-password`: list the saved generic passwords,
    /// metadata only. Raises no prompt.
    ListKeychainPasswords {
        #[serde(default)]
        caller: Option<String>,
    },

    /// `ap keychain managed-keys delete <label>`: remove a managed Secure
    /// Enclave key. Raises no prompt.
    DeleteManagedKey {
        label: String,
        #[serde(default)]
        caller: Option<String>,
    },

    /// The AutoFill extension's passkey registration: run the WebAuthn
    /// authenticator against an unlocked vault and return the attestation.
    /// Byte fields are standard base64.
    CreatePasskey {
        rp_id: String,
        #[serde(default)]
        rp_name: Option<String>,
        user_handle: String,
        user_name: String,
        user_display_name: String,
        client_data_hash: String,
        algorithms: Vec<i64>,
        #[serde(default)]
        excluded_credentials: Vec<String>,
        /// PRF extension input. Absent when the page did not use PRF.
        #[serde(default)]
        prf: Option<WirePrfRegistration>,
        /// The page's origin, when the client knows it. A request that
        /// carries one is refused unless `rp_id` is valid for it. Safari
        /// sends none: the system has already bound the relying party id to
        /// the page.
        #[serde(default)]
        origin: Option<String>,
        #[serde(default)]
        caller: Option<String>,
        /// See [`BrowserClient`].
        #[serde(default)]
        client: BrowserClient,
    },

    /// The AutoFill extension's passkey assertion: sign the challenge with a
    /// stored passkey's private key. Byte fields are standard base64.
    AssertPasskey {
        rp_id: String,
        client_data_hash: String,
        #[serde(default)]
        allowed_credentials: Vec<String>,
        /// The extension had no account list to offer. If several passkeys
        /// match, the prompt asks the user to pick one after the vaults
        /// unlock.
        #[serde(default)]
        choose_account: bool,
        /// PRF extension input. Absent when the page did not use PRF.
        #[serde(default)]
        prf: Option<WirePrfAssertion>,
        /// See [`WireRequest::CreatePasskey`]'s origin.
        #[serde(default)]
        origin: Option<String>,
        #[serde(default)]
        caller: Option<String>,
        /// See [`BrowserClient`].
        #[serde(default)]
        client: BrowserClient,
    },

    /// The AutoFill extension lists the passkeys of `rp_id` from the app's
    /// index, so the user can pick an account before the sign-in prompt.
    /// Raises no prompt.
    ListPasskeys {
        rp_id: String,
    },

    /// The AutoFill extension relays a site report that a passkey is unknown
    /// to it. Raises no prompt. `credential_id` is standard base64.
    ReportUnknownPasskey {
        rp_id: String,
        credential_id: String,
    },

    /// The AutoFill extension relays the passkeys a site accepts for one
    /// account. Raises no prompt. Byte fields are standard base64.
    ReportAcceptedPasskeys {
        rp_id: String,
        user_handle: String,
        credential_ids: Vec<String>,
    },

    /// The AutoFill extension relays a new account name a site reported.
    /// Raises no prompt. `user_handle` is standard base64.
    ReportPasskeyName {
        rp_id: String,
        user_handle: String,
        name: String,
    },

    /// gpg's `CONFIRM`: a yes/no question with no secret attached.
    Confirm {
        description: Option<String>,
        #[serde(default)]
        ok_label: Option<String>,
        #[serde(default)]
        cancel_label: Option<String>,
    },

    /// gpg's `MESSAGE`: something to show and acknowledge.
    Message {
        description: Option<String>,
    },
}

impl WireRequest {
    /// Who the requesting process says asked it. See [`WireRequest::Sign`] for
    /// why this is trusted by delegation. `None` for the requests that carry no
    /// caller: they raise no prompt, or draw one with nothing to attribute.
    pub(super) fn caller(&self) -> Option<&str> {
        match self {
            WireRequest::Sign { caller, .. }
            | WireRequest::AuthorizeKeyUse { caller, .. }
            | WireRequest::GetPassphrase { caller, .. }
            | WireRequest::GetSshPassphrase { caller, .. }
            | WireRequest::ListVaultItems { caller, .. }
            | WireRequest::ListLogins { caller, .. }
            | WireRequest::ListLoginsLocked { caller, .. }
            | WireRequest::FillLogin { caller, .. }
            | WireRequest::GenerateTotp { caller, .. }
            | WireRequest::GeneratePassword { caller, .. }
            | WireRequest::SaveLogin { caller, .. }
            | WireRequest::UpdateLoginPassword { caller, .. }
            | WireRequest::ReadVaultSecret { caller, .. }
            | WireRequest::ResolveSecrets { caller, .. }
            | WireRequest::WriteVaultSecret { caller, .. }
            | WireRequest::ExportVaults { caller, .. }
            | WireRequest::ImportVaults { caller, .. }
            | WireRequest::AddExternalVault { caller, .. }
            | WireRequest::ListAgeKeys { caller, .. }
            | WireRequest::GetAgeIdentity { caller, .. }
            | WireRequest::CreateAgeKey { caller, .. }
            | WireRequest::DeleteAgeKey { caller, .. }
            | WireRequest::ListKeychainPasswords { caller, .. }
            | WireRequest::DeleteManagedKey { caller, .. }
            | WireRequest::CreatePasskey { caller, .. }
            | WireRequest::AssertPasskey { caller, .. } => caller.as_deref(),
            WireRequest::ListIdentities
            | WireRequest::ListPasskeys { .. }
            | WireRequest::ReportUnknownPasskey { .. }
            | WireRequest::ReportAcceptedPasskeys { .. }
            | WireRequest::ReportPasskeyName { .. }
            | WireRequest::Confirm { .. }
            | WireRequest::Message { .. } => None,
        }
    }

    /// What the browser host reported, for the requests a browser can make.
    pub(super) fn client(&self) -> Option<&BrowserClient> {
        match self {
            WireRequest::ListLogins { client, .. }
            | WireRequest::ListLoginsLocked { client, .. }
            | WireRequest::FillLogin { client, .. }
            | WireRequest::GenerateTotp { client, .. }
            | WireRequest::SaveLogin { client, .. }
            | WireRequest::UpdateLoginPassword { client, .. }
            | WireRequest::CreatePasskey { client, .. }
            | WireRequest::AssertPasskey { client, .. } => Some(client),
            _ => None,
        }
    }

    /// The delegated process chain, for the requests that carry one. Empty for
    /// the rest, where the broker's own peer is the requester and its chain is
    /// resolved from the peer instead.
    pub(super) fn caller_chain(&self) -> &[ProcessNode] {
        match self {
            WireRequest::Sign { caller_chain, .. }
            | WireRequest::AuthorizeKeyUse { caller_chain, .. }
            | WireRequest::GetPassphrase { caller_chain, .. }
            | WireRequest::GetSshPassphrase { caller_chain, .. } => caller_chain,
            _ => &[],
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(super) enum WireResponse {
    Identities {
        keys: Vec<ManagedIdentity>,
    },
    Signed {
        algorithm: String,
        /// Base64 of the raw SSH signature body.
        signature: String,
    },
    /// Base64 of the passphrase bytes. Base64 rather than a bare string so a
    /// passphrase is never mangled by JSON escaping of odd bytes.
    Passphrase {
        passphrase: String,
    },
    Confirmed {
        ok: bool,
    },
    VaultItems {
        items: Vec<vault::BrokerVaultItem>,
    },
    Logins {
        logins: Vec<LoginSummary>,
        /// The other logins in the vaults, when the request asked for them.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        others: Vec<OtherLogin>,
    },
    /// The logins in the app's index that match a page. `indexed` is false when
    /// the app has not indexed since it started, so an empty list means "ask
    /// again with a prompt" rather than "no logins".
    LockedLogins {
        logins: Vec<LoginSummary>,
        indexed: bool,
    },
    /// The record id of the login a save created.
    LoginSaved {
        record_id: String,
    },
    GeneratedPassword {
        password: String,
    },
    /// The role credentials of one login. `username` is `None` when the login
    /// has no username role.
    LoginFill {
        username: Option<String>,
        password: String,
    },
    /// A one-time code. `None` when the login has no `Totp` credential.
    TotpCode {
        code: Option<TotpCode>,
    },
    /// `None` when the credential does not exist.
    VaultSecret {
        value: Option<String>,
    },
    /// Positionally matched to the request's `refs`. `None` where a reference
    /// does not resolve.
    ResolvedSecrets {
        values: Vec<Option<String>>,
    },
    /// `true` when the write created the item rather than updating it.
    VaultWritten {
        created: bool,
    },
    /// Number of vaults written into the export bundle.
    VaultsExported {
        count: u32,
    },
    /// Keys of the vaults imported from the bundle.
    VaultsImported {
        keys: Vec<String>,
    },
    /// The external vault that was registered.
    VaultLinked {
        vault_key: String,
        name: Option<String>,
    },
    /// A freshly registered passkey. Byte fields are standard base64.
    PasskeyRegistered {
        credential_id: String,
        attestation_object: String,
        /// Present when the request carried PRF input.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prf: Option<WirePrfRegistrationOutput>,
    },
    /// The passkeys in the app's index for a relying party. `indexed` is false
    /// when the app has not indexed since it started, so an empty list means
    /// "unknown" rather than "no passkeys".
    Passkeys {
        passkeys: Vec<WirePasskeyAccount>,
        indexed: bool,
    },
    /// A passkey assertion. Byte fields are standard base64.
    PasskeyAsserted {
        credential_id: String,
        user_handle: String,
        authenticator_data: String,
        signature: String,
        /// PRF results. Present when the request carried PRF input and the
        /// passkey has a PRF secret.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prf: Option<WirePrfValues>,
    },
    /// Saved age keys, public halves only.
    AgeKeys {
        keys: Vec<age::BrokerAgeKey>,
    },
    /// Base64 of an age identity string, as [`WireResponse::Passphrase`].
    AgeIdentity {
        identity: String,
    },
    /// The age key just created.
    AgeKey {
        name: String,
        recipient: String,
    },
    /// Saved generic passwords, metadata only.
    KeychainPasswords {
        entries: Vec<keychain::BrokerPasswordEntry>,
    },
    Acknowledged,
    Cancelled,
    Failed {
        message: String,
    },
}

/// Decode a standard-base64 wire field into bytes, mapping a bad encoding to an
/// `InvalidData` error so the connection is dropped rather than mishandled.
pub(super) fn decode_b64(value: &str) -> std::io::Result<Vec<u8>> {
    b64.decode(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// One passkey offered for a sign-in. `credential_id` is standard base64.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct WirePasskeyAccount {
    pub credential_id: String,
    pub user_name: String,
}

/// One or two PRF values. Standard base64. As input these are the page values
/// before hashing. As output they are the PRF results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct WirePrfValues {
    pub first: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub second: Option<String>,
}

/// PRF input of a registration. Its presence asks whether PRF is supported.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct WirePrfRegistration {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eval: Option<WirePrfValues>,
}

/// PRF input of an assertion.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct WirePrfAssertion {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eval: Option<WirePrfValues>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub eval_by_credential: Vec<WirePrfCredentialValues>,
}

/// PRF input for one credential. Standard base64.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct WirePrfCredentialValues {
    pub credential_id: String,
    pub first: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub second: Option<String>,
}

/// PRF output of a registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct WirePrfRegistrationOutput {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub results: Option<WirePrfValues>,
}

impl WirePrfValues {
    pub(super) fn decode(&self) -> std::io::Result<PrfValues> {
        Ok(PrfValues {
            first: decode_b64(&self.first)?,
            second: self.second.as_deref().map(decode_b64).transpose()?,
        })
    }

    pub(super) fn encode(values: &PrfValues) -> Self {
        Self {
            first: b64.encode(&values.first),
            second: values.second.as_ref().map(|s| b64.encode(s)),
        }
    }
}

impl WirePrfRegistration {
    pub(super) fn decode(&self) -> std::io::Result<PrfRegistrationInput> {
        Ok(PrfRegistrationInput {
            eval: self.eval.as_ref().map(WirePrfValues::decode).transpose()?,
        })
    }
}

impl WirePrfAssertion {
    pub(super) fn decode(&self) -> std::io::Result<PrfAssertionInput> {
        let mut eval_by_credential = Vec::with_capacity(self.eval_by_credential.len());
        for entry in &self.eval_by_credential {
            eval_by_credential.push((
                decode_b64(&entry.credential_id)?,
                PrfValues {
                    first: decode_b64(&entry.first)?,
                    second: entry.second.as_deref().map(decode_b64).transpose()?,
                },
            ));
        }
        Ok(PrfAssertionInput {
            eval: self.eval.as_ref().map(WirePrfValues::decode).transpose()?,
            eval_by_credential,
        })
    }
}

impl WirePrfRegistrationOutput {
    pub(super) fn encode(output: &PrfRegistrationOutput) -> Self {
        Self {
            enabled: output.enabled,
            results: output.results.as_ref().map(WirePrfValues::encode),
        }
    }
}
