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

use std::fs::{self, Permissions};
use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as b64;
use objc2::rc::Retained;
use objc2_app_kit::NSRunningApplication;
use objc2_foundation::{NSBundle, NSString, NSURL};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader as AsyncBufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::audit;
use crate::core::auth::ForeignContext;
use crate::core::dirs::app_data_dir;
use crate::core::provenance::{PeerIdentity, PeerPolicy, ProcessNode};

pub mod age;
pub mod gpg;
pub mod keychain;
pub mod ssh;
pub mod vault;

pub use age::{
    BrokerAgeKey, request_age_identity, request_age_keys, request_create_age_key,
    request_delete_age_key,
};
pub use gpg::{
    CollectedPassphrase, PassphraseAuthorizer, PassphraseKind, PassphrasePrompt, request_confirm,
    request_message, request_passphrase,
};
pub use keychain::{BrokerPasswordEntry, request_delete_managed_key, request_keychain_passwords};
pub use ssh::{
    ManagedIdentity, SignAuthorizer, SignPrompt, list_identities, request_authorize_key_use,
    request_signature, request_ssh_passphrase,
};
pub use vault::{
    BrokerCredential, BrokerVaultItem, ResolvePurpose, VaultAccessPrompt, VaultAction,
    VaultAuthorizer, VaultRef, WireExportMode, WireImportIdentity, request_add_external_vault,
    request_export_vaults, request_import_vaults, request_resolve_secrets, request_vault_items,
    request_vault_secret, request_write_vault_secret,
};

/// How long a client waits for the user to answer the app's prompt before
/// giving up. Disconnecting ends the prompt, see `InFlightRequest`.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(120);

/// How long to wait for a cold app launch to start serving.
const LAUNCH_TIMEOUT: Duration = Duration::from_secs(20);
const LAUNCH_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// The agent ships inside the app bundle, beside the app's own executable.
const AGENT_EXECUTABLE_NAME: &str = "ap";

pub fn broker_socket_path() -> PathBuf {
    // typically: ~/Library/Application Support/Axo Pass/app-broker.sock
    app_data_dir().join("app-broker.sock")
}

/// Passed to the app by [`launch_app`] to say the launch is only to serve the
/// broker, so the app stays headless: no window, no Dock icon, no focus taken.
pub const LAUNCH_FLAG: &str = "--broker";

#[derive(Debug, Error)]
pub enum BrokerError {
    /// No app is listening and none could be started. The caller should fall
    /// back to its own prompt.
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
}

/// The wire format: one JSON line each way, one request per connection.
#[derive(Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case")]
enum WireRequest {
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

    /// gpg's `CONFIRM`: a yes/no question with no secret attached.
    Confirm {
        description: Option<String>,
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
    fn caller(&self) -> Option<&str> {
        match self {
            WireRequest::Sign { caller, .. }
            | WireRequest::AuthorizeKeyUse { caller, .. }
            | WireRequest::GetPassphrase { caller, .. }
            | WireRequest::GetSshPassphrase { caller, .. }
            | WireRequest::ListVaultItems { caller, .. }
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
            | WireRequest::DeleteManagedKey { caller, .. } => caller.as_deref(),
            WireRequest::ListIdentities
            | WireRequest::Confirm { .. }
            | WireRequest::Message { .. } => None,
        }
    }

    /// The delegated process chain, for the requests that carry one. Empty for
    /// the rest, where the broker's own peer is the requester and its chain is
    /// resolved from the peer instead.
    fn caller_chain(&self) -> &[ProcessNode] {
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
enum WireResponse {
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

// Client (the agent).

fn send_request(request: &WireRequest) -> Result<WireResponse, BrokerError> {
    send_request_for(request, None)
}

/// Send `request` on behalf of `requester`, a client connected to the caller,
/// such as an `ssh` process talking to the agent. When the requester
/// disconnects before the app answers, the connection to the broker is closed,
/// which ends the app's prompt, and this returns
/// [`BrokerError::RequesterDisconnected`].
fn send_request_for(
    request: &WireRequest,
    requester: Option<BorrowedFd<'_>>,
) -> Result<WireResponse, BrokerError> {
    let stream = match connect() {
        Ok(stream) => stream,
        Err(_) => {
            // Nothing listening. The app owns the keys, so start it and wait
            // rather than failing.
            launch_app()?;
            wait_for_broker()?
        },
    };

    stream
        .set_read_timeout(Some(RESPONSE_TIMEOUT))
        .map_err(|e| BrokerError::Failed(e.to_string()))?;

    let mut line = serde_json::to_vec(request).map_err(|e| BrokerError::Failed(e.to_string()))?;
    line.push(b'\n');
    (&stream)
        .write_all(&line)
        .and_then(|_| (&stream).flush())
        .map_err(|e| BrokerError::Failed(format!("Failed to send request: {e}")))?;

    if let Some(requester) = requester {
        wait_for_response(&stream, requester)?;
    }

    let mut response_line = String::new();
    BufReader::new(&stream)
        .read_line(&mut response_line)
        .map_err(|e| match e.kind() {
            // macOS reports an expired socket read timeout as WouldBlock.
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                BrokerError::Failed("Timed out waiting for a response".to_string())
            },
            _ => BrokerError::Failed(format!("Failed to read response: {e}")),
        })?;
    if response_line.trim().is_empty() {
        // The app went away mid-request.
        return Err(BrokerError::Disconnected);
    }

    serde_json::from_str(&response_line)
        .map_err(|e| BrokerError::Failed(format!("Malformed response: {e}")))
}

/// Wait until the broker's response can be read, for up to
/// [`RESPONSE_TIMEOUT`]. Returns early with
/// [`BrokerError::RequesterDisconnected`] if `requester` closes its end first.
///
/// A requester only waits while the request is out, so its socket turning
/// readable means it disconnected. If it sent data instead, it is left alone
/// and only the broker is watched.
fn wait_for_response(
    stream: &std::os::unix::net::UnixStream,
    requester: BorrowedFd<'_>,
) -> Result<(), BrokerError> {
    let timed_out = || BrokerError::Failed("Timed out waiting for a response".to_string());
    let deadline = std::time::Instant::now() + RESPONSE_TIMEOUT;
    let mut watch_requester = true;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(timed_out());
        }
        let mut fds = [
            libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                // poll skips a negative descriptor.
                fd: if watch_requester {
                    requester.as_raw_fd()
                } else {
                    -1
                },
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
        if ready < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(BrokerError::Failed(format!(
                "Failed to wait for a response: {e}"
            )));
        }
        if ready == 0 {
            return Err(timed_out());
        }
        // Readable, closed, or failed: the read that follows reports which.
        if fds[0].revents != 0 {
            return Ok(());
        }
        if fds[1].revents != 0 {
            let mut byte = 0u8;
            let peeked = unsafe {
                libc::recv(
                    requester.as_raw_fd(),
                    (&raw mut byte).cast(),
                    1,
                    libc::MSG_PEEK | libc::MSG_DONTWAIT,
                )
            };
            match peeked {
                0 => return Err(BrokerError::RequesterDisconnected),
                n if n > 0 => watch_requester = false,
                _ => {
                    let e = std::io::Error::last_os_error();
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        return Err(BrokerError::RequesterDisconnected);
                    }
                },
            }
        }
    }
}

fn connect() -> std::io::Result<std::os::unix::net::UnixStream> {
    std::os::unix::net::UnixStream::connect(broker_socket_path())
}

/// The bundle holding this executable, i.e. `.../Axo Pass.app` for the `ap`
/// staged at `Contents/MacOS/ap`.
///
/// Walks up from the executable looking for a `.app` component rather than
/// assuming a fixed depth: `current_exe` is not always canonical (a wrapper
/// that execs `.../Contents/Resources/../MacOS/ap` leaves the `..` in place),
/// so a fixed number of `parent()` calls can land in the wrong directory.
pub(crate) fn app_bundle_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    log::debug!("Resolving the app bundle from {}", exe.display());
    exe.ancestors()
        .find(|path| path.extension().is_some_and(|ext| ext == "app"))
        .map(Path::to_path_buf)
}

/// Whether the app is already running.
///
/// Asks LaunchServices, which is the same authority `open` consults: if it
/// reports an instance, `open` will reopen that one rather than launch a new
/// one. `ap` itself is not a registered application, so it never counts.
fn app_is_running(bundle: &Path) -> bool {
    let Some(id) = bundle_identifier(bundle) else {
        log::debug!("No bundle identifier for {}", bundle.display());
        return false;
    };
    !NSRunningApplication::runningApplicationsWithBundleIdentifier(&id).is_empty()
}

/// The `CFBundleIdentifier` of the bundle at `path`.
fn bundle_identifier(path: &Path) -> Option<Retained<NSString>> {
    let url = NSURL::fileURLWithPath(&NSString::from_str(path.to_str()?));
    NSBundle::bundleWithURL(&url)?.bundleIdentifier()
}

/// Serializes `launch_app` across processes, so two requests arriving together
/// issue one `open` between them.
fn launch_lock_path() -> PathBuf {
    app_data_dir().join("app-broker.launch.lock")
}

/// Take the launch lock, waiting for whoever holds it.
///
/// Waits rather than giving up, so the second caller runs its checks only after
/// the first has finished starting the app and LaunchServices knows about it.
///
/// The lock is an `flock` the kernel releases when the file closes or the
/// process dies, so it cannot go stale and needs no timeout. Nothing reads the
/// file's contents.
fn lock_launch() -> Option<fs::File> {
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(launch_lock_path())
        .map_err(|e| log::debug!("Could not open the launch lock: {e}"))
        .ok()?;
    match unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } {
        0 => Some(file),
        _ => None,
    }
}

/// Start the app in the background, so a signature request does not pull focus
/// away from whatever asked for it.
fn launch_app() -> Result<(), BrokerError> {
    let Some(bundle) = app_bundle_path() else {
        log::debug!("Not running from an app bundle; cannot start the broker");
        return Err(BrokerError::Unavailable);
    };

    // Held until this function returns, so two requests arriving together issue
    // one `open` between them: the second waits here, then finds the app
    // running below. A second `open` would reach the app as a reopen, which
    // puts a window on screen.
    let _lock = lock_launch();

    // `open` on a running app only delivers a reopen event, which puts a window
    // on screen and takes focus, and drops `--args` on the way. So do not issue
    // one: the app is up and binding the socket, and the caller waits for it.
    if app_is_running(&bundle) {
        log::debug!("The app is already running; waiting for it to serve");
        return Ok(());
    }

    log::debug!("Starting {} for the app broker", bundle.display());
    let status = std::process::Command::new("/usr/bin/open")
        .arg("-g")
        .arg(&bundle)
        .arg("--args")
        .arg(LAUNCH_FLAG)
        .status()
        .map_err(|e| BrokerError::Failed(format!("Failed to start the app: {e}")))?;
    if !status.success() {
        return Err(BrokerError::Failed(format!(
            "Failed to start {}: open exited with {status}",
            bundle.display()
        )));
    }
    Ok(())
}

fn wait_for_broker() -> Result<std::os::unix::net::UnixStream, BrokerError> {
    let deadline = std::time::Instant::now() + LAUNCH_TIMEOUT;
    loop {
        if let Ok(stream) = connect() {
            return Ok(stream);
        }
        if std::time::Instant::now() >= deadline {
            log::warn!("The app did not start serving signing requests in time");
            return Err(BrokerError::Unavailable);
        }
        std::thread::sleep(LAUNCH_POLL_INTERVAL);
    }
}

// Server (the app).

/// Serve requests until `shutdown` resolves, then remove the socket.
pub async fn serve(
    authorizers: Authorizers,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) -> std::io::Result<()> {
    serve_on(broker_socket_path(), agent_policy(), authorizers, shutdown).await
}

/// The body of [`serve`], with the socket path and the peer policy supplied
/// rather than derived, so tests can bind a scratch socket and choose who it
/// accepts.
///
/// Binding replaces a socket left behind by a crashed app: only one app runs at
/// a time, and a stale file would otherwise keep the broker offline
/// permanently.
async fn serve_on(
    socket_path: PathBuf,
    policy: PeerPolicy,
    authorizers: Authorizers,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) -> std::io::Result<()> {
    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if socket_path.exists() {
        // Only remove a socket nothing is listening on.
        match std::os::unix::net::UnixStream::connect(&socket_path) {
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!("another app broker owns {}", socket_path.display()),
                ));
            },
            Err(_) => {
                log::debug!("Replacing stale app broker socket {socket_path:?}");
                fs::remove_file(&socket_path)?;
            },
        }
    }

    let listener = UnixListener::bind(&socket_path)?;
    fs::set_permissions(&socket_path, Permissions::from_mode(0o600)).inspect_err(|_| {
        let _ = fs::remove_file(&socket_path);
    })?;
    log::debug!("App broker listening on {}", socket_path.display());

    tokio::select! {
        _ = accept_loop(listener, authorizers, policy) => {},
        _ = shutdown => log::debug!("App broker shutting down"),
    }
    let _ = fs::remove_file(&socket_path);
    Ok(())
}

/// Who the broker takes requests from: only the agent staged beside us in the
/// app bundle, signed by the same team.
///
/// The socket's mode keeps out other users, but every process this user runs
/// can open it, including anything a compromised dependency drops on the
/// machine. The peer check narrows that to the agent.
///
/// An unsigned local build has no team to anchor to, so the requirement is
/// dropped and only the executable path and the user are checked.
fn agent_policy() -> PeerPolicy {
    let policy = PeerPolicy::sibling_executable(AGENT_EXECUTABLE_NAME);
    let accepts = policy.executable.as_ref().map_or_else(
        || "any process running as this user".to_string(),
        |path| path.display().to_string(),
    );
    if policy.requirement.is_some() {
        log::debug!("App broker accepts {accepts}, signed by our own team");
    } else {
        log::warn!(
            "App broker cannot check its peer's code signature: this build carries no team \
             identifier. Accepting {accepts}"
        );
    }
    policy
}

async fn accept_loop(listener: UnixListener, authorizers: Authorizers, policy: PeerPolicy) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let peer = match PeerIdentity::verify(stream.as_raw_fd(), &policy) {
                    Ok(peer) => peer,
                    // A client that gave up while its connection waited to be
                    // accepted. Nothing connected that could be checked, so
                    // nothing was refused.
                    Err(e) if e.is_disconnected() => {
                        log::debug!("App broker client disconnected before it was accepted");
                        continue;
                    },
                    Err(e) => {
                        log::warn!("App broker refused a connection: {e}");
                        let mut event = audit::AuditEvent::new(
                            audit::process_source(),
                            audit::Action::BrokerPeerRejected,
                            audit::Outcome::Denied,
                        )
                        .message(e.to_string())
                        .detail("peer_verified", "false");
                        // Describe the rejected peer with no policy applied. The
                        // executable and signature here come from code that
                        // failed the policy, so the event marks them unverified.
                        if let Ok(peer) = PeerIdentity::identify(stream.as_raw_fd()) {
                            log::debug!("App broker rejected peer: {peer:#?}");
                            event = event.actor(peer_actor(&peer));
                        }
                        audit::record(event);
                        continue;
                    },
                };
                log::debug!("App broker peer: {peer:#?}");

                let authorizers = authorizers.clone();
                // Serially, not spawned: two prompts at once would contend for
                // the screen and the system's authentication session.
                if let Err(e) = handle_connection(stream, &peer, authorizers).await {
                    log::debug!("App broker connection failed: {e}");
                }
            },
            Err(e) => {
                log::error!("App broker accept failed: {e}");
                return;
            },
        }
    }
}

/// Build an audit actor from a peer. Whether the peer passed the policy is the
/// caller's to record: the same fields are read either way.
fn peer_actor(peer: &PeerIdentity) -> audit::Actor {
    audit::Actor {
        caller: peer.caller(),
        pid: Some(peer.pid()),
        executable: peer.executable(),
        bundle_id: peer.bundle_id(),
        team_id: peer.team_id(),
        chain: peer.provenance().chain_labels(),
        chain_detail: peer.provenance().chain_nodes(),
    }
}

/// Describe who a request is for: the peer we verified, named by the caller it
/// delegated to us.
///
/// The process identity comes from the peer, which we checked ourselves. The
/// caller comes from the request when it carries one, because a long-running
/// peer's own chain leads to launchd rather than to whoever asked it: the
/// agent knows `git` made the request, and we cannot see that from the socket.
/// A peer that names nobody falls back to its own chain root.
fn request_actor(
    peer: &PeerIdentity,
    delegated_caller: Option<&str>,
    delegated_chain: &[ProcessNode],
) -> audit::Actor {
    let mut actor = peer_actor(peer);
    if let Some(caller) = delegated_caller.filter(|c| !c.is_empty()) {
        actor.caller = Some(caller.to_string());
    }
    if !delegated_chain.is_empty() {
        actor.chain_detail = delegated_chain.to_vec();
    }
    actor
}

/// The request being served. It is abandoned when the client that sent it
/// disconnects, which ends its prompt. The broker serves one connection at a
/// time, and an abandoned prompt would otherwise block the requests behind it.
pub(super) struct InFlightRequest {
    context: std::sync::Mutex<Option<ForeignContext>>,
    abandoned: tokio::sync::watch::Sender<bool>,
}

impl Default for InFlightRequest {
    fn default() -> Self {
        Self {
            context: std::sync::Mutex::new(None),
            abandoned: tokio::sync::watch::Sender::new(false),
        }
    }
}

impl InFlightRequest {
    /// Attach the context the request's prompt evaluates on. Abandoning the
    /// request invalidates it, which fails the evaluation and so ends the
    /// prompt through the usual path. Invalidates it at once if the request is
    /// already abandoned.
    pub(super) fn attach(&self, context: &ForeignContext) {
        let mut slot = self.context.lock().unwrap_or_else(|e| e.into_inner());
        if *self.abandoned.borrow() {
            context.invalidate();
        } else {
            *slot = Some(context.clone());
        }
    }

    /// Run `prompt` unless the request is abandoned first, in which case
    /// `None`. For prompts with no context to invalidate: dropping a call into
    /// the app cancels its task, and the app dismisses a cancelled prompt.
    pub(super) async fn unless_abandoned<T>(&self, prompt: impl Future<Output = T>) -> Option<T> {
        let mut abandoned = self.abandoned.subscribe();
        // Checked first, so a request already abandoned never starts its
        // prompt.
        tokio::select! {
            biased; // poll in order
            _ = abandoned.wait_for(|abandoned| *abandoned) => None,
            value = prompt => Some(value),
        }
    }

    /// Run `prompt` to completion. If the request is abandoned first, `abandon`
    /// runs while it waits and should make `prompt` finish early. For a prompt
    /// that must not be dropped partway, because the app would carry on with it
    /// alongside the next request.
    pub(super) async fn abandoning<T>(
        &self,
        prompt: impl Future<Output = T>,
        abandon: impl Future<Output = ()>,
    ) -> T {
        tokio::pin!(prompt);
        let mut abandoned = self.abandoned.subscribe();
        tokio::select! {
            value = &mut prompt => return value,
            _ = abandoned.wait_for(|abandoned| *abandoned) => {},
        }
        abandon.await;
        prompt.await
    }

    pub(super) fn is_abandoned(&self) -> bool {
        *self.abandoned.borrow()
    }

    fn abandon(&self) {
        let mut slot = self.context.lock().unwrap_or_else(|e| e.into_inner());
        self.abandoned.send_replace(true);
        if let Some(context) = slot.take() {
            context.invalidate();
        }
    }
}

/// Resolves once the client closes its end. A client sends one request line
/// and then only waits for the response, so any read returning means it has
/// disconnected.
async fn client_disconnected(reader: &mut (impl tokio::io::AsyncRead + Unpin)) {
    let mut buf = [0u8; 64];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {},
        }
    }
}

async fn handle_connection(
    stream: UnixStream,
    peer: &PeerIdentity,
    authorizers: Authorizers,
) -> std::io::Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = AsyncBufReader::new(read_half);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;
    let request: WireRequest = serde_json::from_str(&request_line)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    // A client that gave up while its connection waited to be accepted has
    // already closed it. Its request is not served at all, so the app shows no
    // prompt and records nothing for it.
    let disconnected = tokio::select! {
        biased;
        () = client_disconnected(&mut reader) => true,
        () = std::future::ready(()) => false,
    };
    if disconnected {
        log::debug!("App broker client disconnected before its request was served");
        return Ok(());
    }

    // Resolved once per connection and handed to whichever authorizer serves
    // the request, so the grant the app hands out is attributed to the process
    // we verified rather than to a caller string alone.
    let actor = request_actor(peer, request.caller(), request.caller_chain());
    let caller_chain = actor.chain_detail.clone();

    let in_flight = InFlightRequest::default();
    let serve = async {
        Ok::<_, std::io::Error>(match request {
            WireRequest::ListIdentities => {
                log::debug!("App broker request: list identities");
                tokio::task::spawn_blocking(ssh::list_identities_locally)
                    .await
                    .unwrap_or_else(|e| Err(format!("Failed to list managed keys: {e}")))
                    .map_or_else(
                        |message| WireResponse::Failed { message },
                        |keys| WireResponse::Identities { keys },
                    )
            },
            WireRequest::Sign {
                key_label,
                fingerprint,
                comment,
                caller,
                caller_chain: _,
                data,
                // Secure Enclave keys are ECDSA P-256 and have no flag-selected
                // hash.
                flags: _,
            } => {
                let data = b64
                    .decode(&data)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                let prompt = SignPrompt {
                    key_label,
                    fingerprint,
                    comment,
                    caller,
                    caller_chain: caller_chain.clone(),
                    managed: true,
                    policy: None,
                    grant_candidate: None,
                };
                log::debug!("App broker request: {prompt:?}");
                ssh::sign_managed(&*authorizers.sign, prompt, actor, data, &in_flight).await
            },
            WireRequest::AuthorizeKeyUse {
                fingerprint,
                comment,
                caller,
                caller_chain: _,
                allow_grants,
            } => {
                let prompt = SignPrompt {
                    key_label: String::new(),
                    fingerprint,
                    comment,
                    caller,
                    caller_chain: caller_chain.clone(),
                    managed: false,
                    policy: None,
                    grant_candidate: None,
                };
                log::debug!(
                    "App broker request: authorize key use {prompt:?}, allow grants {allow_grants}"
                );
                ssh::authorize_key_use(&*authorizers.sign, prompt, actor, allow_grants, &in_flight)
                    .await
            },
            WireRequest::GetPassphrase {
                key_id,
                description,
                prompt,
                error_message,
                caller,
                caller_chain: _,
            } => {
                let prompt = PassphrasePrompt {
                    kind: PassphraseKind::Gpg,
                    key_id,
                    description,
                    prompt,
                    error_message,
                    caller,
                    caller_chain: caller_chain.clone(),
                };
                log::debug!("App broker request: {prompt:?}");
                gpg::get_passphrase(&*authorizers.passphrase, prompt, actor, &in_flight).await
            },
            WireRequest::GetSshPassphrase {
                key_id,
                prompt,
                caller,
                caller_chain: _,
            } => {
                let prompt = PassphrasePrompt {
                    kind: PassphraseKind::Ssh,
                    key_id,
                    description: None,
                    prompt: Some(prompt),
                    error_message: None,
                    caller,
                    caller_chain: caller_chain.clone(),
                };
                log::debug!("App broker request: {prompt:?}");
                ssh::get_passphrase(&*authorizers.passphrase, prompt, actor, &in_flight).await
            },
            WireRequest::ListVaultItems { vault_key, caller } => {
                let prompt = vault::VaultAccessPrompt {
                    vault_key,
                    caller,
                    caller_chain: caller_chain.clone(),
                    action: vault::VaultAction::ListItems,
                };
                log::debug!("App broker request: {prompt:?}");
                vault::authorize_and_serve(&*authorizers.vault, prompt, actor, None, &in_flight)
                    .await
            },
            WireRequest::ReadVaultSecret {
                vault_key,
                item_key,
                credential_key,
                caller,
            } => {
                let prompt = vault::VaultAccessPrompt {
                    vault_key,
                    caller,
                    caller_chain: caller_chain.clone(),
                    action: vault::VaultAction::ReadSecret {
                        item_key,
                        credential_key,
                    },
                };
                log::debug!("App broker request: {prompt:?}");
                vault::authorize_and_serve(&*authorizers.vault, prompt, actor, None, &in_flight)
                    .await
            },
            WireRequest::ResolveSecrets {
                refs,
                purpose,
                caller,
            } => {
                let mut vault_keys: Vec<String> =
                    refs.iter().map(|r| r.vault_key.clone()).collect();
                vault_keys.sort();
                vault_keys.dedup();
                let prompt = vault::VaultAccessPrompt {
                    vault_key: vault_keys.join(", "),
                    caller,
                    caller_chain: caller_chain.clone(),
                    action: vault::VaultAction::ResolveSecrets { purpose, refs },
                };
                log::debug!("App broker request: {prompt:?}");
                vault::authorize_and_serve(&*authorizers.vault, prompt, actor, None, &in_flight)
                    .await
            },
            WireRequest::WriteVaultSecret {
                vault_key,
                item_key,
                credential_key,
                title,
                value,
                caller,
            } => {
                let prompt = vault::VaultAccessPrompt {
                    vault_key,
                    caller,
                    caller_chain: caller_chain.clone(),
                    action: vault::VaultAction::WriteSecret {
                        item_key,
                        credential_key,
                    },
                };
                let payload = vault::WriteSecretPayload {
                    title,
                    value: secrecy::SecretString::from(value),
                };
                log::debug!("App broker request: {prompt:?}");
                vault::authorize_and_serve(
                    &*authorizers.vault,
                    prompt,
                    actor,
                    Some(vault::VaultPayload::Write(payload)),
                    &in_flight,
                )
                .await
            },
            WireRequest::ExportVaults {
                vault_keys,
                dest_path,
                mode,
                caller,
            } => {
                let prompt = vault::VaultAccessPrompt {
                    vault_key: vault_keys.join(", "),
                    caller,
                    caller_chain: caller_chain.clone(),
                    action: vault::VaultAction::ExportVaults {
                        vault_keys: vault_keys.clone(),
                    },
                };
                let payload = vault::ExportPayload {
                    dest_path: std::path::PathBuf::from(dest_path),
                    mode: mode.into(),
                };
                log::debug!("App broker request: {prompt:?}");
                vault::authorize_and_serve(
                    &*authorizers.vault,
                    prompt,
                    actor,
                    Some(vault::VaultPayload::Export(payload)),
                    &in_flight,
                )
                .await
            },
            WireRequest::ImportVaults {
                import_path,
                identity,
                selection,
                caller,
            } => {
                let prompt = vault::VaultAccessPrompt {
                    vault_key: std::path::Path::new(&import_path)
                        .file_name()
                        .map_or_else(|| import_path.clone(), |n| n.to_string_lossy().into_owned()),
                    caller,
                    caller_chain: caller_chain.clone(),
                    action: vault::VaultAction::ImportVaults {
                        count: selection.len(),
                    },
                };
                let payload = vault::ImportPayload {
                    import_path: std::path::PathBuf::from(import_path),
                    identity,
                    selection,
                };
                log::debug!("App broker request: {prompt:?}");
                vault::authorize_and_serve(
                    &*authorizers.vault,
                    prompt,
                    actor,
                    Some(vault::VaultPayload::Import(payload)),
                    &in_flight,
                )
                .await
            },
            WireRequest::AddExternalVault { path, caller } => {
                let prompt = vault::VaultAccessPrompt {
                    vault_key: path.clone(),
                    caller,
                    caller_chain: caller_chain.clone(),
                    action: vault::VaultAction::AddVault { path },
                };
                log::debug!("App broker request: {prompt:?}");
                vault::authorize_and_serve(&*authorizers.vault, prompt, actor, None, &in_flight)
                    .await
            },
            WireRequest::ListAgeKeys { .. } => {
                log::debug!("App broker request: list age keys");
                age::list_keys().await
            },
            WireRequest::GetAgeIdentity { key_id, caller } => {
                log::debug!("App broker request: get age identity {key_id}");
                age::get_identity(&*authorizers.passphrase, key_id, caller, actor, &in_flight).await
            },
            WireRequest::CreateAgeKey { key_id, .. } => {
                log::debug!("App broker request: create age key {key_id}");
                age::create_key(key_id, actor).await
            },
            WireRequest::DeleteAgeKey { key_id, .. } => {
                log::debug!("App broker request: delete age key {key_id}");
                age::delete_key(key_id, actor).await
            },
            WireRequest::ListKeychainPasswords { .. } => {
                log::debug!("App broker request: list keychain passwords");
                keychain::list_passwords().await
            },
            WireRequest::DeleteManagedKey { label, .. } => {
                log::debug!("App broker request: delete managed key {label}");
                keychain::delete_managed_key(label, actor).await
            },
            WireRequest::Confirm { description } => {
                log::debug!("App broker request: confirm");
                let ok = in_flight
                    .unless_abandoned(authorizers.passphrase.confirm(description))
                    .await;
                WireResponse::Confirmed {
                    ok: ok.unwrap_or(false),
                }
            },
            WireRequest::Message { description } => {
                log::debug!("App broker request: message");
                in_flight
                    .unless_abandoned(authorizers.passphrase.message(description))
                    .await;
                WireResponse::Acknowledged
            },
        })
    };
    tokio::pin!(serve);

    let response = tokio::select! {
        biased; // poll in order
        () = client_disconnected(&mut reader) => {
            log::debug!("App broker client disconnected mid-request, ending its prompt");
            in_flight.abandon();
            // The request still runs to completion so the app's `end` is
            // called, but nobody is left to read the response.
            serve.await?;
            return Ok(());
        },
        response = &mut serve => response?,
    };

    let mut line =
        serde_json::to_vec(&response).map_err(|e| std::io::Error::other(e.to_string()))?;
    line.push(b'\n');
    write_half.write_all(&line).await?;
    write_half.flush().await
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;
    use std::path::Path;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;

    use super::*;

    /// The passphrase the stub hands back when asked to collect one.
    const STUB_PASSPHRASE: &str = "hunter2";

    /// Stands in for the app. It cannot produce a real `LAContext`, so both
    /// `begin` methods decline. A request that reaches it has still been
    /// accepted, framed, parsed and routed, which is what these tests cover.
    #[derive(Default)]
    struct StubAuthorizer {
        prompts: Mutex<Vec<SignPrompt>>,
        passphrase_prompts: Mutex<Vec<PassphrasePrompt>>,
        peers: Mutex<Vec<audit::Actor>>,
        ended: AtomicUsize,
        prompts_dropped: AtomicUsize,
    }

    #[async_trait]
    impl SignAuthorizer for StubAuthorizer {
        async fn begin(
            &self,
            prompt: SignPrompt,
            peer: audit::Actor,
        ) -> Result<crate::core::auth::ForeignContext, String> {
            self.prompts.lock().unwrap().push(prompt);
            self.peers.lock().unwrap().push(peer);
            Err("stub authorizer".to_string())
        }

        async fn end(&self, _prompt: SignPrompt, _outcome: PromptOutcome) {
            self.ended.fetch_add(1, Ordering::SeqCst);
        }

        async fn notify_preapproved(
            &self,
            _prompt: SignPrompt,
            _app: crate::ssh::app_grants::GrantApp,
        ) {
        }
    }

    #[async_trait]
    impl PassphraseAuthorizer for StubAuthorizer {
        async fn begin(
            &self,
            _prompt: PassphrasePrompt,
            peer: audit::Actor,
        ) -> Result<crate::core::auth::ForeignContext, String> {
            self.peers.lock().unwrap().push(peer);
            Err("stub authorizer".to_string())
        }

        async fn collect(
            &self,
            prompt: PassphrasePrompt,
        ) -> Result<Option<CollectedPassphrase>, String> {
            self.passphrase_prompts.lock().unwrap().push(prompt);
            Ok(Some(CollectedPassphrase {
                value: secrecy::SecretString::from(STUB_PASSPHRASE),
                // Nothing may touch the real keychain from a test.
                save_to_keychain: false,
            }))
        }

        async fn end(&self, _prompt: PassphrasePrompt, _outcome: PromptOutcome) {
            self.ended.fetch_add(1, Ordering::SeqCst);
        }

        /// `"hang"` stands for a user who never answers. Its prompt is only
        /// ever dropped, which is counted.
        async fn confirm(&self, description: Option<String>) -> bool {
            if description.as_deref() == Some("hang") {
                struct Dropped<'a>(&'a AtomicUsize);
                impl Drop for Dropped<'_> {
                    fn drop(&mut self) {
                        self.0.fetch_add(1, Ordering::SeqCst);
                    }
                }
                let _dropped = Dropped(&self.prompts_dropped);
                std::future::pending::<()>().await;
            }
            true
        }

        async fn message(&self, _description: Option<String>) {}
    }

    #[async_trait]
    impl vault::VaultAuthorizer for StubAuthorizer {
        async fn begin(
            &self,
            _prompt: vault::VaultAccessPrompt,
            peer: audit::Actor,
        ) -> Result<crate::core::auth::ForeignContext, String> {
            self.peers.lock().unwrap().push(peer);
            Err("stub authorizer".to_string())
        }

        async fn abandon(&self) {}

        async fn end(&self, _prompt: vault::VaultAccessPrompt, _outcome: PromptOutcome) {
            self.ended.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A broker on a scratch socket, shut down when dropped.
    struct TestBroker {
        socket_path: PathBuf,
        authorizer: Arc<StubAuthorizer>,
        shutdown: Option<tokio::sync::oneshot::Sender<()>>,
        // Rejecting a peer and serving a vault request both write audit
        // events. Held so they land in a scratch directory instead of the one
        // an audit test is counting.
        _audit_dir: crate::audit::test_support::TestDir,
        _dir: tempfile::TempDir,
    }

    impl TestBroker {
        async fn start(policy: PeerPolicy) -> Self {
            let audit_dir = crate::audit::test_support::test_dir();
            let dir = tempfile::tempdir().unwrap();
            let socket_path = dir.path().join("app-broker.sock");
            let authorizer = Arc::new(StubAuthorizer::default());
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

            tokio::spawn(serve_on(
                socket_path.clone(),
                policy,
                Authorizers {
                    sign: authorizer.clone(),
                    passphrase: authorizer.clone(),
                    vault: authorizer.clone(),
                },
                shutdown_rx,
            ));
            wait_for_socket(&socket_path).await;

            TestBroker {
                socket_path,
                authorizer,
                shutdown: Some(shutdown_tx),
                _audit_dir: audit_dir,
                _dir: dir,
            }
        }

        /// Send one request line the way an outside process would, and return
        /// the response line. Empty means the broker hung up on us.
        fn request(&self, line: &str) -> String {
            let stream = std::os::unix::net::UnixStream::connect(&self.socket_path).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            (&stream).write_all(line.as_bytes()).unwrap();
            (&stream).write_all(b"\n").unwrap();
            (&stream).flush().unwrap();

            let mut response = String::new();
            BufReader::new(&stream).read_line(&mut response).unwrap();
            response
        }
    }

    impl Drop for TestBroker {
        fn drop(&mut self) {
            if let Some(shutdown) = self.shutdown.take() {
                let _ = shutdown.send(());
            }
        }
    }

    /// `serve_on` binds before it accepts, so a connectable socket is the
    /// readiness signal.
    async fn wait_for_socket(socket_path: &Path) {
        for _ in 0..200 {
            if std::os::unix::net::UnixStream::connect(socket_path).is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("broker never bound {}", socket_path.display());
    }

    /// A policy this test process satisfies, standing in for the real one that
    /// names `ap` inside the app bundle.
    fn accepting_policy() -> PeerPolicy {
        PeerPolicy {
            same_user: true,
            requirement: None,
            executable: Some(std::env::current_exe().unwrap()),
        }
    }

    /// A policy no test process satisfies.
    fn rejecting_policy() -> PeerPolicy {
        PeerPolicy {
            executable: Some(PathBuf::from("/usr/bin/true")),
            ..accepting_policy()
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn serves_a_request_from_an_accepted_peer() {
        let broker = TestBroker::start(accepting_policy()).await;

        let response = broker.request(
            r#"{"request":"sign","key_label":"key-1","caller":"git (ssh)","data":"aGk="}"#,
        );

        // The stub declines, so the request is answered rather than signed.
        // Reaching the stub at all means the peer was accepted.
        let response: WireResponse = serde_json::from_str(&response).unwrap();
        assert!(
            matches!(&response, WireResponse::Failed { message } if message == "stub authorizer"),
            "unexpected response to an accepted peer"
        );

        let prompts = broker.authorizer.prompts.lock().unwrap();
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].key_label, "key-1");
        assert_eq!(prompts[0].caller.as_deref(), Some("git (ssh)"));
        assert_eq!(broker.authorizer.ended.load(Ordering::SeqCst), 1);
    }

    /// Abandoning a request runs its `abandon` step and then still waits for
    /// the prompt to finish, rather than dropping it.
    #[tokio::test]
    async fn abandoning_dismisses_the_prompt_and_waits_for_it() {
        let in_flight = Arc::new(InFlightRequest::default());
        let (dismiss, dismissed) = tokio::sync::oneshot::channel::<()>();

        let abandoner = in_flight.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            abandoner.abandon();
        });

        // Stands for a prompt that only returns once it is dismissed.
        let prompt = async {
            dismissed.await.unwrap();
            "dismissed"
        };
        let abandon = async {
            dismiss.send(()).unwrap();
        };
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            in_flight.abandoning(prompt, abandon),
        )
        .await
        .expect("abandoning never returned");
        assert_eq!(result, "dismissed");
    }

    /// The agent stops waiting on the broker once the client it is serving
    /// disconnects.
    #[test]
    fn stops_waiting_when_the_requester_disconnects() {
        use std::os::fd::AsFd;
        use std::os::unix::net::UnixStream;

        let (broker, _broker_peer) = UnixStream::pair().unwrap();
        let (requester, requester_peer) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            drop(requester_peer);
        });

        let result = wait_for_response(&broker, requester.as_fd());
        assert!(matches!(result, Err(BrokerError::RequesterDisconnected)));
    }

    /// Data from the requester is not a disconnect: the wait goes on until the
    /// broker answers.
    #[test]
    fn keeps_waiting_when_the_requester_sends_data() {
        use std::os::fd::AsFd;
        use std::os::unix::net::UnixStream;

        let (broker, mut broker_peer) = UnixStream::pair().unwrap();
        let (requester, mut requester_peer) = UnixStream::pair().unwrap();
        requester_peer.write_all(b"x").unwrap();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            broker_peer.write_all(b"{}\n").unwrap();
            // Held open until the response is read.
            std::thread::sleep(Duration::from_millis(500));
        });

        assert!(wait_for_response(&broker, requester.as_fd()).is_ok());
    }

    /// A client that disconnects while its prompt is waiting gets the prompt
    /// dropped, and the broker moves on to the next connection.
    #[tokio::test(flavor = "multi_thread")]
    async fn drops_the_prompt_of_a_disconnected_client() {
        let broker = TestBroker::start(accepting_policy()).await;

        let stream = std::os::unix::net::UnixStream::connect(&broker.socket_path).unwrap();
        (&stream)
            .write_all(b"{\"request\":\"confirm\",\"description\":\"hang\"}\n")
            .unwrap();
        // Give the broker time to read the request and reach the prompt.
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(stream);

        // Times out after five seconds if the broker is still stuck on the
        // first prompt.
        let response = broker.request(r#"{"request":"confirm","description":"ok"}"#);
        let response: WireResponse = serde_json::from_str(&response).unwrap();
        assert!(matches!(response, WireResponse::Confirmed { ok: true }));
        assert_eq!(broker.authorizer.prompts_dropped.load(Ordering::SeqCst), 1);
    }

    /// A client that gives up while its connection waits behind another is
    /// never served: its request reaches no authorizer.
    #[tokio::test(flavor = "multi_thread")]
    async fn skips_a_client_that_disconnected_while_queued() {
        let broker = TestBroker::start(accepting_policy()).await;

        // Holds the broker on a prompt nobody answers.
        let busy = std::os::unix::net::UnixStream::connect(&broker.socket_path).unwrap();
        (&busy)
            .write_all(b"{\"request\":\"confirm\",\"description\":\"hang\"}\n")
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Queues behind it, then gives up.
        let queued = std::os::unix::net::UnixStream::connect(&broker.socket_path).unwrap();
        (&queued)
            .write_all(b"{\"request\":\"sign\",\"key_label\":\"key-1\",\"data\":\"aGk=\"}\n")
            .unwrap();
        drop(queued);
        drop(busy);

        let response = broker.request(r#"{"request":"confirm","description":"ok"}"#);
        let response: WireResponse = serde_json::from_str(&response).unwrap();
        assert!(matches!(response, WireResponse::Confirmed { ok: true }));
        assert!(broker.authorizer.prompts.lock().unwrap().is_empty());
        assert_eq!(broker.authorizer.ended.load(Ordering::SeqCst), 0);

        // The closed connection could not be identified, which is not a
        // rejected peer.
        let rejected = audit::read(&audit::AuditFilter {
            actions: vec![audit::Action::BrokerPeerRejected],
            ..Default::default()
        });
        assert!(rejected.events.is_empty());
    }

    /// The authorizer is told who asked: the process on the other end of the
    /// socket, named by the caller that process delegated.
    #[tokio::test(flavor = "multi_thread")]
    async fn hands_the_verified_peer_to_the_authorizer() {
        let broker = TestBroker::start(accepting_policy()).await;

        broker.request(
            r#"{"request":"sign","key_label":"key-1","caller":"git (ssh)","data":"aGk="}"#,
        );

        let peers = broker.authorizer.peers.lock().unwrap();
        assert_eq!(peers.len(), 1);
        // This process is the peer, so the pid is ours and the chain is
        // whatever started the test runner.
        assert_eq!(peers[0].pid, Some(std::process::id()));
        assert!(
            peers[0].executable.is_some(),
            "peer executable not resolved"
        );
        // The delegated caller wins over the peer's own chain root: the peer is
        // the agent, and only the agent knows git asked it.
        assert_eq!(peers[0].caller.as_deref(), Some("git (ssh)"));
    }

    /// A request that delegates no caller still names the peer, falling back to
    /// the root of its own process chain.
    #[tokio::test(flavor = "multi_thread")]
    async fn names_the_peer_when_no_caller_is_delegated() {
        let broker = TestBroker::start(accepting_policy()).await;

        broker.request(r#"{"request":"sign","key_label":"key-1","data":"aGk="}"#);

        let peers = broker.authorizer.peers.lock().unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].pid, Some(std::process::id()));
    }

    /// A delegated caller chain reaches the prompt verbatim, so the app can let
    /// the user expand it.
    #[tokio::test(flavor = "multi_thread")]
    async fn delegates_the_caller_chain_to_the_prompt() {
        let broker = TestBroker::start(accepting_policy()).await;

        broker.request(
            r#"{"request":"sign","key_label":"key-1","caller":"git (ssh)","caller_chain":[{"command":"git","executable":"/usr/bin/git","pid":123,"bundle_id":null,"team_id":null},{"command":"zsh","executable":"/bin/zsh","pid":42,"bundle_id":null,"team_id":null}],"data":"aGk="}"#,
        );

        let prompts = broker.authorizer.prompts.lock().unwrap();
        assert_eq!(prompts.len(), 1);
        let chain: Vec<&str> = prompts[0]
            .caller_chain
            .iter()
            .map(|n| n.command.as_str())
            .collect();
        assert_eq!(chain, ["git", "zsh"]);
    }

    /// With no delegated chain, the prompt still gets one: the broker resolves
    /// it from its own verified peer.
    #[tokio::test(flavor = "multi_thread")]
    async fn falls_back_to_the_peer_chain_for_the_prompt() {
        let broker = TestBroker::start(accepting_policy()).await;

        broker.request(r#"{"request":"sign","key_label":"key-1","data":"aGk="}"#);

        let prompts = broker.authorizer.prompts.lock().unwrap();
        assert_eq!(prompts.len(), 1);
        assert!(
            !prompts[0].caller_chain.is_empty(),
            "peer chain not resolved for the prompt"
        );
    }

    /// A confirm-on-use request reaches the sign authorizer, worded for a key
    /// the agent holds rather than a managed one.
    #[tokio::test(flavor = "multi_thread")]
    async fn routes_a_key_use_authorization_to_the_sign_authorizer() {
        let broker = TestBroker::start(accepting_policy()).await;

        let response = broker.request(
            r#"{"request":"authorize_key_use","fingerprint":"SHA256:abc","comment":"work laptop","caller":"git (ssh)"}"#,
        );

        // The stub declines to hand back a context, so the request is answered
        // rather than confirmed. Reaching the stub means the peer was accepted
        // and the request routed.
        let response: WireResponse = serde_json::from_str(&response).unwrap();
        assert!(
            matches!(&response, WireResponse::Failed { message } if message == "stub authorizer"),
            "unexpected response to a key-use authorization"
        );

        let prompts = broker.authorizer.prompts.lock().unwrap();
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].fingerprint.as_deref(), Some("SHA256:abc"));
        assert_eq!(prompts[0].comment.as_deref(), Some("work laptop"));
        assert_eq!(prompts[0].caller.as_deref(), Some("git (ssh)"));
        assert!(!prompts[0].managed);
        assert_eq!(broker.authorizer.ended.load(Ordering::SeqCst), 1);
    }

    /// With no key id there is nothing to unlock, so the request goes straight
    /// to the app's text field and comes back with what the user typed.
    #[tokio::test(flavor = "multi_thread")]
    async fn collects_a_passphrase_for_a_key_with_nothing_saved() {
        let broker = TestBroker::start(accepting_policy()).await;

        let response = broker.request(
            r#"{"request":"get_passphrase","key_id":null,"description":"Enter passphrase","prompt":null,"error_message":null,"caller":"git (gpg)"}"#,
        );

        let response: WireResponse = serde_json::from_str(&response).unwrap();
        let WireResponse::Passphrase { passphrase } = response else {
            panic!("unexpected response to a passphrase request");
        };
        assert_eq!(b64.decode(passphrase).unwrap(), STUB_PASSPHRASE.as_bytes());

        let prompts = broker.authorizer.passphrase_prompts.lock().unwrap();
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].description.as_deref(), Some("Enter passphrase"));
        assert_eq!(prompts[0].caller.as_deref(), Some("git (gpg)"));
    }

    /// Confirm and message carry no secret, but they draw a window, so they are
    /// gated on the same peer check.
    #[tokio::test(flavor = "multi_thread")]
    async fn answers_confirm_and_message() {
        let broker = TestBroker::start(accepting_policy()).await;

        let response: WireResponse =
            serde_json::from_str(&broker.request(r#"{"request":"confirm","description":"ok?"}"#))
                .unwrap();
        assert!(matches!(response, WireResponse::Confirmed { ok: true }));

        let response: WireResponse =
            serde_json::from_str(&broker.request(r#"{"request":"message","description":"hi"}"#))
                .unwrap();
        assert!(matches!(response, WireResponse::Acknowledged));
    }

    /// A batch resolve reaches the vault authorizer, carrying the delegated
    /// caller and spanning whatever vaults its refs name.
    #[tokio::test(flavor = "multi_thread")]
    async fn routes_a_batch_resolve_to_the_vault_authorizer() {
        let broker = TestBroker::start(accepting_policy()).await;

        let response = broker.request(
            r#"{"request":"resolve_secrets","purpose":"exec","caller":"git","refs":[{"vault_key":"v1","item_key":"i1","credential_key":"c1"},{"vault_key":"v2","item_key":"i2","credential_key":"c2"}]}"#,
        );

        let response: WireResponse = serde_json::from_str(&response).unwrap();
        assert!(
            matches!(&response, WireResponse::Failed { message } if message == "stub authorizer"),
            "unexpected response to a batch resolve"
        );

        let peers = broker.authorizer.peers.lock().unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].caller.as_deref(), Some("git"));
        assert_eq!(broker.authorizer.ended.load(Ordering::SeqCst), 1);
    }

    /// Export, import and add each reach the vault authorizer with the
    /// delegated caller. The stub declines the context, so the request is
    /// answered rather than served.
    #[tokio::test(flavor = "multi_thread")]
    async fn routes_vault_management_to_the_vault_authorizer() {
        for line in [
            r#"{"request":"export_vaults","vault_keys":["v1"],"dest_path":"/tmp/x.axovault","mode":{"kind":"passphrase","passphrase":"pw","work_factor":18},"caller":"zsh"}"#,
            r#"{"request":"import_vaults","import_path":"/tmp/x.axovault","identity":{"kind":"passphrase","passphrase":"pw"},"selection":[["00000000-0000-0000-0000-000000000000","v2"]],"caller":"zsh"}"#,
            r#"{"request":"add_external_vault","path":"/tmp/v.json","caller":"zsh"}"#,
        ] {
            let broker = TestBroker::start(accepting_policy()).await;
            let response: WireResponse = serde_json::from_str(&broker.request(line)).unwrap();
            assert!(
                matches!(&response, WireResponse::Failed { message } if message == "stub authorizer"),
                "unexpected response to {line}"
            );
            let peers = broker.authorizer.peers.lock().unwrap();
            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].caller.as_deref(), Some("zsh"));
        }
    }

    /// An age identity request for a name not in the keychain is answered with
    /// `Failed`. Reaching that answer means the peer was accepted and the
    /// request framed, parsed and routed. The stub's `begin` is not asserted:
    /// `get_identity` checks the entry first, so a synthetic key never reaches
    /// the authorizer.
    #[tokio::test(flavor = "multi_thread")]
    async fn answers_an_age_identity_request_for_an_unknown_key() {
        let broker = TestBroker::start(accepting_policy()).await;

        let response =
            broker.request(r#"{"request":"get_age_identity","key_id":"nosuchkey","caller":"git"}"#);

        let response: WireResponse = serde_json::from_str(&response).unwrap();
        assert!(
            matches!(&response, WireResponse::Failed { message } if message.contains("nosuchkey")),
            "unexpected response to an unknown age key",
        );
        assert!(broker.authorizer.peers.lock().unwrap().is_empty());
    }

    /// A rejected peer cannot list the saved passwords.
    #[tokio::test(flavor = "multi_thread")]
    async fn hangs_up_on_a_rejected_peer_listing_keychain_passwords() {
        let broker = TestBroker::start(rejecting_policy()).await;

        let response = broker.request(r#"{"request":"list_keychain_passwords","caller":"evil"}"#);

        assert!(response.is_empty(), "broker answered a rejected peer");
    }

    /// Deleting a managed key that does not exist answers `Failed` rather than
    /// panicking.
    #[tokio::test(flavor = "multi_thread")]
    async fn answers_a_managed_key_deletion_for_an_unknown_label() {
        let broker = TestBroker::start(accepting_policy()).await;

        let response = broker.request(
            r#"{"request":"delete_managed_key","label":"ssh-key-nosuchkey","caller":"ap"}"#,
        );

        let response: WireResponse = serde_json::from_str(&response).unwrap();
        assert!(
            matches!(response, WireResponse::Failed { .. }),
            "unexpected response to an unknown managed key deletion"
        );
    }

    /// A rejected peer cannot ask for an age identity.
    #[tokio::test(flavor = "multi_thread")]
    async fn hangs_up_on_a_rejected_peer_asking_for_an_age_identity() {
        let broker = TestBroker::start(rejecting_policy()).await;

        let response =
            broker.request(r#"{"request":"get_age_identity","key_id":"demo","caller":"evil"}"#);

        assert!(response.is_empty(), "broker answered a rejected peer");
        assert!(broker.authorizer.peers.lock().unwrap().is_empty());
    }

    /// A rejected peer cannot ask for a passphrase either.
    #[tokio::test(flavor = "multi_thread")]
    async fn hangs_up_on_a_rejected_peer_asking_for_a_passphrase() {
        let broker = TestBroker::start(rejecting_policy()).await;

        let response = broker.request(
            r#"{"request":"get_passphrase","key_id":null,"description":null,"prompt":null,"error_message":null,"caller":"evil"}"#,
        );

        assert!(response.is_empty(), "broker answered a rejected peer");
        assert!(
            broker
                .authorizer
                .passphrase_prompts
                .lock()
                .unwrap()
                .is_empty()
        );
    }

    /// A process that is not the agent is hung up on and never reaches the
    /// authorizer.
    #[tokio::test(flavor = "multi_thread")]
    async fn hangs_up_on_a_peer_the_policy_rejects() {
        let broker = TestBroker::start(rejecting_policy()).await;

        let response = broker
            .request(r#"{"request":"sign","key_label":"key-1","caller":"evil","data":"aGk="}"#);

        assert!(response.is_empty(), "broker answered a rejected peer");
        assert!(broker.authorizer.prompts.lock().unwrap().is_empty());
    }

    /// Listing is gated on the same check as signing, so a rejected peer cannot
    /// read the public keys either.
    #[tokio::test(flavor = "multi_thread")]
    async fn hangs_up_on_a_rejected_peer_listing_identities() {
        let broker = TestBroker::start(rejecting_policy()).await;
        assert!(
            broker
                .request(r#"{"request":"list_identities"}"#)
                .is_empty()
        );
    }

    /// A socket left behind by a crashed app must not keep the broker offline.
    #[tokio::test(flavor = "multi_thread")]
    async fn replaces_a_stale_socket() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("app-broker.sock");
        // What a crashed app leaves behind: a socket file nothing is listening
        // on.
        fs::write(&socket_path, b"").unwrap();

        let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let authorizer = Arc::new(StubAuthorizer::default());
        tokio::spawn(serve_on(
            socket_path.clone(),
            accepting_policy(),
            Authorizers {
                sign: authorizer.clone(),
                passphrase: authorizer.clone(),
                vault: authorizer,
            },
            shutdown_rx,
        ));
        wait_for_socket(&socket_path).await;
    }

    /// The policy the app actually runs with never accepts a stray process.
    #[test]
    fn the_agent_policy_rejects_this_process() {
        let policy = agent_policy();
        let (ours, _theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        assert!(
            PeerIdentity::verify(ours.as_raw_fd(), &policy).is_err(),
            "the agent policy accepted the test binary"
        );
    }
}
