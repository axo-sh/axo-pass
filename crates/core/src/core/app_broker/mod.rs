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
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as b64;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as AsyncBufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::core::dirs::app_data_dir;
use crate::core::provenance::{PeerIdentity, PeerPolicy};

pub mod gpg;
pub mod ssh;

pub use gpg::{
    CollectedPassphrase, PassphraseAuthorizer, PassphraseKind, PassphrasePrompt, request_confirm,
    request_message, request_passphrase,
};
pub use ssh::{
    ManagedIdentity, SignAuthorizer, SignPrompt, list_identities, request_signature,
    request_ssh_passphrase,
};

/// How long the agent waits for the user to answer the app's prompt before
/// giving up and falling back to the system dialog.
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

/// Marks an `open` issued by [`launch_app`]. `open` delivers a reopen event to
/// an app that is already running and drops `--args` when it does, so a marker
/// is the only way to tell a broker launch from a person opening the app.
fn launch_request_path() -> PathBuf {
    app_data_dir().join("app-broker.launch")
}

/// How long a launch marker stays meaningful: long enough to cover a cold
/// launch, short enough that a stale one does not swallow a real reopen.
const LAUNCH_REQUEST_TTL: Duration = Duration::from_secs(30);

/// Consume the marker left by [`launch_app`]. True when this launch or reopen
/// came from the broker, in which case the app must stay headless.
pub fn take_launch_request() -> bool {
    let path = launch_request_path();
    let Ok(metadata) = fs::metadata(&path) else {
        return false;
    };
    let _ = fs::remove_file(&path);
    metadata
        .modified()
        .ok()
        .and_then(|written| written.elapsed().ok())
        .is_some_and(|age| age < LAUNCH_REQUEST_TTL)
}

#[derive(Debug, Error)]
pub enum BrokerError {
    /// No app is listening. The caller should fall back to its own prompt.
    #[error("App broker unavailable")]
    Unavailable,

    #[error("User cancelled the prompt")]
    Cancelled,

    #[error("App broker failed: {0}")]
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
}

/// The wire format: one JSON line each way, one request per connection.
#[derive(Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case")]
enum WireRequest {
    ListIdentities,
    Sign {
        key_label: String,

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

        /// Base64 of the bytes to sign.
        data: String,
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
    Acknowledged,
    Cancelled,
    Failed {
        message: String,
    },
}

// Client (the agent).

fn send_request(request: &WireRequest) -> Result<WireResponse, BrokerError> {
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

    let mut response_line = String::new();
    BufReader::new(&stream)
        .read_line(&mut response_line)
        .map_err(|e| BrokerError::Failed(format!("Failed to read response: {e}")))?;
    if response_line.trim().is_empty() {
        // The app went away mid-request.
        return Err(BrokerError::Unavailable);
    }

    serde_json::from_str(&response_line)
        .map_err(|e| BrokerError::Failed(format!("Malformed response: {e}")))
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
fn app_bundle_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    log::debug!("Resolving the app bundle from {}", exe.display());
    exe.ancestors()
        .find(|path| path.extension().is_some_and(|ext| ext == "app"))
        .map(Path::to_path_buf)
}

/// Start the app in the background, so a signature request does not pull focus
/// away from whatever asked for it.
fn launch_app() -> Result<(), BrokerError> {
    let Some(bundle) = app_bundle_path() else {
        log::debug!("Not running from an app bundle; cannot start the broker");
        return Err(BrokerError::Unavailable);
    };

    log::debug!("Starting {} for the app broker", bundle.display());
    // The marker tells the app this launch is only to serve the broker, so it
    // stays headless: no main window, no Dock icon, no focus taken.
    if let Err(e) = fs::write(launch_request_path(), b"") {
        log::debug!("Could not write the broker launch marker: {e}");
    }
    let status = std::process::Command::new("/usr/bin/open")
        .arg("-g")
        .arg(&bundle)
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
                    Err(e) => {
                        log::warn!("App broker refused a connection: {e}");
                        continue;
                    },
                };
                log::debug!("App broker peer: {peer:#?}");

                let authorizers = authorizers.clone();
                // Serially, not spawned: two prompts at once would contend for
                // the screen and the system's authentication session.
                if let Err(e) = handle_connection(stream, authorizers).await {
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

async fn handle_connection(stream: UnixStream, authorizers: Authorizers) -> std::io::Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut request_line = String::new();
    AsyncBufReader::new(read_half)
        .read_line(&mut request_line)
        .await?;
    let request: WireRequest = serde_json::from_str(&request_line)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let response = match request {
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
            caller,
            data,
        } => {
            let data = b64
                .decode(&data)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            let prompt = SignPrompt { key_label, caller };
            log::debug!("App broker request: {prompt:?}");
            ssh::authorize_and_sign(&*authorizers.sign, prompt, data).await
        },
        WireRequest::GetPassphrase {
            key_id,
            description,
            prompt,
            error_message,
            caller,
        } => {
            let prompt = PassphrasePrompt {
                kind: PassphraseKind::Gpg,
                key_id,
                description,
                prompt,
                error_message,
                caller,
            };
            log::debug!("App broker request: {prompt:?}");
            gpg::get_passphrase(&*authorizers.passphrase, prompt).await
        },
        WireRequest::GetSshPassphrase {
            key_id,
            prompt,
            caller,
        } => {
            let prompt = PassphrasePrompt {
                kind: PassphraseKind::Ssh,
                key_id,
                description: None,
                prompt: Some(prompt),
                error_message: None,
                caller,
            };
            log::debug!("App broker request: {prompt:?}");
            ssh::get_passphrase(&*authorizers.passphrase, prompt).await
        },
        WireRequest::Confirm { description } => {
            log::debug!("App broker request: confirm");
            WireResponse::Confirmed {
                ok: authorizers.passphrase.confirm(description).await,
            }
        },
        WireRequest::Message { description } => {
            log::debug!("App broker request: message");
            authorizers.passphrase.message(description).await;
            WireResponse::Acknowledged
        },
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
        ended: AtomicUsize,
    }

    #[async_trait]
    impl SignAuthorizer for StubAuthorizer {
        async fn begin(
            &self,
            prompt: SignPrompt,
        ) -> Result<crate::core::auth::ForeignContext, String> {
            self.prompts.lock().unwrap().push(prompt);
            Err("stub authorizer".to_string())
        }

        async fn end(&self, _prompt: SignPrompt, _outcome: PromptOutcome) {
            self.ended.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl PassphraseAuthorizer for StubAuthorizer {
        async fn begin(
            &self,
            _prompt: PassphrasePrompt,
        ) -> Result<crate::core::auth::ForeignContext, String> {
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

        async fn confirm(&self, _description: Option<String>) -> bool {
            true
        }

        async fn message(&self, _description: Option<String>) {}
    }

    /// A broker on a scratch socket, shut down when dropped.
    struct TestBroker {
        socket_path: PathBuf,
        authorizer: Arc<StubAuthorizer>,
        shutdown: Option<tokio::sync::oneshot::Sender<()>>,
        _dir: tempfile::TempDir,
    }

    impl TestBroker {
        async fn start(policy: PeerPolicy) -> Self {
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
                },
                shutdown_rx,
            ));
            wait_for_socket(&socket_path).await;

            TestBroker {
                socket_path,
                authorizer,
                shutdown: Some(shutdown_tx),
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
                passphrase: authorizer,
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
