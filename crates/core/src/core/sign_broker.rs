//! Hands the agent's managed-key work to the app.
//!
//! The agent cannot do this work itself, for two reasons. It runs headless, so
//! it can only raise the system authentication dialog; drawing the prompt
//! inline needs an `LAAuthenticationView` attached to a context owned by a
//! process that can put a window on screen, and an `LAContext` cannot cross a
//! process boundary. It also cannot reach the keys: they live in the data
//! protection keychain, which needs the restricted `keychain-access-groups`
//! entitlement, and AMFI only honours that for code carrying a provisioning
//! profile, which a plain executable has nowhere to hold.
//!
//! The app has both the window and the entitlement, so the agent proxies to it
//! over a Unix socket and never touches the keychain itself. Requests are
//! served whether or not the vault is unlocked. Signing prompts; listing does
//! not.
//!
//! With no app running the client launches it and waits for the socket, so
//! `ssh-add -l` against a closed app starts it rather than reporting no keys.
//!
//! The broker identifies the peer before reading a request: it must be the `ap`
//! staged in this bundle, signed by the same team. See `agent_policy`.

use std::fs::{self, Permissions};
use std::future::Future;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as b64;
use serde::{Deserialize, Serialize};
use ssh_key::{Algorithm, Signature};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as AsyncBufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::core::auth::{AuthContext, ForeignContext, sign_with_managed_key_on};
use crate::core::dirs::app_data_dir;
use crate::core::provenance::{PeerIdentity, PeerPolicy};
use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::managed_key::ManagedSshKey;

/// How long the agent waits for the user to answer the app's prompt before
/// giving up and falling back to the system dialog.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(120);

/// How long to wait for a cold app launch to start serving.
const LAUNCH_TIMEOUT: Duration = Duration::from_secs(20);
const LAUNCH_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// The agent ships inside the app bundle, beside the app's own executable.
const AGENT_EXECUTABLE_NAME: &str = "ap";

pub fn broker_socket_path() -> PathBuf {
    // typically: ~/Library/Application Support/Axo Pass/sign-broker.sock
    app_data_dir().join("sign-broker.sock")
}

#[derive(Debug, Error)]
pub enum SignBrokerError {
    /// No app is listening. The caller should fall back to its own prompt.
    #[error("Signing broker unavailable")]
    Unavailable,

    #[error("User cancelled the signing prompt")]
    Cancelled,

    #[error("Signing broker failed: {0}")]
    Failed(String),
}

/// What the app needs to describe the prompt.
#[derive(Debug, Clone)]
pub struct SignPrompt {
    pub key_label: String,

    /// Who asked, as the agent resolved it. See [`WireRequest::Sign`] for why
    /// this can be shown to the user.
    pub caller: Option<String>,
}

/// How a signing attempt ended.
///
/// The app distinguishes an approval from a dismissed prompt. Only an approval
/// starts the clocks that bound how long it is reused, and only an approval is
/// reported to the user.
#[derive(Debug, Clone)]
pub enum SignOutcome {
    Succeeded,
    Cancelled,
    Failed(String),
}

/// Supplies an `LAContext` to sign on, and learns how the attempt ended so it
/// can take its prompt down.
pub trait SignAuthorizer: Send + Sync + 'static {
    /// Prepare a context for `prompt` and put the prompt on screen. The broker
    /// evaluates the returned context, which is what makes the attached
    /// `LAAuthenticationView` draw.
    fn begin(
        &self,
        prompt: SignPrompt,
    ) -> Pin<Box<dyn Future<Output = Result<ForeignContext, String>> + Send>>;

    /// The attempt finished. Always called once `begin` has been called, so the
    /// app can take the prompt down and settle the authorization it handed out.
    fn end(
        &self,
        prompt: SignPrompt,
        outcome: SignOutcome,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

// --------------------------------------------------------------------------
// Wire format: one JSON line each way, one request per connection.
// --------------------------------------------------------------------------

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
    Cancelled,
    Failed {
        message: String,
    },
}

/// A managed key as the agent sees it: enough to advertise the identity and to
/// ask for a signature later, with no keychain access of its own.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedIdentity {
    pub key_label: String,
    /// One OpenSSH public key line: algorithm, base64 key, comment.
    pub public_key: String,
}

// --------------------------------------------------------------------------
// Client (the agent)
// --------------------------------------------------------------------------

/// List the managed keys the app can sign with. Blocking, and starts the app if
/// it is not already running.
pub fn list_identities() -> Result<Vec<ManagedIdentity>, SignBrokerError> {
    match send_request(&WireRequest::ListIdentities)? {
        WireResponse::Identities { keys } => Ok(keys),
        WireResponse::Failed { message } => Err(SignBrokerError::Failed(message)),
        _ => Err(SignBrokerError::Failed(
            "Unexpected response to identity listing".to_string(),
        )),
    }
}

/// Ask the app to authorize and produce a signature. Blocking: it waits for the
/// user to answer a prompt, so call it from a thread that can block.
pub fn request_signature(
    key_label: &str,
    data: &[u8],
    caller: Option<&str>,
) -> Result<Signature, SignBrokerError> {
    let request = WireRequest::Sign {
        key_label: key_label.to_string(),
        caller: caller.map(String::from),
        data: b64.encode(data),
    };
    match send_request(&request)? {
        WireResponse::Signed {
            algorithm,
            signature,
        } => {
            let algorithm = Algorithm::new(&algorithm)
                .map_err(|e| SignBrokerError::Failed(format!("Unknown algorithm: {e}")))?;
            let body = b64
                .decode(signature)
                .map_err(|e| SignBrokerError::Failed(format!("Malformed signature: {e}")))?;
            Signature::new(algorithm, body)
                .map_err(|e| SignBrokerError::Failed(format!("Invalid signature: {e}")))
        },
        WireResponse::Cancelled => Err(SignBrokerError::Cancelled),
        WireResponse::Failed { message } => Err(SignBrokerError::Failed(message)),
        _ => Err(SignBrokerError::Failed(
            "Unexpected response to signing request".to_string(),
        )),
    }
}

fn send_request(request: &WireRequest) -> Result<WireResponse, SignBrokerError> {
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
        .map_err(|e| SignBrokerError::Failed(e.to_string()))?;

    let mut line =
        serde_json::to_vec(request).map_err(|e| SignBrokerError::Failed(e.to_string()))?;
    line.push(b'\n');
    (&stream)
        .write_all(&line)
        .and_then(|_| (&stream).flush())
        .map_err(|e| SignBrokerError::Failed(format!("Failed to send request: {e}")))?;

    let mut response_line = String::new();
    BufReader::new(&stream)
        .read_line(&mut response_line)
        .map_err(|e| SignBrokerError::Failed(format!("Failed to read response: {e}")))?;
    if response_line.trim().is_empty() {
        // The app went away mid-request.
        return Err(SignBrokerError::Unavailable);
    }

    serde_json::from_str(&response_line)
        .map_err(|e| SignBrokerError::Failed(format!("Malformed response: {e}")))
}

fn connect() -> std::io::Result<std::os::unix::net::UnixStream> {
    std::os::unix::net::UnixStream::connect(broker_socket_path())
}

/// The bundle holding this executable, i.e. `.../Axo Pass.app` for the `ap`
/// staged at `Contents/MacOS/ap`.
fn app_bundle_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let bundle = exe.parent()?.parent()?.parent()?;
    (bundle.extension()? == "app").then(|| bundle.to_path_buf())
}

/// Start the app in the background, so a signature request does not pull focus
/// away from whatever asked for it.
fn launch_app() -> Result<(), SignBrokerError> {
    let Some(bundle) = app_bundle_path() else {
        log::debug!("Not running from an app bundle; cannot start the broker");
        return Err(SignBrokerError::Unavailable);
    };

    log::debug!("Starting {} for the signing broker", bundle.display());
    let status = std::process::Command::new("/usr/bin/open")
        .arg("-g")
        .arg(&bundle)
        .status()
        .map_err(|e| SignBrokerError::Failed(format!("Failed to start the app: {e}")))?;
    if !status.success() {
        return Err(SignBrokerError::Failed(format!(
            "Failed to start {}: open exited with {status}",
            bundle.display()
        )));
    }
    Ok(())
}

fn wait_for_broker() -> Result<std::os::unix::net::UnixStream, SignBrokerError> {
    let deadline = std::time::Instant::now() + LAUNCH_TIMEOUT;
    loop {
        if let Ok(stream) = connect() {
            return Ok(stream);
        }
        if std::time::Instant::now() >= deadline {
            log::warn!("The app did not start serving signing requests in time");
            return Err(SignBrokerError::Unavailable);
        }
        std::thread::sleep(LAUNCH_POLL_INTERVAL);
    }
}

// --------------------------------------------------------------------------
// Server (the app)
// --------------------------------------------------------------------------

/// Serve signing requests until `shutdown` resolves, then remove the socket.
pub async fn serve(
    authorizer: Arc<dyn SignAuthorizer>,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) -> std::io::Result<()> {
    serve_on(broker_socket_path(), agent_policy(), authorizer, shutdown).await
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
    authorizer: Arc<dyn SignAuthorizer>,
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
                    format!("another signing broker owns {}", socket_path.display()),
                ));
            },
            Err(_) => {
                log::debug!("Replacing stale signing broker socket {socket_path:?}");
                fs::remove_file(&socket_path)?;
            },
        }
    }

    let listener = UnixListener::bind(&socket_path)?;
    fs::set_permissions(&socket_path, Permissions::from_mode(0o600)).inspect_err(|_| {
        let _ = fs::remove_file(&socket_path);
    })?;
    log::debug!("Signing broker listening on {}", socket_path.display());

    tokio::select! {
        _ = accept_loop(listener, authorizer, policy) => {},
        _ = shutdown => log::debug!("Signing broker shutting down"),
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
        log::debug!("Signing broker accepts {accepts}, signed by our own team");
    } else {
        log::warn!(
            "Signing broker cannot check its peer's code signature: this build carries no team \
             identifier. Accepting {accepts}"
        );
    }
    policy
}

async fn accept_loop(
    listener: UnixListener,
    authorizer: Arc<dyn SignAuthorizer>,
    policy: PeerPolicy,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let peer = match PeerIdentity::verify(stream.as_raw_fd(), &policy) {
                    Ok(peer) => peer,
                    Err(e) => {
                        log::warn!("Signing broker refused a connection: {e}");
                        continue;
                    },
                };
                log::debug!("Signing broker peer: {peer:#?}");

                let authorizer = authorizer.clone();
                // Serially, not spawned: two prompts at once would contend for
                // the screen and the system's authentication session.
                if let Err(e) = handle_connection(stream, authorizer).await {
                    log::debug!("Signing broker connection failed: {e}");
                }
            },
            Err(e) => {
                log::error!("Signing broker accept failed: {e}");
                return;
            },
        }
    }
}

async fn handle_connection(
    stream: UnixStream,
    authorizer: Arc<dyn SignAuthorizer>,
) -> std::io::Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut request_line = String::new();
    AsyncBufReader::new(read_half)
        .read_line(&mut request_line)
        .await?;
    let request: WireRequest = serde_json::from_str(&request_line)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let response = match request {
        WireRequest::ListIdentities => {
            log::debug!("Signing broker request: list identities");
            tokio::task::spawn_blocking(list_identities_locally)
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
            log::debug!("Signing broker request: {prompt:?}");
            authorize_and_sign(&*authorizer, prompt, data).await
        },
    };

    let mut line =
        serde_json::to_vec(&response).map_err(|e| std::io::Error::other(e.to_string()))?;
    line.push(b'\n');
    write_half.write_all(&line).await?;
    write_half.flush().await
}

/// Read the managed keys out of the keychain. Listing needs no authentication,
/// so this raises no prompt and works with the vault still locked.
fn list_identities_locally() -> Result<Vec<ManagedIdentity>, String> {
    let keys = ManagedSshKey::list().map_err(|e| format!("Failed to list managed keys: {e}"))?;
    let mut identities = Vec::with_capacity(keys.len());
    for key in keys {
        let comment = format!("axo-secure-enclave:{}", &key.name()[0..6]);
        let public_key = ssh_key::PublicKey::new(key.public_key().clone(), comment)
            .to_openssh()
            .map_err(|e| format!("Failed to encode public key: {e}"))?;
        identities.push(ManagedIdentity {
            key_label: key.label(),
            public_key,
        });
    }
    Ok(identities)
}

async fn authorize_and_sign(
    authorizer: &dyn SignAuthorizer,
    prompt: SignPrompt,
    data: Vec<u8>,
) -> WireResponse {
    let context = match authorizer.begin(prompt.clone()).await {
        Ok(context) => context,
        Err(message) => {
            log::debug!("Signing broker authorization declined: {message}");
            // `begin` may already have put a prompt on screen, so end the
            // attempt rather than leaving it there.
            authorizer
                .end(prompt, SignOutcome::Failed(message.clone()))
                .await;
            return WireResponse::Failed { message };
        },
    };

    let key_label = prompt.key_label.clone();
    let caller = prompt.caller.clone();
    let result = tokio::task::spawn_blocking(move || {
        sign_with_managed_key_on(
            AuthContext::Foreign(context),
            &key_label,
            &data,
            caller.as_deref(),
        )
    })
    .await
    .unwrap_or_else(|e| {
        Err(KeychainError::SigningFailed(format!(
            "Signing task failed: {e}"
        )))
    });

    let (response, outcome) = match result {
        Ok(signature) => (
            WireResponse::Signed {
                algorithm: signature.algorithm().to_string(),
                signature: b64.encode(signature.as_bytes()),
            },
            SignOutcome::Succeeded,
        ),
        // A dismissed prompt is the user's answer, so report a cancellation
        // rather than a failure.
        Err(KeychainError::UserCancelled) => (WireResponse::Cancelled, SignOutcome::Cancelled),
        Err(e) => {
            let message = e.to_string();
            (
                WireResponse::Failed {
                    message: message.clone(),
                },
                SignOutcome::Failed(message),
            )
        },
    };
    authorizer.end(prompt, outcome).await;
    response
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;
    use std::path::Path;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// Stands in for the app. It cannot produce a real `LAContext`, so `begin`
    /// always declines. A request that reaches it has still been accepted,
    /// framed, parsed and routed, which is what these tests cover.
    #[derive(Default)]
    struct StubAuthorizer {
        prompts: Mutex<Vec<SignPrompt>>,
        ended: AtomicUsize,
    }

    impl SignAuthorizer for StubAuthorizer {
        fn begin(
            &self,
            prompt: SignPrompt,
        ) -> Pin<Box<dyn Future<Output = Result<ForeignContext, String>> + Send>> {
            self.prompts.lock().unwrap().push(prompt);
            Box::pin(async { Err("stub authorizer".to_string()) })
        }

        fn end(
            &self,
            _prompt: SignPrompt,
            _outcome: SignOutcome,
        ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            self.ended.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {})
        }
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
            let socket_path = dir.path().join("sign-broker.sock");
            let authorizer = Arc::new(StubAuthorizer::default());
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

            tokio::spawn(serve_on(
                socket_path.clone(),
                policy,
                authorizer.clone(),
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
        let socket_path = dir.path().join("sign-broker.sock");
        // What a crashed app leaves behind: a socket file nothing is listening
        // on.
        fs::write(&socket_path, b"").unwrap();

        let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(serve_on(
            socket_path.clone(),
            accepting_policy(),
            Arc::new(StubAuthorizer::default()),
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
