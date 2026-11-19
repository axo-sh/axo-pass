// The broker helpers serve tests that run on macOS only until the Linux peer
// check exists.
#![cfg_attr(linux, allow(dead_code, unused_imports))]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;

use crate::audit;
use crate::audit::test_support::{TestDir, test_dir};
use crate::core::app_broker::access::{Client, RequestScope};
use crate::core::app_broker::server::serve_on;
use crate::core::app_broker::wire::WireResponse;
use crate::core::app_broker::{
    Authorizers, BrokerPasswordEntry, ClientIdentity, CollectedPassphrase, ConfirmPrompt,
    KeychainLister, LoginIndex, PassphraseAuthorizer, PassphraseKind, PassphrasePrompt,
    PromptOutcome, SignAuthorizer, SignPrompt, vault,
};
use crate::core::auth::{AuthContext, ForeignContext};
use crate::core::provenance::PeerPolicy;
use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::generic_password::PasswordEntryType;
use crate::ssh::app_grants::GrantApp;

/// The passphrase the stub hands back when asked to collect one.
pub(super) const STUB_PASSPHRASE: &str = "hunter2";

/// Stands in for the app. It cannot produce a real `LAContext`, so both
/// `begin` methods decline. A request that reaches it has still been
/// accepted, framed, parsed and routed, which is what these tests cover.
#[derive(Default)]
pub(in crate::core::app_broker) struct StubAuthorizer {
    pub(super) prompts: Mutex<Vec<SignPrompt>>,
    pub(super) passphrase_prompts: Mutex<Vec<PassphrasePrompt>>,
    /// Kinds of the passphrase prompts passed to `begin`.
    pub(super) passphrase_kinds: Mutex<Vec<PassphraseKind>>,
    /// Whether the keychain listing fails on the shared context, as it does
    /// in a locked app.
    pub(super) locked: AtomicBool,
    pub(super) vault_prompts: Mutex<Vec<vault::VaultAccessPrompt>>,
    pub(super) peers: Mutex<Vec<audit::Actor>>,
    pub(super) ended: AtomicUsize,
    pub(super) prompts_hung: AtomicUsize,
    pub(super) prompts_dropped: AtomicUsize,
    /// Signalled when the broker abandons a vault request, as the app's
    /// prompt does when its client disconnects.
    abandoned: tokio::sync::Notify,
}

impl StubAuthorizer {
    /// Wait for a user who never answers, until the request is abandoned.
    /// Starting and ending the wait are both counted.
    async fn hang(&self) {
        self.prompts_hung.fetch_add(1, Ordering::SeqCst);
        struct Dropped<'a>(&'a AtomicUsize);
        impl Drop for Dropped<'_> {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let _dropped = Dropped(&self.prompts_dropped);
        self.abandoned.notified().await;
    }

    /// Block until a `"hang"` prompt has started. Verifying a peer can take
    /// hundreds of milliseconds, so a fixed sleep may end before the
    /// request reaches its prompt.
    #[cfg_attr(linux, allow(dead_code))]
    pub(super) fn wait_for_hung_prompt(&self) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while self.prompts_hung.load(Ordering::SeqCst) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the hanging request never reached its prompt"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Answers with a fixed entry instead of reading the login keychain, which
/// would raise an authorization prompt and stall the suite. If `locked` is
/// set, the shared context fails as it does in a locked app.
impl KeychainLister for StubAuthorizer {
    fn list_passwords(
        &self,
        context: AuthContext,
    ) -> Result<Vec<BrokerPasswordEntry>, KeychainError> {
        if self.locked.load(Ordering::SeqCst) && matches!(context, AuthContext::SharedThreadLocal) {
            return Err(KeychainError::AuthenticationExpired);
        }
        Ok(vec![BrokerPasswordEntry {
            password_type: PasswordEntryType::SSHKey,
            key_id: "stub".to_string(),
        }])
    }
}

#[async_trait]
impl SignAuthorizer for StubAuthorizer {
    async fn begin(
        &self,
        prompt: SignPrompt,
        peer: audit::Actor,
    ) -> Result<ForeignContext, String> {
        self.prompts.lock().unwrap().push(prompt);
        self.peers.lock().unwrap().push(peer);
        Err("stub authorizer".to_string())
    }

    async fn end(&self, _prompt: SignPrompt, _outcome: PromptOutcome) {
        self.ended.fetch_add(1, Ordering::SeqCst);
    }

    async fn notify_preapproved(&self, _prompt: SignPrompt, _app: GrantApp) {}
}

#[async_trait]
impl PassphraseAuthorizer for StubAuthorizer {
    async fn begin(
        &self,
        prompt: PassphrasePrompt,
        peer: audit::Actor,
    ) -> Result<ForeignContext, String> {
        self.passphrase_kinds.lock().unwrap().push(prompt.kind);
        self.peers.lock().unwrap().push(peer);
        Err("stub authorizer".to_string())
    }

    async fn collect(
        &self,
        prompt: PassphrasePrompt,
        _can_use_saved: bool,
    ) -> Result<Option<CollectedPassphrase>, String> {
        self.passphrase_prompts.lock().unwrap().push(prompt);
        Ok(Some(CollectedPassphrase {
            value: secrecy::SecretString::from(STUB_PASSPHRASE),
            // Nothing may touch the real keychain from a test.
            save_to_keychain: false,
            use_saved: false,
        }))
    }

    async fn end(&self, _prompt: PassphrasePrompt, _outcome: PromptOutcome) {
        self.ended.fetch_add(1, Ordering::SeqCst);
    }

    /// `"hang"` stands for a user who never answers. Its prompt is only
    /// ever dropped. Starting and dropping it are both counted.
    async fn confirm(&self, prompt: ConfirmPrompt) -> bool {
        if prompt.description.as_deref() == Some("hang") {
            self.hang().await;
        }
        true
    }

    async fn message(&self, _description: Option<String>) {}
}

#[async_trait]
impl vault::VaultAuthorizer for StubAuthorizer {
    async fn begin(
        &self,
        prompt: vault::VaultAccessPrompt,
        peer: audit::Actor,
    ) -> Result<vault::VaultAuthorization, String> {
        if matches!(
            &prompt.client,
            ClientIdentity::Browser { extension: Some(extension), .. } if extension == "hang"
        ) {
            self.hang().await;
            return Err("abandoned".to_string());
        }
        self.vault_prompts.lock().unwrap().push(prompt);
        self.peers.lock().unwrap().push(peer);
        Err("stub authorizer".to_string())
    }

    async fn abandon(&self) {
        self.abandoned.notify_one();
    }

    async fn end(&self, _prompt: vault::VaultAccessPrompt, _outcome: PromptOutcome) {
        self.ended.fetch_add(1, Ordering::SeqCst);
    }
}

/// A broker on a scratch socket, shut down when dropped.
pub(super) struct TestBroker {
    pub(super) socket_path: PathBuf,
    pub(super) authorizer: Arc<StubAuthorizer>,
    pub(super) logins: Arc<LoginIndex>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    server: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    // Rejecting a peer and serving a vault request both write audit
    // events. Held so they land in a scratch directory instead of the one
    // an audit test is counting.
    _audit_dir: TestDir,
    _dir: tempfile::TempDir,
}

impl TestBroker {
    pub(super) async fn start(policy: PeerPolicy) -> Self {
        Self::start_with_scope(policy, RequestScope::Agent).await
    }

    pub(super) async fn start_with_scope(policy: PeerPolicy, scope: RequestScope) -> Self {
        Self::start_with_clients(vec![Client { policy, scope }]).await
    }

    pub(super) async fn start_with_clients(clients: Vec<Client>) -> Self {
        let audit_dir = test_dir();
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("app-broker.sock");
        let authorizer = Arc::new(StubAuthorizer::default());
        let logins = Arc::new(LoginIndex::default());
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let server = tokio::spawn(serve_on(
            socket_path.clone(),
            clients,
            Authorizers {
                sign: authorizer.clone(),
                passphrase: authorizer.clone(),
                vault: authorizer.clone(),
                keychain: authorizer.clone(),
                logins: logins.clone(),
                vaults: empty_vaults(),
            },
            shutdown_rx,
        ));
        wait_for_socket(&socket_path).await;

        TestBroker {
            socket_path,
            authorizer,
            logins,
            shutdown: Some(shutdown_tx),
            server: Some(server),
            _audit_dir: audit_dir,
            _dir: dir,
        }
    }

    /// Send one request line the way an outside process would, and return
    /// the response line. Empty means the broker hung up on us.
    pub(super) fn request(&self, line: &str) -> String {
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

    /// [`Self::request`], with the response line parsed.
    pub(super) fn request_parsed(&self, line: &str) -> WireResponse {
        serde_json::from_str(&self.request(line)).unwrap()
    }
}

/// Waits for the serve task to exit so its listener is closed before the
/// test ends. Requires a multi-thread runtime.
impl Drop for TestBroker {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(server) = self.server.take() {
            tokio::task::block_in_place(|| {
                let _ = tokio::runtime::Handle::current().block_on(server);
            });
        }
    }
}

/// `serve_on` binds before it accepts, so a connectable socket is the
/// readiness signal.
pub(super) async fn wait_for_socket(socket_path: &Path) {
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
pub(super) fn accepting_policy() -> PeerPolicy {
    PeerPolicy {
        same_user: true,
        requirement: None,
        executable: Some(std::env::current_exe().unwrap()),
    }
}

/// A policy no test process satisfies.
#[cfg_attr(linux, allow(dead_code))]
pub(super) fn rejecting_policy() -> PeerPolicy {
    PeerPolicy {
        executable: Some(PathBuf::from("/usr/bin/true")),
        ..accepting_policy()
    }
}

pub(super) const PAGE: &str =
    r#""url":"https://example.com","frame_url":"https://example.com/login""#;
pub(super) const CHROME: &str = r#""client":{"browser":{"name":"Google Chrome","team_id":"EQHXZ8M8AV"},"extension":"chrome-extension://abc/"}"#;

/// A browser whose vault prompts are never answered, see
/// [`StubAuthorizer::hang`].
pub(super) const HANGING: &str =
    r#""client":{"browser":{"name":"Google Chrome","team_id":"EQHXZ8M8AV"},"extension":"hang"}"#;

pub(super) async fn browser_host_broker() -> TestBroker {
    TestBroker::start_with_scope(accepting_policy(), RequestScope::BrowserHost).await
}

/// A vault store with no vaults, so no test reads the developer's own vaults.
pub(in crate::core::app_broker) fn empty_vaults() -> crate::secrets::vaults::VaultCatalog {
    crate::secrets::vaults::VaultCatalog::with_unlocker(
        PathBuf::from("/nonexistent/vaults"),
        crate::secrets::vaults::storage::txn::VaultWriter::isolated("/nonexistent/data"),
        Default::default(),
        Arc::new(crate::secrets::vaults::storage::test_unlocker::KeyUnlocker::default()),
    )
}
