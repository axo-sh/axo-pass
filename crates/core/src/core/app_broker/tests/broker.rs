//! Helpers for tests through a live broker. The Linux peer check refuses every
//! client, so these tests run on macOS only.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::support::{StubAuthorizer, empty_vaults};
use crate::audit::test_support::{TestDir, test_dir};
use crate::core::app_broker::access::{Client, RequestScope};
use crate::core::app_broker::server::serve_on;
use crate::core::app_broker::wire::WireResponse;
use crate::core::app_broker::{Authorizers, LoginIndex};
use crate::core::provenance::PeerPolicy;

impl StubAuthorizer {
    /// Block until a `"hang"` prompt has started. Verifying a peer can take
    /// hundreds of milliseconds, so a fixed sleep may end before the
    /// request reaches its prompt.
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
pub(super) fn rejecting_policy() -> PeerPolicy {
    PeerPolicy {
        executable: Some(PathBuf::from("/usr/bin/true")),
        ..accepting_policy()
    }
}

pub(super) const CHROME: &str = r#""client":{"browser":{"name":"Google Chrome","team_id":"EQHXZ8M8AV"},"extension":"chrome-extension://abc/"}"#;

/// A browser whose vault prompts are never answered, see
/// [`StubAuthorizer::hang`].
pub(super) const HANGING: &str =
    r#""client":{"browser":{"name":"Google Chrome","team_id":"EQHXZ8M8AV"},"extension":"hang"}"#;

pub(super) async fn browser_host_broker() -> TestBroker {
    TestBroker::start_with_scope(accepting_policy(), RequestScope::BrowserHost).await
}
