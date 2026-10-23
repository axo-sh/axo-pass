#[test]
fn a_frame_on_another_site_is_cross_site() {
    let page = vault::LoginPage::parse("https://evil.com", "https://example.com", None).unwrap();
    assert!(page.cross_site);
    assert_eq!(page.top_host.as_deref(), Some("evil.com"));
    assert!(page.require_same_site().is_err());
}

#[test]
fn a_frame_on_a_sibling_subdomain_is_not_cross_site() {
    let page = vault::LoginPage::parse(
        "https://example.com",
        "https://accounts.example.com/login",
        None,
    )
    .unwrap();
    assert!(!page.cross_site);
    assert_eq!(page.top_host.as_deref(), Some("example.com"));
    assert!(page.require_same_site().is_ok());
}

#[test]
fn a_top_level_page_is_not_cross_site() {
    let page = vault::LoginPage::parse("https://example.com", "https://example.com", None).unwrap();
    assert!(!page.cross_site);
    assert!(page.require_same_site().is_ok());
}

#[test]
fn shared_hosting_domains_are_cross_site() {
    let page = vault::LoginPage::parse("https://a.github.io", "https://b.github.io", None).unwrap();
    assert!(page.cross_site);
}

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as b64;

use super::access::{
    AUTOFILL_CALLER, Client, RequestScope, UNKNOWN_CLIENT, agent_policy, requester_for,
};
use super::client::wait_for_response;
use super::in_flight::InFlightRequest;
use super::mach::{self, TestRequest};
use super::server::serve_on;
use super::wire::{WireRequest, WireResponse};
use super::*;
use crate::audit;
use crate::audit::test_support::{TestDir, test_dir};
use crate::core::auth::ForeignContext;
use crate::core::provenance::{PeerIdentity, PeerPolicy};
use crate::secrets::keychain::generic_password::PasswordEntryType;
use crate::ssh::app_grants::GrantApp;

/// The passphrase the stub hands back when asked to collect one.
const STUB_PASSPHRASE: &str = "hunter2";

/// Stands in for the app. It cannot produce a real `LAContext`, so both
/// `begin` methods decline. A request that reaches it has still been
/// accepted, framed, parsed and routed, which is what these tests cover.
#[derive(Default)]
struct StubAuthorizer {
    prompts: Mutex<Vec<SignPrompt>>,
    passphrase_prompts: Mutex<Vec<PassphrasePrompt>>,
    vault_prompts: Mutex<Vec<vault::VaultAccessPrompt>>,
    peers: Mutex<Vec<audit::Actor>>,
    ended: AtomicUsize,
    prompts_hung: AtomicUsize,
    prompts_dropped: AtomicUsize,
}

impl StubAuthorizer {
    /// Block until a `"hang"` prompt has started. Verifying a peer can take
    /// hundreds of milliseconds, so a fixed sleep may end before the
    /// request reaches its prompt.
    fn wait_for_hung_prompt(&self) {
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
/// would raise an authorization prompt and stall the suite.
#[async_trait]
impl KeychainLister for StubAuthorizer {
    async fn list_passwords(&self) -> Result<Vec<BrokerPasswordEntry>, String> {
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
        _prompt: PassphrasePrompt,
        peer: audit::Actor,
    ) -> Result<ForeignContext, String> {
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
    /// ever dropped. Starting and dropping it are both counted.
    async fn confirm(&self, prompt: ConfirmPrompt) -> bool {
        if prompt.description.as_deref() == Some("hang") {
            self.prompts_hung.fetch_add(1, Ordering::SeqCst);
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
        prompt: vault::VaultAccessPrompt,
        peer: audit::Actor,
    ) -> Result<ForeignContext, String> {
        self.vault_prompts.lock().unwrap().push(prompt);
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
    logins: Arc<LoginIndex>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    server: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    // Rejecting a peer and serving a vault request both write audit
    // events. Held so they land in a scratch directory instead of the one
    // an audit test is counting.
    _audit_dir: TestDir,
    _dir: tempfile::TempDir,
}

impl TestBroker {
    async fn start(policy: PeerPolicy) -> Self {
        Self::start_with_scope(policy, RequestScope::Agent).await
    }

    async fn start_with_scope(policy: PeerPolicy, scope: RequestScope) -> Self {
        Self::start_with_clients(vec![Client { policy, scope }]).await
    }

    async fn start_with_clients(clients: Vec<Client>) -> Self {
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

    let response = broker
        .request(r#"{"request":"sign","key_label":"key-1","caller":"git (ssh)","data":"aGk="}"#);

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
    tokio::task::block_in_place(|| broker.authorizer.wait_for_hung_prompt());
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
    tokio::task::block_in_place(|| broker.authorizer.wait_for_hung_prompt());

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

    broker.request(r#"{"request":"sign","key_label":"key-1","caller":"git (ssh)","data":"aGk="}"#);

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

/// A keychain password listing is framed, parsed and routed to the
/// configured lister, and its entries come back on the wire.
#[tokio::test(flavor = "multi_thread")]
async fn routes_a_keychain_password_listing() {
    let broker = TestBroker::start(accepting_policy()).await;

    let response = broker.request(r#"{"request":"list_keychain_passwords","caller":"ap"}"#);

    let response: WireResponse = serde_json::from_str(&response)
        .expect("unexpected response to a keychain password listing");
    let WireResponse::KeychainPasswords { entries } = response else {
        panic!("expected a keychain password listing");
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key_id, "stub");
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

    let response = broker
        .request(r#"{"request":"delete_managed_key","label":"ssh-key-nosuchkey","caller":"ap"}"#);

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

    let response =
        broker.request(r#"{"request":"sign","key_label":"key-1","caller":"evil","data":"aGk="}"#);

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

/// The AutoFill scope refuses a request outside it. The stub lister
/// answers a keychain listing on any other socket, so `Failed` means the
/// request never reached it.
#[tokio::test(flavor = "multi_thread")]
async fn the_autofill_scope_refuses_other_requests() {
    let broker =
        TestBroker::start_with_scope(accepting_policy(), RequestScope::AutofillExtension).await;

    let response = broker.request(r#"{"request":"list_keychain_passwords","caller":"x"}"#);

    let response: WireResponse = serde_json::from_str(&response).unwrap();
    assert!(
        matches!(&response, WireResponse::Failed { message } if message.contains("may not")),
        "the autofill scope served a keychain listing",
    );
}

#[test]
fn the_autofill_scope_allows_only_autofill_requests() {
    let allowed = [
        r#"{"request":"list_logins","url":"https://example.com","frame_url":"https://example.com"}"#,
        r#"{"request":"fill_login","url":"https://example.com","frame_url":"https://example.com","record_id":"r"}"#,
        r#"{"request":"generate_totp","url":"https://example.com","frame_url":"https://example.com","record_id":"r"}"#,
        r#"{"request":"create_passkey","rp_id":"example.com","user_handle":"","user_name":"u","user_display_name":"u","client_data_hash":"","algorithms":[-7]}"#,
        r#"{"request":"assert_passkey","rp_id":"example.com","client_data_hash":""}"#,
        r#"{"request":"list_passkeys","rp_id":"example.com"}"#,
        r#"{"request":"report_unknown_passkey","rp_id":"example.com","credential_id":"AQ=="}"#,
        r#"{"request":"report_accepted_passkeys","rp_id":"example.com","user_handle":"CQ==","credential_ids":["AQ=="]}"#,
        r#"{"request":"report_passkey_name","rp_id":"example.com","user_handle":"CQ==","name":"ada"}"#,
    ];
    let refused = [
        r#"{"request":"list_identities"}"#,
        r#"{"request":"list_vault_items","vault_key":"v"}"#,
        r#"{"request":"read_vault_secret","vault_key":"v","item_key":"i","credential_key":"c"}"#,
        r#"{"request":"resolve_secrets","refs":[],"purpose":"read"}"#,
        r#"{"request":"write_vault_secret","vault_key":"v","item_key":"i","credential_key":"c","title":"t","value":"x"}"#,
        r#"{"request":"export_vaults","vault_keys":[],"dest_path":"/tmp/x","mode":{"kind":"recipient","recipient":"age1"}}"#,
        r#"{"request":"import_vaults","import_path":"/tmp/x","identity":{"kind":"passphrase","passphrase":"p"},"selection":[]}"#,
        r#"{"request":"add_external_vault","path":"/tmp/v.json"}"#,
        r#"{"request":"get_age_identity","key_id":"k"}"#,
        r#"{"request":"list_keychain_passwords"}"#,
        r#"{"request":"list_age_keys"}"#,
    ];
    for line in allowed {
        let request: WireRequest = serde_json::from_str(line).unwrap();
        assert!(RequestScope::AutofillExtension.allows(&request), "{line}");
        assert!(RequestScope::Agent.allows(&request), "{line}");
    }
    for line in refused {
        let request: WireRequest = serde_json::from_str(line).unwrap();
        assert!(!RequestScope::AutofillExtension.allows(&request), "{line}");
        assert!(RequestScope::Agent.allows(&request), "{line}");
    }
}

/// The AutoFill scope names the caller itself, so a request cannot pick
/// the name its prompt, grant, and audit event carry.
#[tokio::test(flavor = "multi_thread")]
async fn the_autofill_scope_names_its_own_caller() {
    for line in [
        r#"{"request":"list_logins","url":"https://example.com","frame_url":"https://example.com/login","caller":"Chrome"}"#,
        r#"{"request":"fill_login","url":"https://example.com","frame_url":"https://example.com/login","record_id":"r","caller":"Chrome"}"#,
        r#"{"request":"generate_totp","url":"https://example.com","frame_url":"https://example.com/login","record_id":"r","caller":"Chrome"}"#,
        r#"{"request":"assert_passkey","rp_id":"example.com","client_data_hash":"","caller":"Chrome"}"#,
    ] {
        let broker =
            TestBroker::start_with_scope(accepting_policy(), RequestScope::AutofillExtension).await;
        let response: WireResponse = serde_json::from_str(&broker.request(line)).unwrap();
        assert!(
            matches!(&response, WireResponse::Failed { message } if message == "stub authorizer"),
            "unexpected response to {line}"
        );
        let peers = broker.authorizer.peers.lock().unwrap();
        assert_eq!(peers.len(), 1, "{line}");
        assert_eq!(peers[0].caller.as_deref(), Some(AUTOFILL_CALLER), "{line}");
    }
}

/// A page the broker cannot match, and a relying party id that is not a
/// registrable domain, are refused before any prompt is raised.
#[tokio::test(flavor = "multi_thread")]
async fn refuses_unmatchable_pages_and_public_suffix_rp_ids_before_prompting() {
    for (line, expected) in [
        (
            r#"{"request":"list_logins","url":"https://example.com","frame_url":"ftp://example.com"}"#,
            "http and https",
        ),
        (
            r#"{"request":"fill_login","url":"https://example.com","frame_url":"","record_id":"r"}"#,
            "http and https",
        ),
        (
            r#"{"request":"assert_passkey","rp_id":"github.io","client_data_hash":""}"#,
            "public suffix",
        ),
        (
            r#"{"request":"assert_passkey","rp_id":"example.com","client_data_hash":"","origin":"https://evil.com"}"#,
            "not a domain of",
        ),
        (
            r#"{"request":"create_passkey","rp_id":"co.uk","user_handle":"","user_name":"u","user_display_name":"u","client_data_hash":"","algorithms":[-7]}"#,
            "public suffix",
        ),
    ] {
        let broker =
            TestBroker::start_with_scope(accepting_policy(), RequestScope::AutofillExtension).await;
        let response: WireResponse = serde_json::from_str(&broker.request(line)).unwrap();
        assert!(
            matches!(&response, WireResponse::Failed { message } if message.contains(expected)),
            "unexpected response to {line}"
        );
        assert!(broker.authorizer.peers.lock().unwrap().is_empty(), "{line}");
    }
}

const PAGE: &str = r#""url":"https://example.com","frame_url":"https://example.com/login""#;
const CHROME: &str = r#""client":{"browser":{"name":"Google Chrome","team_id":"EQHXZ8M8AV"},"extension":"chrome-extension://abc/"}"#;

async fn browser_host_broker() -> TestBroker {
    TestBroker::start_with_scope(accepting_policy(), RequestScope::BrowserHost).await
}

fn parse(line: &str) -> WireRequest {
    serde_json::from_str(line).unwrap()
}

#[test]
fn the_browser_host_scope_adds_generation_and_saving_to_the_autofill_requests() {
    let autofill = [
        format!(r#"{{"request":"list_logins",{PAGE}}}"#),
        format!(r#"{{"request":"list_logins_locked",{PAGE}}}"#),
        format!(r#"{{"request":"fill_login",{PAGE},"record_id":"r"}}"#),
        format!(r#"{{"request":"generate_totp",{PAGE},"record_id":"r"}}"#),
        r#"{"request":"assert_passkey","rp_id":"example.com","client_data_hash":""}"#.to_string(),
    ];
    let browser_only = [
        r#"{"request":"generate_password"}"#.to_string(),
        format!(r#"{{"request":"save_login",{PAGE},"password":"pw"}}"#),
        format!(r#"{{"request":"update_login_password",{PAGE},"record_id":"r","password":"pw"}}"#),
    ];
    let refused = [
        r#"{"request":"list_identities"}"#,
        r#"{"request":"read_vault_secret","vault_key":"v","item_key":"i","credential_key":"c"}"#,
        r#"{"request":"resolve_secrets","refs":[],"purpose":"read"}"#,
        r#"{"request":"write_vault_secret","vault_key":"v","item_key":"i","credential_key":"c","title":"t","value":"x"}"#,
        r#"{"request":"export_vaults","vault_keys":[],"dest_path":"/tmp/x","mode":{"kind":"recipient","recipient":"age1"}}"#,
        r#"{"request":"import_vaults","import_path":"/tmp/x","identity":{"kind":"passphrase","passphrase":"p"},"selection":[]}"#,
        r#"{"request":"add_external_vault","path":"/tmp/v.json"}"#,
        r#"{"request":"get_age_identity","key_id":"k"}"#,
        r#"{"request":"list_keychain_passwords"}"#,
        r#"{"request":"sign","key_label":"k","data":"aGk="}"#,
        r#"{"request":"get_passphrase","key_id":"k"}"#,
        r#"{"request":"report_unknown_passkey","rp_id":"example.com","credential_id":"AQ=="}"#,
        r#"{"request":"list_passkeys","rp_id":"example.com"}"#,
    ];
    for line in autofill.iter().chain(&browser_only) {
        let request = parse(line);
        assert!(RequestScope::BrowserHost.allows(&request), "{line}");
        assert!(RequestScope::Agent.allows(&request), "{line}");
    }
    for line in &autofill {
        assert!(
            RequestScope::AutofillExtension.allows(&parse(line)),
            "{line}"
        );
    }
    for line in &browser_only {
        assert!(
            !RequestScope::AutofillExtension.allows(&parse(line)),
            "{line}"
        );
    }
    for line in refused {
        let request = parse(line);
        assert!(!RequestScope::BrowserHost.allows(&request), "{line}");
        assert!(RequestScope::Agent.allows(&request), "{line}");
    }
}

/// The browser host names the caller from the browser it verified, and
/// the request's own `caller` and `requester` cannot change that.
#[tokio::test(flavor = "multi_thread")]
async fn the_browser_host_scope_names_the_verified_browser() {
    let broker = browser_host_broker().await;
    let line = format!(
        r#"{{"request":"fill_login",{PAGE},"record_id":"r","caller":"Safari","requester":"Notes",{CHROME}}}"#
    );
    broker.request(&line);

    let peers = broker.authorizer.peers.lock().unwrap();
    assert_eq!(peers[0].caller.as_deref(), Some("Google Chrome"));
    let prompts = broker.authorizer.vault_prompts.lock().unwrap();
    assert_eq!(prompts[0].caller.as_deref(), Some("Google Chrome"));
    assert_eq!(
        prompts[0].client,
        ClientIdentity::Browser {
            name: "Google Chrome".to_string(),
            team_id: "EQHXZ8M8AV".to_string(),
            extension: Some("chrome-extension://abc/".to_string()),
        }
    );
    let VaultAction::FillLogin { page, .. } = &prompts[0].action else {
        panic!("not a fill: {:?}", prompts[0].action);
    };
    assert_eq!(page.requester, None);
}

/// A host with no verified browser is "Unknown process" and is never
/// identified, so no approval is reused for it.
#[tokio::test(flavor = "multi_thread")]
async fn an_unverified_browser_host_is_unknown_and_never_identified() {
    for client in [
        r#""client":{"extension":"chrome-extension://abc/"}"#,
        r#""client":{}"#,
    ] {
        let broker = browser_host_broker().await;
        broker.request(&format!(
            r#"{{"request":"fill_login",{PAGE},"record_id":"r","caller":"Chrome",{client}}}"#
        ));
        // No client report at all.
        broker.request(&format!(
            r#"{{"request":"list_logins",{PAGE},"caller":"Chrome"}}"#
        ));

        let prompts = broker.authorizer.vault_prompts.lock().unwrap();
        assert_eq!(prompts.len(), 2);
        for prompt in prompts.iter() {
            assert_eq!(prompt.caller.as_deref(), Some(UNKNOWN_CLIENT));
            assert!(matches!(prompt.client, ClientIdentity::Unverified { .. }));
        }
    }
}

/// Only a verified browser host may report a browser. The same report
/// from `ap` or the AutoFill extension is ignored.
#[tokio::test(flavor = "multi_thread")]
async fn other_scopes_ignore_a_browser_report() {
    for scope in [RequestScope::Agent, RequestScope::AutofillExtension] {
        let broker = TestBroker::start_with_scope(accepting_policy(), scope).await;
        broker.request(&format!(
            r#"{{"request":"fill_login",{PAGE},"record_id":"r","caller":"git",{CHROME}}}"#
        ));
        let prompts = broker.authorizer.vault_prompts.lock().unwrap();
        assert_eq!(prompts[0].client, ClientIdentity::Process, "{scope:?}");
        assert_ne!(prompts[0].caller.as_deref(), Some("Google Chrome"));
    }
}

/// Only the AutoFill extension names the app a request is for. A browser
/// host and `ap` are always a browser.
#[test]
fn only_the_autofill_extension_names_a_requesting_app() {
    let app = || Some("Notes".to_string());
    assert_eq!(requester_for(RequestScope::AutofillExtension, app()), app());
    assert_eq!(requester_for(RequestScope::BrowserHost, app()), None);
    assert_eq!(requester_for(RequestScope::Agent, app()), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn locked_listing_is_refused_to_the_agent_and_an_unverified_host() {
    let line = format!(r#"{{"request":"list_logins_locked",{PAGE}}}"#);
    let verified = format!(r#"{{"request":"list_logins_locked",{PAGE},{CHROME}}}"#);
    let refused = [
        (RequestScope::Agent, verified.clone()),
        (RequestScope::BrowserHost, line.clone()),
    ];
    for (scope, line) in refused {
        let broker = TestBroker::start_with_scope(accepting_policy(), scope).await;
        broker.logins.replace(Vec::new());
        let response: WireResponse = serde_json::from_str(&broker.request(&line)).unwrap();
        assert!(
            matches!(&response, WireResponse::Failed { message } if message.contains("may not")),
            "{scope:?} listed without a prompt"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn locked_listing_answers_from_the_index_without_a_prompt() {
    use crate::secrets::vaults::autofill::AutofillItem;
    use crate::secrets::vaults::{MatchKind, Website};

    let item = |record_id: &str, site: &str| AutofillItem {
        vault_key: "personal".to_string(),
        item_key: record_id.to_string(),
        record_id: record_id.to_string(),
        title: record_id.to_string(),
        username: Some("tp".to_string()),
        password_key: "password".to_string(),
        websites: vec![Website::new(site, MatchKind::Domain)],
        has_totp: false,
        matched: None,
    };
    let verified = format!(r#"{{"request":"list_logins_locked",{PAGE},{CHROME}}}"#);
    let plain = format!(r#"{{"request":"list_logins_locked",{PAGE}}}"#);

    for (scope, line) in [
        (RequestScope::BrowserHost, verified),
        (RequestScope::AutofillExtension, plain),
    ] {
        let broker = TestBroker::start_with_scope(accepting_policy(), scope).await;

        // Nothing is indexed before the app's first unlock.
        let response: WireResponse = serde_json::from_str(&broker.request(&line)).unwrap();
        assert!(
            matches!(&response, WireResponse::LockedLogins { logins, indexed: false } if logins.is_empty()),
            "{scope:?}"
        );

        broker
            .logins
            .replace(vec![item("a", "example.com"), item("b", "other.com")]);
        let response: WireResponse = serde_json::from_str(&broker.request(&line)).unwrap();
        let WireResponse::LockedLogins { logins, indexed } = response else {
            panic!("{scope:?}: unexpected response");
        };
        assert!(indexed);
        assert_eq!(logins.len(), 1, "{scope:?} listed a login for another site");
        assert_eq!(logins[0].record_id, "a");

        assert!(broker.authorizer.vault_prompts.lock().unwrap().is_empty());
        assert!(broker.authorizer.peers.lock().unwrap().is_empty());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn passkey_listing_answers_from_the_index_without_a_prompt() {
    use super::IndexedPasskey;

    let broker =
        TestBroker::start_with_scope(accepting_policy(), RequestScope::AutofillExtension).await;
    let line = r#"{"request":"list_passkeys","rp_id":"example.com"}"#;

    // Nothing is indexed before the app's first unlock.
    let response: WireResponse = serde_json::from_str(&broker.request(line)).unwrap();
    assert!(matches!(
        &response,
        WireResponse::Passkeys { passkeys, indexed: false } if passkeys.is_empty()
    ));

    let passkey = |rp_id: &str, id: u8, user_name: &str| IndexedPasskey {
        rp_id: rp_id.to_string(),
        credential_id: vec![id],
        user_name: user_name.to_string(),
    };
    broker.logins.replace_passkeys(vec![
        passkey("example.com", 1, "wobby"),
        passkey("other.com", 2, "ada"),
        passkey("example.com", 3, "webby"),
    ]);
    let response: WireResponse = serde_json::from_str(&broker.request(line)).unwrap();
    let WireResponse::Passkeys { passkeys, indexed } = response else {
        panic!("unexpected response");
    };
    assert!(indexed);
    let found: Vec<_> = passkeys
        .iter()
        .map(|p| (p.credential_id.as_str(), p.user_name.as_str()))
        .collect();
    assert_eq!(found, [("Aw==", "webby"), ("AQ==", "wobby")]);

    assert!(broker.authorizer.vault_prompts.lock().unwrap().is_empty());
    assert!(broker.authorizer.peers.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn passkey_listing_refuses_a_public_suffix() {
    let broker =
        TestBroker::start_with_scope(accepting_policy(), RequestScope::AutofillExtension).await;
    broker.logins.replace_passkeys(Vec::new());
    let line = r#"{"request":"list_passkeys","rp_id":"github.io"}"#;
    let response: WireResponse = serde_json::from_str(&broker.request(line)).unwrap();
    assert!(
        matches!(&response, WireResponse::Failed { message } if message.contains("public suffix"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn generates_a_password_without_a_prompt() {
    let broker = browser_host_broker().await;

    let response: WireResponse =
        serde_json::from_str(&broker.request(r#"{"request":"generate_password"}"#)).unwrap();
    let WireResponse::GeneratedPassword { password } = response else {
        panic!("unexpected response");
    };
    assert_eq!(password.len(), 20);

    let response: WireResponse = serde_json::from_str(
        &broker.request(r#"{"request":"generate_password","policy":{"length":8,"symbols":false}}"#),
    )
    .unwrap();
    let WireResponse::GeneratedPassword { password } = response else {
        panic!("unexpected response");
    };
    assert_eq!(password.len(), 8);
    assert!(password.chars().all(|c| c.is_ascii_alphanumeric()));

    let response: WireResponse = serde_json::from_str(
        &broker.request(r#"{"request":"generate_password","policy":{"length":1}}"#),
    )
    .unwrap();
    assert!(matches!(response, WireResponse::Failed { .. }));

    assert!(broker.authorizer.peers.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_autofill_scope_cannot_generate_or_save() {
    let broker =
        TestBroker::start_with_scope(accepting_policy(), RequestScope::AutofillExtension).await;
    for line in [
        r#"{"request":"generate_password"}"#.to_string(),
        format!(r#"{{"request":"save_login",{PAGE},"password":"pw"}}"#),
        format!(r#"{{"request":"update_login_password",{PAGE},"record_id":"r","password":"pw"}}"#),
    ] {
        let response: WireResponse = serde_json::from_str(&broker.request(&line)).unwrap();
        assert!(
            matches!(&response, WireResponse::Failed { message } if message.contains("may not")),
            "{line}"
        );
    }
    assert!(broker.authorizer.vault_prompts.lock().unwrap().is_empty());
}

/// A registration prompt carries the logins the index holds for the
/// relying party, and suggests the one with the account's username.
#[tokio::test(flavor = "multi_thread")]
async fn a_registration_prompt_carries_the_placement_choices() {
    use crate::secrets::vaults::{LoginPlace, MatchKind, Website};

    let broker = browser_host_broker().await;
    let place = |item: &str, user: &str, site: &str| LoginPlace {
        vault_key: "work".to_string(),
        item_key: item.to_string(),
        title: item.to_string(),
        username: Some(user.to_string()),
        websites: vec![Website::new(site, MatchKind::Domain)],
    };
    broker.logins.replace_places(vec![
        place("example", "ada", "example.com"),
        place("other", "ada", "other.com"),
    ]);
    broker.request(
        r#"{"request":"create_passkey","rp_id":"example.com","user_handle":"","user_name":"ada","user_display_name":"ada","client_data_hash":"","algorithms":[-7]}"#,
    );

    let prompts = broker.authorizer.vault_prompts.lock().unwrap();
    assert_eq!(prompts.len(), 1);
    let VaultAction::CreatePasskey {
        rp_id,
        user_name,
        choices,
    } = &prompts[0].action
    else {
        panic!("expected a registration prompt");
    };
    assert_eq!((rp_id.as_str(), user_name.as_str()), ("example.com", "ada"));
    assert_eq!(choices.logins.len(), 1);
    assert_eq!(choices.logins[0].item_key, "example");
    assert_eq!(choices.suggested, Some(0));
    assert_eq!(choices.default_vault, "work");
    assert_eq!(prompts[0].vault_key, "work");
}

/// A save names the site and the account in its prompt, and always
/// reaches the prompt. The password is not in what the app sees.
#[tokio::test(flavor = "multi_thread")]
async fn saving_a_login_always_prompts_and_keeps_the_password_out_of_it() {
    let broker = browser_host_broker().await;
    broker.request(&format!(
        r#"{{"request":"save_login",{PAGE},"username":"tp@example.com","password":"s3cret",{CHROME}}}"#
    ));
    broker.request(&format!(
        r#"{{"request":"update_login_password",{PAGE},"record_id":"r","password":"s3cret","account":"tp",{CHROME}}}"#
    ));

    let prompts = broker.authorizer.vault_prompts.lock().unwrap();
    assert_eq!(prompts.len(), 2);
    assert!(
        matches!(&prompts[0].action, VaultAction::SaveLogin { page, username }
            if page.host == "example.com" && username.as_deref() == Some("tp@example.com"))
    );
    assert!(
        matches!(&prompts[1].action, VaultAction::UpdateLoginPassword { page, record_id, account }
            if page.host == "example.com" && record_id == "r" && account.as_deref() == Some("tp"))
    );
    for prompt in prompts.iter() {
        assert_eq!(prompt.caller.as_deref(), Some("Google Chrome"));
        assert!(!format!("{prompt:?}").contains("s3cret"));
    }
}

/// Nothing without a password or an http(s) page reaches the prompt.
#[tokio::test(flavor = "multi_thread")]
async fn refuses_a_save_with_no_password_or_page_before_prompting() {
    let broker = browser_host_broker().await;
    for line in [
        format!(r#"{{"request":"save_login",{PAGE},"password":""}}"#),
        format!(r#"{{"request":"update_login_password",{PAGE},"record_id":"r","password":""}}"#),
        r#"{"request":"save_login","url":"https://example.com","frame_url":"ftp://example.com","password":"pw"}"#.to_string(),
    ] {
        let response: WireResponse = serde_json::from_str(&broker.request(&line)).unwrap();
        assert!(matches!(response, WireResponse::Failed { .. }), "{line}");
    }
    assert!(broker.authorizer.vault_prompts.lock().unwrap().is_empty());
}

/// A peer is matched against each client's policy in turn, and the first
/// it satisfies gives the scope.
#[tokio::test(flavor = "multi_thread")]
async fn the_policy_a_peer_satisfies_gives_its_scope() {
    let broker = TestBroker::start_with_clients(vec![
        Client {
            policy: rejecting_policy(),
            scope: RequestScope::Agent,
        },
        Client {
            policy: accepting_policy(),
            scope: RequestScope::BrowserHost,
        },
    ])
    .await;

    let response: WireResponse =
        serde_json::from_str(&broker.request(r#"{"request":"list_keychain_passwords"}"#)).unwrap();
    assert!(
        matches!(&response, WireResponse::Failed { message } if message.contains("may not")),
        "the browser host scope served a keychain listing"
    );
    let response: WireResponse =
        serde_json::from_str(&broker.request(r#"{"request":"generate_password"}"#)).unwrap();
    assert!(matches!(response, WireResponse::GeneratedPassword { .. }));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_no_client_accepts_is_refused() {
    let broker = TestBroker::start_with_clients(vec![
        Client {
            policy: rejecting_policy(),
            scope: RequestScope::Agent,
        },
        Client {
            policy: rejecting_policy(),
            scope: RequestScope::BrowserHost,
        },
    ])
    .await;
    assert!(
        broker
            .request(r#"{"request":"generate_password"}"#)
            .is_empty()
    );
}

/// A Mach service with a name no other test or process uses.
fn start_mach_service(policy: PeerPolicy) -> (String, mach::MachService) {
    let (name, service, _) = start_mach_service_with(policy, RequestScope::Agent);
    (name, service)
}

fn start_mach_service_with(
    policy: PeerPolicy,
    scope: RequestScope,
) -> (String, mach::MachService, Arc<StubAuthorizer>) {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let name = format!(
        "com.breakfastlabs.frittata.test.{}.{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let authorizer = Arc::new(StubAuthorizer::default());
    let service =
        mach::MachService::start(&name, policy, scope, stub_authorizers(&authorizer)).unwrap();
    (name, service, authorizer)
}

fn stub_authorizers(authorizer: &Arc<StubAuthorizer>) -> Authorizers {
    Authorizers {
        sign: authorizer.clone(),
        passphrase: authorizer.clone(),
        vault: authorizer.clone(),
        keychain: authorizer.clone(),
        logins: Arc::new(LoginIndex::default()),
        vaults: empty_vaults(),
    }
}

/// A vault store with no vaults, so no test reads the developer's own vaults.
fn empty_vaults() -> crate::secrets::vaults::VaultCatalog {
    crate::secrets::vaults::VaultCatalog::with_unlocker(
        PathBuf::from("/nonexistent/vaults"),
        crate::secrets::vaults::storage::txn::VaultWriter::isolated("/nonexistent/data"),
        Default::default(),
        Arc::new(crate::secrets::vaults::storage::test_unlocker::KeyUnlocker::default()),
    )
}

/// A request over the Mach service is verified from its audit token,
/// served, and answered.
#[tokio::test(flavor = "multi_thread")]
async fn serves_a_request_over_the_mach_service() {
    let _audit_dir = test_dir();
    let (name, service) = start_mach_service(accepting_policy());

    let response = tokio::task::spawn_blocking(move || {
        mach::send_test_request(&name, br#"{"request":"list_keychain_passwords"}"#)
    })
    .await
    .unwrap()
    .expect("the Mach service dropped the request");

    let response: WireResponse = serde_json::from_slice(&response).unwrap();
    assert!(matches!(response, WireResponse::KeychainPasswords { .. }));
    service.stop();
}

/// A sender that fails the policy gets no reply.
#[tokio::test(flavor = "multi_thread")]
async fn drops_a_mach_request_from_a_rejected_sender() {
    let _audit_dir = test_dir();
    let (name, service) = start_mach_service(rejecting_policy());

    let response = tokio::task::spawn_blocking(move || {
        mach::send_test_request(&name, br#"{"request":"list_keychain_passwords"}"#)
    })
    .await
    .unwrap();

    assert!(
        response.is_none(),
        "the Mach service answered a rejected sender"
    );
    service.stop();
}

/// A message that is not a well-formed request is dropped without a
/// reply, and the service goes on serving.
#[tokio::test(flavor = "multi_thread")]
async fn drops_malformed_mach_messages() {
    let _audit_dir = test_dir();
    let (name, service) = start_mach_service(accepting_policy());
    let valid = br#"{"request":"list_keychain_passwords"}"#;
    let oversize = vec![b' '; (1 << 20) + 1];

    let response = tokio::task::spawn_blocking(move || {
        let malformed = [
            TestRequest {
                id: 0x1234,
                ..TestRequest::new(valid)
            },
            TestRequest {
                complex: false,
                ..TestRequest::new(valid)
            },
            TestRequest::new(&oversize),
        ];
        for request in &malformed {
            let exchange = mach::send_test_exchange(&name, request).unwrap();
            assert!(exchange.receive(5000).is_none());
        }
        // Without a reply port there is no one to answer or notify.
        let request = TestRequest {
            reply_port: false,
            ..TestRequest::new(valid)
        };
        mach::send_test_exchange(&name, &request).unwrap();

        mach::send_test_request(&name, valid)
    })
    .await
    .unwrap()
    .expect("the Mach service stopped serving after a malformed message");

    let response: WireResponse = serde_json::from_slice(&response).unwrap();
    assert!(matches!(response, WireResponse::KeychainPasswords { .. }));
    service.stop();
}

/// A body that is not a request is dropped without a reply.
#[tokio::test(flavor = "multi_thread")]
async fn drops_a_mach_request_with_an_unreadable_body() {
    let _audit_dir = test_dir();
    let (name, service) = start_mach_service(accepting_policy());

    let (garbage, valid) = tokio::task::spawn_blocking(move || {
        (
            mach::send_test_request(&name, b"not json"),
            mach::send_test_request(&name, br#"{"request":"list_keychain_passwords"}"#),
        )
    })
    .await
    .unwrap();

    assert!(garbage.is_none(), "the Mach service answered garbage");
    assert!(valid.is_some());
    service.stop();
}

/// A request outside the service's scope is refused with an answer.
#[tokio::test(flavor = "multi_thread")]
async fn refuses_a_mach_request_outside_the_scope() {
    let _audit_dir = test_dir();
    let (name, service, authorizer) =
        start_mach_service_with(accepting_policy(), RequestScope::AutofillExtension);

    let response = tokio::task::spawn_blocking(move || {
        mach::send_test_request(&name, br#"{"request":"list_identities"}"#)
    })
    .await
    .unwrap()
    .expect("the Mach service dropped a refused request");

    let response: WireResponse = serde_json::from_slice(&response).unwrap();
    assert!(
        matches!(&response, WireResponse::Failed { message } if message.contains("may not")),
        "the Mach service did not refuse the request"
    );
    assert!(authorizer.prompts.lock().unwrap().is_empty());
    service.stop();
}

/// A client that goes away while its prompt is waiting gets the prompt
/// dropped, and the service moves on to the next request.
#[tokio::test(flavor = "multi_thread")]
async fn drops_the_prompt_of_a_disconnected_mach_client() {
    let _audit_dir = test_dir();
    let (name, service, authorizer) =
        start_mach_service_with(accepting_policy(), RequestScope::Agent);

    let waiter = authorizer.clone();
    let response = tokio::task::spawn_blocking(move || {
        let hanging = mach::send_test_exchange(
            &name,
            &TestRequest::new(br#"{"request":"confirm","description":"hang"}"#),
        )
        .unwrap();
        waiter.wait_for_hung_prompt();
        drop(hanging);

        mach::send_test_request(&name, br#"{"request":"confirm","description":"ok"}"#)
    })
    .await
    .unwrap()
    .expect("the Mach service stayed stuck on the abandoned prompt");

    let response: WireResponse = serde_json::from_slice(&response).unwrap();
    assert!(matches!(response, WireResponse::Confirmed { ok: true }));
    assert_eq!(authorizer.prompts_dropped.load(Ordering::SeqCst), 1);
    service.stop();
}

/// A client that gives up while its request waits behind another is never
/// served: its request reaches no authorizer.
#[tokio::test(flavor = "multi_thread")]
async fn skips_a_mach_client_that_went_away_while_queued() {
    let _audit_dir = test_dir();
    let (name, service, authorizer) =
        start_mach_service_with(accepting_policy(), RequestScope::Agent);

    let waiter = authorizer.clone();
    let response = tokio::task::spawn_blocking(move || {
        // Holds the service on a prompt nobody answers.
        let busy = mach::send_test_exchange(
            &name,
            &TestRequest::new(br#"{"request":"confirm","description":"hang"}"#),
        )
        .unwrap();
        waiter.wait_for_hung_prompt();

        // Queues behind it, then gives up.
        let queued = mach::send_test_exchange(
            &name,
            &TestRequest::new(br#"{"request":"sign","key_label":"key-1","data":"aGk="}"#),
        )
        .unwrap();
        drop(queued);
        drop(busy);

        mach::send_test_request(&name, br#"{"request":"confirm","description":"ok"}"#)
    })
    .await
    .unwrap()
    .expect("the Mach service stayed stuck on the abandoned prompt");

    let response: WireResponse = serde_json::from_slice(&response).unwrap();
    assert!(matches!(response, WireResponse::Confirmed { ok: true }));
    assert!(authorizer.prompts.lock().unwrap().is_empty());
    assert_eq!(authorizer.ended.load(Ordering::SeqCst), 0);
    service.stop();
}

/// A second app registering the same name fails and leaves the first
/// service serving.
#[tokio::test(flavor = "multi_thread")]
async fn refuses_a_name_that_is_already_registered() {
    let _audit_dir = test_dir();
    let (name, service) = start_mach_service(accepting_policy());

    let authorizer = Arc::new(StubAuthorizer::default());
    let second = mach::MachService::start(
        &name,
        accepting_policy(),
        RequestScope::Agent,
        stub_authorizers(&authorizer),
    );
    assert!(second.is_err(), "a second service took a registered name");

    let response = tokio::task::spawn_blocking(move || {
        mach::send_test_request(&name, br#"{"request":"list_keychain_passwords"}"#)
    })
    .await
    .unwrap();
    assert!(response.is_some());
    service.stop();
}

/// Stopping the service frees its name for the next one.
#[tokio::test(flavor = "multi_thread")]
async fn frees_the_name_when_stopped() {
    let _audit_dir = test_dir();
    let (name, service) = start_mach_service(accepting_policy());
    service.stop();

    // The receive thread exits within its poll timeout and then destroys
    // the port.
    let authorizer = Arc::new(StubAuthorizer::default());
    let mut restarted = None;
    for _ in 0..100 {
        match mach::MachService::start(
            &name,
            accepting_policy(),
            RequestScope::Agent,
            stub_authorizers(&authorizer),
        ) {
            Ok(service) => {
                restarted = Some(service);
                break;
            },
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    restarted
        .expect("the name was still registered after the service stopped")
        .stop();
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
        vec![Client {
            policy: accepting_policy(),
            scope: RequestScope::Agent,
        }],
        Authorizers {
            sign: authorizer.clone(),
            passphrase: authorizer.clone(),
            vault: authorizer.clone(),
            keychain: authorizer,
            logins: Arc::new(LoginIndex::default()),
            vaults: empty_vaults(),
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
