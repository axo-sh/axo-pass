use std::fs;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::broker::{TestBroker, accepting_policy, rejecting_policy, wait_for_socket};
use super::support::{StubAuthorizer, empty_vaults};
use crate::audit;
use crate::core::app_broker::access::{Client, RequestScope, agent_policy};
use crate::core::app_broker::client::wait_for_response;
use crate::core::app_broker::in_flight::InFlightRequest;
use crate::core::app_broker::server::serve_on;
use crate::core::app_broker::wire::WireResponse;
use crate::core::app_broker::{Authorizers, BrokerError, LoginIndex};
use crate::core::provenance::PeerIdentity;

#[tokio::test(flavor = "multi_thread")]
async fn serves_request_from_accepted_peer() {
    let broker = TestBroker::start(accepting_policy()).await;

    let response = broker.request_parsed(
        r#"{"request":"sign_with_secure_enclave_key","key_label":"key-1","caller":"git (ssh)","data":"aGk="}"#,
    );

    // The stub declines, so the request is answered rather than signed.
    // Reaching the stub at all means the peer was accepted.
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
async fn abandoning_dismisses_prompt_and_waits_for_it() {
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
fn stops_waiting_when_requester_disconnects() {
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
fn keeps_waiting_when_requester_sends_data() {
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
async fn drops_prompt_of_disconnected_client() {
    let broker = TestBroker::start(accepting_policy()).await;

    let stream = std::os::unix::net::UnixStream::connect(&broker.socket_path).unwrap();
    (&stream)
        .write_all(b"{\"request\":\"confirm\",\"description\":\"hang\"}\n")
        .unwrap();
    tokio::task::block_in_place(|| broker.authorizer.wait_for_hung_prompt());
    drop(stream);

    // Times out after five seconds if the broker is still stuck on the
    // first prompt.
    let response = broker.request_parsed(r#"{"request":"confirm","description":"ok"}"#);
    assert!(matches!(response, WireResponse::Confirmed { ok: true }));
    assert_eq!(broker.authorizer.prompts_dropped.load(Ordering::SeqCst), 1);
}

/// A client that gives up while its connection waits behind another is
/// never served: its request reaches no authorizer.
#[tokio::test(flavor = "multi_thread")]
async fn skips_client_that_disconnected_while_queued() {
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
        .write_all(
            b"{\"request\":\"sign_with_secure_enclave_key\",\"key_label\":\"key-1\",\"data\":\"aGk=\"}\n",
        )
        .unwrap();
    drop(queued);
    drop(busy);

    let response = broker.request_parsed(r#"{"request":"confirm","description":"ok"}"#);
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
async fn hands_verified_peer_to_authorizer() {
    let broker = TestBroker::start(accepting_policy()).await;

    broker.request(r#"{"request":"sign_with_secure_enclave_key","key_label":"key-1","caller":"git (ssh)","data":"aGk="}"#);

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
async fn names_peer_when_no_caller_delegated() {
    let broker = TestBroker::start(accepting_policy()).await;

    broker
        .request(r#"{"request":"sign_with_secure_enclave_key","key_label":"key-1","data":"aGk="}"#);

    let peers = broker.authorizer.peers.lock().unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].pid, Some(std::process::id()));
}

/// A delegated caller chain reaches the prompt verbatim, so the app can let
/// the user expand it.
#[tokio::test(flavor = "multi_thread")]
async fn delegates_caller_chain_to_prompt() {
    let broker = TestBroker::start(accepting_policy()).await;

    broker.request(
        r#"{"request":"sign_with_secure_enclave_key","key_label":"key-1","caller":"git (ssh)","caller_chain":[{"command":"git","executable":"/usr/bin/git","pid":123,"bundle_id":null,"team_id":null},{"command":"zsh","executable":"/bin/zsh","pid":42,"bundle_id":null,"team_id":null}],"data":"aGk="}"#,
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
async fn falls_back_to_peer_chain_for_prompt() {
    let broker = TestBroker::start(accepting_policy()).await;

    broker
        .request(r#"{"request":"sign_with_secure_enclave_key","key_label":"key-1","data":"aGk="}"#);

    let prompts = broker.authorizer.prompts.lock().unwrap();
    assert_eq!(prompts.len(), 1);
    assert!(
        !prompts[0].caller_chain.is_empty(),
        "peer chain not resolved for the prompt"
    );
}

/// A rejected peer is hung up on and never reaches the authorizer. Listing is
/// gated on the same check as signing, so a rejected peer cannot read the
/// public keys, the saved passwords, an age identity, or a passphrase either.
#[tokio::test(flavor = "multi_thread")]
async fn hangs_up_on_rejected_peer() {
    type Untouched = fn(&TestBroker);
    let cases: [(&str, &str, Untouched); 5] = [
        (
            "listing keychain passwords",
            r#"{"request":"list_keychain_passwords","caller":"evil"}"#,
            |_| {},
        ),
        (
            "asking for age identity",
            r#"{"request":"get_age_identity","key_id":"demo","caller":"evil"}"#,
            |broker| assert!(broker.authorizer.peers.lock().unwrap().is_empty()),
        ),
        (
            "asking for passphrase",
            r#"{"request":"get_passphrase","key_id":null,"description":null,"prompt":null,"error_message":null,"caller":"evil"}"#,
            |broker| {
                assert!(
                    broker
                        .authorizer
                        .passphrase_prompts
                        .lock()
                        .unwrap()
                        .is_empty()
                );
            },
        ),
        (
            "signing",
            r#"{"request":"sign_with_secure_enclave_key","key_label":"key-1","caller":"evil","data":"aGk="}"#,
            |broker| assert!(broker.authorizer.prompts.lock().unwrap().is_empty()),
        ),
        (
            "listing identities",
            r#"{"request":"list_identities"}"#,
            |_| {},
        ),
    ];
    for (case, request, untouched) in cases {
        let broker = TestBroker::start(rejecting_policy()).await;

        let response = broker.request(request);

        assert!(
            response.is_empty(),
            "broker answered a rejected peer {case}"
        );
        untouched(&broker);
    }
}

/// A peer is matched against each client's policy in turn, and the first
/// it satisfies gives the scope.
#[tokio::test(flavor = "multi_thread")]
async fn policy_peer_satisfies_gives_its_scope() {
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

    let response = broker.request_parsed(r#"{"request":"list_keychain_passwords"}"#);
    assert!(
        matches!(&response, WireResponse::Failed { message } if message.contains("may not")),
        "the browser host scope served a keychain listing"
    );
    let response = broker.request_parsed(r#"{"request":"generate_password"}"#);
    assert!(matches!(response, WireResponse::GeneratedPassword { .. }));
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_no_client_accepts_refused() {
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

/// A socket left behind by a crashed app must not keep the broker offline.
#[tokio::test(flavor = "multi_thread")]
async fn replaces_stale_socket() {
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
fn agent_policy_rejects_this_process() {
    let policy = agent_policy();
    let (ours, _theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    assert!(
        PeerIdentity::verify(ours.as_raw_fd(), &policy).is_err(),
        "the agent policy accepted the test binary"
    );
}
