use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::support::{StubAuthorizer, accepting_policy, empty_vaults, rejecting_policy};
use crate::audit::test_support::test_dir;
use crate::core::app_broker::access::RequestScope;
use crate::core::app_broker::mach::{self, TestRequest};
use crate::core::app_broker::wire::WireResponse;
use crate::core::app_broker::{Authorizers, LoginIndex};
use crate::core::provenance::PeerPolicy;

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

/// A request over the Mach service is verified from its audit token,
/// served, and answered.
#[tokio::test(flavor = "multi_thread")]
async fn serves_request_over_mach_service() {
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
async fn drops_mach_request_from_rejected_sender() {
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
async fn drops_mach_request_with_unreadable_body() {
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
async fn refuses_mach_request_outside_scope() {
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
async fn drops_prompt_of_disconnected_mach_client() {
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
async fn skips_mach_client_that_went_away_while_queued() {
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
async fn refuses_name_that_is_already_registered() {
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
async fn frees_name_when_stopped() {
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
