//! Request scope and cross-site tests through a live broker.

use super::broker::{CHROME, TestBroker, accepting_policy, browser_host_broker};
use super::support::PAGE;
use crate::core::app_broker::access::{AUTOFILL_CALLER, RequestScope, UNKNOWN_CLIENT};
use crate::core::app_broker::wire::WireResponse;
use crate::core::app_broker::{ClientIdentity, VaultAction};

/// The AutoFill scope refuses a request outside it. The stub lister
/// answers a keychain listing on any other socket, so `Failed` means the
/// request never reached it.
#[tokio::test(flavor = "multi_thread")]
async fn autofill_scope_refuses_other_requests() {
    let broker =
        TestBroker::start_with_scope(accepting_policy(), RequestScope::AutofillExtension).await;

    let response = broker.request_parsed(r#"{"request":"list_keychain_passwords","caller":"x"}"#);

    assert!(
        matches!(&response, WireResponse::Failed { message } if message.contains("may not")),
        "the autofill scope served a keychain listing",
    );
}

/// The AutoFill scope names the caller itself, so a request cannot pick
/// the name its prompt, grant, and audit event carry.
#[tokio::test(flavor = "multi_thread")]
async fn autofill_scope_names_its_own_caller() {
    for line in [
        r#"{"request":"list_logins","url":"https://example.com","frame_url":"https://example.com/login","caller":"Chrome"}"#,
        r#"{"request":"fill_login","url":"https://example.com","frame_url":"https://example.com/login","record_id":"r","caller":"Chrome"}"#,
        r#"{"request":"generate_totp","url":"https://example.com","frame_url":"https://example.com/login","record_id":"r","caller":"Chrome"}"#,
        r#"{"request":"assert_passkey","rp_id":"example.com","client_data_hash":"","caller":"Chrome"}"#,
    ] {
        let broker =
            TestBroker::start_with_scope(accepting_policy(), RequestScope::AutofillExtension).await;
        let response: WireResponse = broker.request_parsed(line);
        assert!(
            matches!(&response, WireResponse::Failed { message } if message == "stub authorizer"),
            "unexpected response to {line}"
        );
        let peers = broker.authorizer.peers.lock().unwrap();
        assert_eq!(peers.len(), 1, "{line}");
        assert_eq!(peers[0].caller.as_deref(), Some(AUTOFILL_CALLER), "{line}");
    }
}

/// The browser host names the caller from the browser it verified, and
/// the request's own `caller` and `requester` cannot change that.
#[tokio::test(flavor = "multi_thread")]
async fn browser_host_scope_names_verified_browser() {
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
async fn unverified_browser_host_is_unknown_and_never_identified() {
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
async fn other_scopes_ignore_browser_report() {
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

#[tokio::test(flavor = "multi_thread")]
async fn autofill_scope_cannot_generate_or_save() {
    let broker =
        TestBroker::start_with_scope(accepting_policy(), RequestScope::AutofillExtension).await;
    for line in [
        r#"{"request":"generate_password"}"#.to_string(),
        format!(r#"{{"request":"save_login",{PAGE},"password":"pw"}}"#),
        format!(r#"{{"request":"update_login_password",{PAGE},"record_id":"r","password":"pw"}}"#),
    ] {
        let response: WireResponse = broker.request_parsed(&line);
        assert!(
            matches!(&response, WireResponse::Failed { message } if message.contains("may not")),
            "{line}"
        );
    }
    assert!(broker.authorizer.vault_prompts.lock().unwrap().is_empty());
}

/// A fill in a cross-site frame reaches the prompt, except a pick from "All
/// logins", which is refused before any prompt with both hosts named.
#[tokio::test(flavor = "multi_thread")]
async fn cross_site_unmatched_fill_refused_before_prompt() {
    let page = r#""url":"https://icloud.com","frame_url":"https://idmsa.apple.com/signin""#;
    let broker = browser_host_broker().await;

    let line =
        format!(r#"{{"request":"fill_login",{page},"record_id":"r","unmatched":true,{CHROME}}}"#);
    let response: WireResponse = broker.request_parsed(&line);
    let WireResponse::Failed { message } = response else {
        panic!("an unmatched cross-site fill was not refused");
    };
    assert!(
        message.contains("idmsa.apple.com") && message.contains("icloud.com"),
        "{message}"
    );
    assert!(broker.authorizer.vault_prompts.lock().unwrap().is_empty());

    for request in [
        r#""request":"fill_login","record_id":"r""#,
        r#""request":"generate_totp","record_id":"r""#,
    ] {
        let line = format!(r#"{{{request},{page},{CHROME}}}"#);
        let _: WireResponse = broker.request_parsed(&line);
    }
    let prompts = broker.authorizer.vault_prompts.lock().unwrap();
    assert_eq!(prompts.len(), 2);
    for prompt in prompts.iter() {
        assert!(!prompt.may_reuse_approval(), "{prompt:?}");
    }
}
