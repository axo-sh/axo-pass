use std::sync::atomic::Ordering;

use super::broker::{TestBroker, accepting_policy};
use super::support::STUB_PASSPHRASE;
use crate::core::app_broker::PassphraseKind;
use crate::core::app_broker::access::RequestScope;
use crate::core::app_broker::wire::{WireResponse, b64_decode_raw};

/// A confirm-on-use request reaches the sign authorizer, worded for a key
/// the agent holds rather than a managed one.
#[tokio::test(flavor = "multi_thread")]
async fn routes_key_use_authorization_to_sign_authorizer() {
    let broker = TestBroker::start(accepting_policy()).await;

    let response = broker.request_parsed(
        r#"{"request":"authorize_key_use","fingerprint":"SHA256:abc","comment":"work laptop","caller":"git (ssh)"}"#,
    );

    // The stub declines to hand back a context, so the request is answered
    // rather than confirmed. Reaching the stub means the peer was accepted
    // and the request routed.
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
async fn collects_passphrase_for_key_with_nothing_saved() {
    let broker = TestBroker::start(accepting_policy()).await;

    let response = broker.request_parsed(
        r#"{"request":"get_passphrase","key_id":null,"description":"Enter passphrase","prompt":null,"error_message":null,"caller":"git (gpg)"}"#,
    );

    let WireResponse::Passphrase { passphrase } = response else {
        panic!("unexpected response to a passphrase request");
    };
    assert_eq!(
        b64_decode_raw(passphrase).unwrap(),
        STUB_PASSPHRASE.as_bytes()
    );

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

    let response = broker.request_parsed(r#"{"request":"confirm","description":"ok?"}"#);
    assert!(matches!(response, WireResponse::Confirmed { ok: true }));

    let response = broker.request_parsed(r#"{"request":"message","description":"hi"}"#);
    assert!(matches!(response, WireResponse::Acknowledged));
}

/// A batch resolve reaches the vault authorizer, carrying the delegated
/// caller and spanning whatever vaults its refs name.
#[tokio::test(flavor = "multi_thread")]
async fn routes_batch_resolve_to_vault_authorizer() {
    let broker = TestBroker::start(accepting_policy()).await;

    let response = broker.request_parsed(
        r#"{"request":"resolve_secrets","purpose":"exec","caller":"git","refs":[{"vault_key":"v1","item_key":"i1","credential_key":"c1"},{"vault_key":"v2","item_key":"i2","credential_key":"c2"}]}"#,
    );

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
async fn routes_vault_management_to_vault_authorizer() {
    for line in [
        r#"{"request":"export_vaults","vault_keys":["v1"],"dest_path":"/tmp/x.axovault","mode":{"kind":"passphrase","passphrase":"pw","work_factor":18},"caller":"zsh"}"#,
        r#"{"request":"import_vaults","import_path":"/tmp/x.axovault","identity":{"kind":"passphrase","passphrase":"pw"},"selection":[["00000000-0000-0000-0000-000000000000","v2"]],"caller":"zsh"}"#,
        r#"{"request":"add_external_vault","path":"/tmp/v.json","caller":"zsh"}"#,
    ] {
        let broker = TestBroker::start(accepting_policy()).await;
        let response: WireResponse = broker.request_parsed(line);
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
async fn answers_age_identity_request_for_unknown_key() {
    let broker = TestBroker::start(accepting_policy()).await;

    let response = broker
        .request_parsed(r#"{"request":"get_age_identity","key_id":"nosuchkey","caller":"git"}"#);

    assert!(
        matches!(&response, WireResponse::Failed { message } if message.contains("nosuchkey")),
        "unexpected response to an unknown age key",
    );
    assert!(broker.authorizer.peers.lock().unwrap().is_empty());
}

/// A keychain password listing is framed, parsed and routed to the
/// configured lister, and its entries come back on the wire.
#[tokio::test(flavor = "multi_thread")]
async fn routes_keychain_password_listing() {
    let broker = TestBroker::start(accepting_policy()).await;

    let response = broker.request(r#"{"request":"list_keychain_passwords","caller":"ap"}"#);

    let response: WireResponse = serde_json::from_str(&response)
        .expect("unexpected response to a keychain password listing");
    let WireResponse::KeychainPasswords { entries } = response else {
        panic!("expected a keychain password listing");
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key_id, "stub");
    // The app is unlocked, so the listing does not raise a prompt.
    assert!(
        broker
            .authorizer
            .passphrase_kinds
            .lock()
            .unwrap()
            .is_empty()
    );
}

/// If the app is locked, a keychain password listing asks the app for a
/// prompt instead of reading on the shared context.
#[tokio::test(flavor = "multi_thread")]
async fn locked_keychain_listing_prompts() {
    let broker = TestBroker::start(accepting_policy()).await;
    broker.authorizer.locked.store(true, Ordering::SeqCst);

    let response = broker.request_parsed(r#"{"request":"list_keychain_passwords","caller":"ap"}"#);

    // The stub declines to hand back a context, so the listing fails with its
    // message.
    assert!(
        matches!(&response, WireResponse::Failed { message } if message == "stub authorizer"),
        "unexpected response to a locked keychain listing"
    );
    assert_eq!(
        *broker.authorizer.passphrase_kinds.lock().unwrap(),
        vec![PassphraseKind::KeychainList]
    );
    assert_eq!(broker.authorizer.ended.load(Ordering::SeqCst), 1);
}

/// Deleting a managed key that does not exist answers `Failed` rather than
/// panicking.
#[tokio::test(flavor = "multi_thread")]
async fn answers_managed_key_deletion_for_unknown_label() {
    let broker = TestBroker::start(accepting_policy()).await;

    let response = broker.request_parsed(
        r#"{"request":"delete_managed_key","label":"ssh-key-nosuchkey","caller":"ap"}"#,
    );

    assert!(
        matches!(response, WireResponse::Failed { .. }),
        "unexpected response to an unknown managed key deletion"
    );
}

/// The settings request is answered without a prompt. The test binary has no
/// keychain access group, so the settings are the defaults.
#[tokio::test(flavor = "multi_thread")]
async fn answers_protected_settings_request() {
    let broker = TestBroker::start(accepting_policy()).await;

    let response = broker.request_parsed(r#"{"request":"get_protected_settings"}"#);

    let WireResponse::ProtectedSettings { settings } = response else {
        panic!("unexpected response to a settings request");
    };
    assert!(!settings.audit_include_details);
    assert!(
        broker
            .authorizer
            .passphrase_kinds
            .lock()
            .unwrap()
            .is_empty()
    );
}

/// Only `ap` reads the settings. The AutoFill extension and the browser host
/// are refused.
#[tokio::test(flavor = "multi_thread")]
async fn protected_settings_refused_to_extension_and_browser_host() {
    for scope in [RequestScope::AutofillExtension, RequestScope::BrowserHost] {
        let broker = TestBroker::start_with_scope(accepting_policy(), scope).await;

        let response = broker.request_parsed(r#"{"request":"get_protected_settings"}"#);

        assert!(
            matches!(&response, WireResponse::Failed { message } if message.contains("may not")),
            "{scope:?} read the settings"
        );
    }
}
