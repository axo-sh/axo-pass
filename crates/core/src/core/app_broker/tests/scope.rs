use super::support::{CHROME, PAGE, TestBroker, accepting_policy, browser_host_broker};
use crate::core::app_broker::access::{
    AUTOFILL_CALLER, RequestScope, UNKNOWN_CLIENT, requester_for,
};
use crate::core::app_broker::wire::{WireRequest, WireResponse};
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

#[test]
fn autofill_scope_allows_only_autofill_requests() {
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

fn parse(line: &str) -> WireRequest {
    serde_json::from_str(line).unwrap()
}

#[test]
fn browser_host_scope_extends_requests() {
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

/// Only the AutoFill extension names the app a request is for. A browser
/// host and `ap` are always a browser.
#[test]
fn only_autofill_extension_names_requesting_app() {
    let app = || Some("Notes".to_string());
    assert_eq!(requester_for(RequestScope::AutofillExtension, app()), app());
    assert_eq!(requester_for(RequestScope::BrowserHost, app()), None);
    assert_eq!(requester_for(RequestScope::Agent, app()), None);
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
