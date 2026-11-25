use super::support::PAGE;
use crate::core::app_broker::access::{RequestScope, requester_for};
use crate::core::app_broker::wire::WireRequest;

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
        r#"{"request":"load_vault_key","fingerprint":"SHA256:x"}"#,
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
        r#"{"request":"sign_with_secure_enclave_key","key_label":"k","data":"aGk="}"#,
        r#"{"request":"load_vault_key","fingerprint":"SHA256:x"}"#,
        r#"{"request":"get_passphrase","key_id":"k"}"#,
        r#"{"request":"report_unknown_passkey","rp_id":"example.com","credential_id":"AQ=="}"#,
        r#"{"request":"list_passkeys","rp_id":"example.com"}"#,
        r#"{"request":"create_passkey","rp_id":"example.com","user_handle":"","user_name":"u","user_display_name":"u","client_data_hash":"","algorithms":[-7]}"#,
        r#"{"request":"assert_passkey","rp_id":"example.com","client_data_hash":""}"#,
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

/// Only the AutoFill extension names the app a request is for. A browser
/// host and `ap` are always a browser.
#[test]
fn only_autofill_extension_names_requesting_app() {
    let app = || Some("Notes".to_string());
    assert_eq!(requester_for(RequestScope::AutofillExtension, app()), app());
    assert_eq!(requester_for(RequestScope::BrowserHost, app()), None);
    assert_eq!(requester_for(RequestScope::Agent, app()), None);
}
