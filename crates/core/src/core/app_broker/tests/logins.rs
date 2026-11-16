use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use super::support::{CHROME, HANGING, PAGE, TestBroker, accepting_policy, browser_host_broker};
use crate::core::app_broker::VaultAction;
use crate::core::app_broker::access::RequestScope;
use crate::core::app_broker::wire::WireResponse;

/// A page the broker cannot match, and a relying party id that is not a
/// registrable domain, are refused before any prompt is raised.
#[tokio::test(flavor = "multi_thread")]
async fn refuses_unmatchable_rp_ids_early() {
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
        let response: WireResponse = broker.request_parsed(line);
        assert!(
            matches!(&response, WireResponse::Failed { message } if message.contains(expected)),
            "unexpected response to {line}"
        );
        assert!(broker.authorizer.peers.lock().unwrap().is_empty(), "{line}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn locked_listing_refused_to_untrusted() {
    let line = format!(r#"{{"request":"list_logins_locked",{PAGE}}}"#);
    let verified = format!(r#"{{"request":"list_logins_locked",{PAGE},{CHROME}}}"#);
    let refused = [
        (RequestScope::Agent, verified.clone()),
        (RequestScope::BrowserHost, line.clone()),
    ];
    for (scope, line) in refused {
        let broker = TestBroker::start_with_scope(accepting_policy(), scope).await;
        broker.logins.replace(Vec::new());
        let response: WireResponse = broker.request_parsed(&line);
        assert!(
            matches!(&response, WireResponse::Failed { message } if message.contains("may not")),
            "{scope:?} listed without a prompt"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn locked_listing_answers_from_index_without_prompt() {
    use crate::secrets::vaults::autofill::AutofillItem;
    use crate::secrets::vaults::{MatchKind, Website};

    let item = |record_id: &str, site: &str| AutofillItem {
        vault_key: "personal".to_string(),
        vault_name: None,
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
        let response: WireResponse = broker.request_parsed(&line);
        assert!(
            matches!(&response, WireResponse::LockedLogins { logins, indexed: false } if logins.is_empty()),
            "{scope:?}"
        );

        broker
            .logins
            .replace(vec![item("a", "example.com"), item("b", "other.com")]);
        let response: WireResponse = broker.request_parsed(&line);
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
async fn passkey_listing_answers_from_index_without_prompt() {
    use crate::core::app_broker::IndexedPasskey;

    let broker =
        TestBroker::start_with_scope(accepting_policy(), RequestScope::AutofillExtension).await;
    let line = r#"{"request":"list_passkeys","rp_id":"example.com"}"#;

    // Nothing is indexed before the app's first unlock.
    let response: WireResponse = broker.request_parsed(line);
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
    let response: WireResponse = broker.request_parsed(line);
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
async fn passkey_listing_refuses_public_suffix() {
    let broker =
        TestBroker::start_with_scope(accepting_policy(), RequestScope::AutofillExtension).await;
    broker.logins.replace_passkeys(Vec::new());
    let line = r#"{"request":"list_passkeys","rp_id":"github.io"}"#;
    let response: WireResponse = broker.request_parsed(line);
    assert!(
        matches!(&response, WireResponse::Failed { message } if message.contains("public suffix"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn generates_password_without_prompt() {
    let broker = browser_host_broker().await;

    let response = broker.request_parsed(r#"{"request":"generate_password"}"#);
    let WireResponse::GeneratedPassword { password } = response else {
        panic!("unexpected response");
    };
    assert_eq!(password.len(), 20);

    let response = broker
        .request_parsed(r#"{"request":"generate_password","policy":{"length":8,"symbols":false}}"#);
    let WireResponse::GeneratedPassword { password } = response else {
        panic!("unexpected response");
    };
    assert_eq!(password.len(), 8);
    assert!(password.chars().all(|c| c.is_ascii_alphanumeric()));

    let response =
        broker.request_parsed(r#"{"request":"generate_password","policy":{"length":1}}"#);
    assert!(matches!(response, WireResponse::Failed { .. }));

    assert!(broker.authorizer.peers.lock().unwrap().is_empty());
}

/// A registration prompt carries the logins the index holds for the
/// relying party, and suggests the one with the account's username.
#[tokio::test(flavor = "multi_thread")]
async fn registration_prompt_carries_placement_choices() {
    use crate::secrets::vaults::{LoginPlace, MatchKind, Website};

    let broker =
        TestBroker::start_with_scope(accepting_policy(), RequestScope::AutofillExtension).await;
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
async fn saving_login_always_prompts_and_keeps_password_out_of_it() {
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
        matches!(&prompts[0].action, VaultAction::SaveLogin { page, username, .. }
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

/// A save prompt carries the vault choices, and names the default vault until
/// the user chooses. With no vaults yet, the default vault is the one a write
/// creates.
#[tokio::test(flavor = "multi_thread")]
async fn save_prompt_carries_vault_choices() {
    let broker = browser_host_broker().await;
    broker.request(&format!(
        r#"{{"request":"save_login",{PAGE},"password":"s3cret",{CHROME}}}"#
    ));

    let prompts = broker.authorizer.vault_prompts.lock().unwrap();
    assert_eq!(prompts.len(), 1);
    let VaultAction::SaveLogin { choices, .. } = &prompts[0].action else {
        panic!("expected a save prompt");
    };
    assert!(choices.vaults.is_empty());
    assert_eq!(choices.default_vault, "default");
    assert_eq!(prompts[0].vault_key, "default");
}

/// Nothing without a password or an http(s) page reaches the prompt.
#[tokio::test(flavor = "multi_thread")]
async fn refuses_save_with_no_password_or_page_before_prompting() {
    let broker = browser_host_broker().await;
    for line in [
        format!(r#"{{"request":"save_login",{PAGE},"password":""}}"#),
        format!(r#"{{"request":"update_login_password",{PAGE},"record_id":"r","password":""}}"#),
        r#"{"request":"save_login","url":"https://example.com","frame_url":"ftp://example.com","password":"pw"}"#.to_string(),
    ] {
        let response: WireResponse = broker.request_parsed(&line);
        assert!(matches!(response, WireResponse::Failed { .. }), "{line}");
    }
    assert!(broker.authorizer.vault_prompts.lock().unwrap().is_empty());
}

/// Send a listing that waits on its prompt until the connection is dropped.
fn send_hanging_listing(broker: &TestBroker) -> UnixStream {
    let stream = UnixStream::connect(&broker.socket_path).unwrap();
    let line = format!(r#"{{"request":"list_logins",{PAGE},{HANGING}}}"#);
    (&stream).write_all(line.as_bytes()).unwrap();
    (&stream).write_all(b"\n").unwrap();
    stream
}

/// A locked listing needs no prompt, so it is answered while an earlier
/// request waits on the user.
#[tokio::test(flavor = "multi_thread")]
async fn locked_listing_not_queued_behind_prompt() {
    let broker = browser_host_broker().await;
    broker.logins.replace(Vec::new());

    let busy = send_hanging_listing(&broker);
    tokio::task::block_in_place(|| broker.authorizer.wait_for_hung_prompt());

    // Times out after five seconds if the broker queues it behind the prompt.
    let line = format!(r#"{{"request":"list_logins_locked",{PAGE},{CHROME}}}"#);
    let response: WireResponse = broker.request_parsed(&line);
    assert!(matches!(
        response,
        WireResponse::LockedLogins { indexed: true, .. }
    ));
    assert_eq!(broker.authorizer.prompts_hung.load(Ordering::SeqCst), 1);
    drop(busy);
}

/// Requests that may prompt take turns, so a second prompt starts only after
/// the first is gone.
#[tokio::test(flavor = "multi_thread")]
async fn prompting_requests_wait_for_turn() {
    let broker = browser_host_broker().await;

    let first = send_hanging_listing(&broker);
    tokio::task::block_in_place(|| broker.authorizer.wait_for_hung_prompt());
    let _second = send_hanging_listing(&broker);

    tokio::task::block_in_place(|| {
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(broker.authorizer.prompts_hung.load(Ordering::SeqCst), 1);

        drop(first);
        let deadline = Instant::now() + Duration::from_secs(5);
        while broker.authorizer.prompts_hung.load(Ordering::SeqCst) < 2 {
            assert!(
                Instant::now() < deadline,
                "the second prompt never started after the first ended"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    });
}
