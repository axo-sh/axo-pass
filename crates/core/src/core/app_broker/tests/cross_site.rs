// Tests through a live broker run on macOS only: the Linux peer check is a
// stub that refuses every client until M2.
#![cfg_attr(linux, allow(dead_code, unused_imports))]

use super::support::{CHROME, browser_host_broker};
use crate::core::app_broker::vault;
use crate::core::app_broker::wire::WireResponse;

#[test]
fn frame_on_another_site_is_cross_site() {
    let page = vault::LoginPage::parse("https://evil.com", "https://example.com", None).unwrap();
    assert!(page.cross_site);
    assert_eq!(page.top_host.as_deref(), Some("evil.com"));
    assert_eq!(page.url, "https://evil.com");
    assert!(page.clone().refuse_unmatched_cross_site(false).is_ok());
    assert!(page.refuse_unmatched_cross_site(true).is_err());
}

#[test]
fn frame_on_sibling_subdomain_not_cross_site() {
    let page = vault::LoginPage::parse(
        "https://example.com",
        "https://accounts.example.com/login",
        None,
    )
    .unwrap();
    assert!(!page.cross_site);
    assert_eq!(page.top_host.as_deref(), Some("example.com"));
    assert!(page.refuse_unmatched_cross_site(true).is_ok());
}

#[test]
fn top_level_page_not_cross_site() {
    let page = vault::LoginPage::parse("https://example.com", "https://example.com", None).unwrap();
    assert!(!page.cross_site);
    assert!(page.refuse_unmatched_cross_site(true).is_ok());
}

#[test]
fn shared_hosting_domains_are_cross_site() {
    let page = vault::LoginPage::parse("https://a.github.io", "https://b.github.io", None).unwrap();
    assert!(page.cross_site);
}

/// A fill in a cross-site frame reaches the prompt, except a pick from "All
/// logins", which is refused before any prompt with both hosts named.
#[cfg(macos)]
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
