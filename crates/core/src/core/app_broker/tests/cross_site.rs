use crate::core::app_broker::vault;

#[test]
fn frame_on_another_site_is_cross_site() {
    let page = vault::LoginPage::parse("https://evil.com", "https://example.com", None).unwrap();
    assert!(page.cross_site);
    assert_eq!(page.top_host.as_deref(), Some("evil.com"));
    assert!(page.require_same_site().is_err());
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
    assert!(page.require_same_site().is_ok());
}

#[test]
fn top_level_page_not_cross_site() {
    let page = vault::LoginPage::parse("https://example.com", "https://example.com", None).unwrap();
    assert!(!page.cross_site);
    assert!(page.require_same_site().is_ok());
}

#[test]
fn shared_hosting_domains_are_cross_site() {
    let page = vault::LoginPage::parse("https://a.github.io", "https://b.github.io", None).unwrap();
    assert!(page.cross_site);
}
