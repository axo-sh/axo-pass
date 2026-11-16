use super::super::{
    AutofillItem, MatchKind, MatchRank, MatchedWebsite, identity_hosts, match_scope, match_service,
};
use super::{domain, matches, site};

#[test]
fn match_scope_follows_match_kind() {
    let url = "https://signin.aws.amazon.com/switchrole?account=1&displayName=dev";
    let scope = |kind| match_scope(&site(url, kind)).unwrap();
    assert_eq!(scope(MatchKind::Domain), "amazon.com");
    assert_eq!(scope(MatchKind::Host), "signin.aws.amazon.com");
    assert_eq!(
        scope(MatchKind::StartsWith),
        "signin.aws.amazon.com/switchrole?account=1&displayName=dev"
    );
    assert_eq!(scope(MatchKind::Never), "signin.aws.amazon.com");
}

#[test]
fn match_scope_keeps_nondefault_port() {
    let website = site("http://localhost:3000/app", MatchKind::StartsWith);
    assert_eq!(match_scope(&website).unwrap(), "localhost:3000/app");
    let website = site("https://www.example.com:443/", MatchKind::StartsWith);
    assert_eq!(match_scope(&website).unwrap(), "example.com");
}

#[test]
fn match_scope_uses_public_suffix_list() {
    let website = site("https://shop.example.co.uk", MatchKind::Domain);
    assert_eq!(match_scope(&website).unwrap(), "example.co.uk");
}

#[test]
fn identity_hosts_follow_match_kind() {
    let websites = [
        site("https://login.example.com/x", MatchKind::Domain),
        site("https://www.other.org/app", MatchKind::Host),
        site("https://pages.test/a", MatchKind::StartsWith),
        site("https://never.test", MatchKind::Never),
        site("example.com", MatchKind::Domain),
    ];
    assert_eq!(
        identity_hosts(&websites),
        [
            "example.com",
            "login.example.com",
            "other.org",
            "pages.test"
        ]
    );
}

#[test]
fn domain_matches_same_host() {
    assert!(matches(&domain("https://example.com/login"), "example.com"));
    assert!(matches(
        &domain("example.com"),
        "https://example.com/anything"
    ));
}

#[test]
fn domain_matches_across_subdomains_of_registrable_domain() {
    assert!(matches(
        &domain("https://accounts.example.com"),
        "example.com"
    ));
    assert!(matches(&domain("https://example.com"), "login.example.com"));
    assert!(matches(
        &domain("https://a.example.co.uk"),
        "b.example.co.uk"
    ));
}

#[test]
fn private_suffixes_isolate_sites() {
    assert!(!matches(&domain("a.github.io"), "b.github.io"));
    assert!(!matches(&domain("github.io"), "a.github.io"));
    assert!(!matches(&domain("a.github.io"), "github.io"));
    assert!(matches(&domain("a.github.io"), "a.github.io"));
    assert!(!matches(&domain("one.vercel.app"), "two.vercel.app"));
}

#[test]
fn domain_does_not_cross_registrable_domains() {
    assert!(!matches(&domain("https://example.com"), "example.org"));
    assert!(!matches(&domain("https://example.com"), "notexample.com"));
    assert!(!matches(
        &domain("https://example.com"),
        "example.com.evil.com"
    ));
    assert!(!matches(&domain("https://co.uk"), "example.co.uk"));
    assert!(!matches(&[], "example.com"));
}

#[test]
fn www_ignored() {
    assert!(matches(&domain("https://www.example.com"), "example.com"));
    assert!(matches(
        &[site("www.example.com", MatchKind::Host)],
        "example.com"
    ));
}

#[test]
fn host_requires_equal_hosts() {
    let websites = [site("https://login.example.com", MatchKind::Host)];
    assert!(matches(&websites, "login.example.com"));
    assert!(matches(&websites, "https://login.example.com/path?q=1"));
    assert!(!matches(&websites, "example.com"));
    assert!(!matches(&websites, "other.example.com"));
}

#[test]
fn ports_ignored_by_domain_and_compared_by_host_and_starts_with() {
    use MatchKind::{Domain, Host, StartsWith};
    // Label, stored website, match kind, page, and whether it matches.
    let rows = [
        (
            "domain ignores ports",
            "http://example.com:8080",
            Domain,
            "https://example.com:9000/x",
            true,
        ),
        (
            "domain ignores ports on localhost",
            "localhost:3000",
            Domain,
            "http://localhost:8080",
            true,
        ),
        (
            "host same port",
            "http://localhost:3000",
            Host,
            "http://localhost:3000/login",
            true,
        ),
        (
            "host other port",
            "http://localhost:3000",
            Host,
            "http://localhost:8080",
            false,
        ),
        (
            "host no port",
            "http://localhost:3000",
            Host,
            "http://localhost",
            false,
        ),
        (
            "default port in page",
            "https://example.com",
            Host,
            "https://example.com:443/x",
            true,
        ),
        (
            "other port in page",
            "https://example.com",
            Host,
            "https://example.com:8443",
            false,
        ),
        (
            "default port stored",
            "https://example.com:443",
            Host,
            "https://example.com",
            true,
        ),
        (
            "bare page, port stored",
            "https://example.com:8443",
            Host,
            "example.com",
            true,
        ),
        (
            "bare stored, port in page",
            "example.com",
            Host,
            "https://example.com:8443",
            true,
        ),
        (
            "starts with same port",
            "https://example.com:8443/app",
            StartsWith,
            "https://example.com:8443/app/x",
            true,
        ),
        (
            "starts with other port",
            "https://example.com:8443/app",
            StartsWith,
            "https://example.com/app/x",
            false,
        ),
    ];
    for (label, stored, kind, page, expected) in rows {
        assert_eq!(matches(&[site(stored, kind)], page), expected, "{label}");
    }
}

#[test]
fn never_matches_nothing() {
    let websites = [site("https://example.com", MatchKind::Never)];
    assert!(!matches(&websites, "https://example.com"));
    assert!(!matches(&websites, "example.com"));
    assert!(!matches(&websites, "https://sub.example.com"));
}

#[test]
fn never_does_not_block_another_website_on_same_login() {
    let websites = [
        site("https://example.com/admin", MatchKind::Never),
        site("https://example.com", MatchKind::Domain),
    ];
    assert!(matches(&websites, "https://example.com/admin"));
}

#[test]
fn https_login_does_not_match_http_page() {
    for kind in [MatchKind::Domain, MatchKind::Host, MatchKind::StartsWith] {
        let websites = [site("https://example.com", kind)];
        assert!(matches(&websites, "https://example.com"));
        assert!(!matches(&websites, "http://example.com"));
        assert!(!matches(&websites, "HTTP://example.com/login"));
    }
}

#[test]
fn http_or_bare_login_matches_http_page() {
    assert!(matches(&domain("http://example.com"), "http://example.com"));
    assert!(matches(&domain("example.com"), "http://example.com"));
}

#[test]
fn starts_with_compares_pages_on_same_host() {
    let websites = [site("https://example.com/app", MatchKind::StartsWith)];
    assert!(matches(&websites, "https://example.com/app/login"));
    assert!(matches(&websites, "https://example.com/app"));
    assert!(!matches(&websites, "https://example.com/other"));
    assert!(!matches(&websites, "https://sub.example.com/app"));
}

#[test]
fn starts_with_compares_whole_path_segments() {
    let websites = [site("https://example.com/app", MatchKind::StartsWith)];
    assert!(!matches(&websites, "https://example.com/application"));
    assert!(!matches(&websites, "https://example.com/app-evil/login"));
    assert!(matches(&websites, "https://example.com/app/"));
    assert!(matches(&websites, "https://example.com/app/a/b?x=1"));
    let websites = [site("https://example.com/app/", MatchKind::StartsWith)];
    assert!(matches(&websites, "https://example.com/app"));
    assert!(matches(&websites, "https://example.com/app/login"));
    assert!(!matches(&websites, "https://example.com/application"));
}

#[test]
fn starts_with_normalizes_dot_segments() {
    let websites = [site("https://example.com/app", MatchKind::StartsWith)];
    assert!(!matches(&websites, "https://example.com/app/../admin"));
    assert!(matches(&websites, "https://example.com/other/../app/login"));
}

#[test]
fn starts_with_requires_equal_stored_query() {
    let websites = [site(
        "https://example.com/app?tenant=a",
        MatchKind::StartsWith,
    )];
    assert!(matches(&websites, "https://example.com/app?tenant=a"));
    assert!(!matches(&websites, "https://example.com/app?tenant=ab"));
    assert!(!matches(&websites, "https://example.com/app"));
}

#[test]
fn starts_with_does_not_match_longer_host() {
    let websites = [site("https://example.com", MatchKind::StartsWith)];
    assert!(!matches(&websites, "https://example.com.evil.com/login"));
    assert!(matches(&websites, "https://example.com/login"));
}

#[test]
fn starts_with_treats_bare_domain_as_host_match() {
    let websites = [site("https://example.com/app", MatchKind::StartsWith)];
    assert!(matches(&websites, "example.com"));
    assert!(!matches(&websites, "other.com"));
}

#[test]
fn idn_hosts_compare_in_ascii() {
    assert!(matches(
        &domain("https://bücher.example"),
        "xn--bcher-kva.example"
    ));
    assert!(matches(&domain("xn--bcher-kva.example"), "BÜCHER.example"));
}

#[test]
fn ip_addresses_and_single_label_hosts_match_exactly() {
    assert!(matches(&domain("http://192.168.0.1"), "192.168.0.1"));
    assert!(!matches(&domain("http://192.168.0.1"), "10.168.0.1"));
    assert!(!matches(&domain("http://192.168.0.1"), "192.168.0.2"));
    assert!(matches(&domain("localhost"), "http://localhost:3000"));
    assert!(!matches(&domain("localhost"), "other"));
}

#[test]
fn other_schemes_never_match() {
    assert!(!matches(
        &domain("postgres://example.com/db"),
        "example.com"
    ));
    assert!(!matches(
        &domain("example.com"),
        "postgres://example.com/db"
    ));
    assert!(!matches(&domain("example.com"), ""));
}

#[test]
fn reports_stored_host_that_matched() {
    let websites = vec![
        site("https://www.other.com", MatchKind::Domain),
        site("https://accounts.example.com", MatchKind::Domain),
    ];
    let matched = match_service(&websites, "https://example.com/login").unwrap();
    assert_eq!(matched.host, "accounts.example.com");
    assert_eq!(matched.kind, MatchKind::Domain);
    assert_eq!(matched.rank, MatchRank::Domain);
}

#[test]
fn exact_host_match_beats_domain_match() {
    let websites = vec![
        site("https://accounts.example.com", MatchKind::Domain),
        site("https://example.com", MatchKind::Domain),
    ];
    let matched = match_service(&websites, "example.com").unwrap();
    assert_eq!(matched.host, "example.com");
    assert_eq!(matched.rank, MatchRank::Host);
}

#[test]
fn matches_sort_by_rank_then_title() {
    let item = |title: &str, rank: Option<MatchRank>| AutofillItem {
        vault_key: "personal".to_string(),
        vault_name: None,
        item_key: title.to_lowercase(),
        record_id: String::new(),
        title: title.to_string(),
        username: None,
        password_key: "password".to_string(),
        websites: Vec::new(),
        has_totp: false,
        matched: rank.map(|rank| MatchedWebsite {
            host: "example.com".to_string(),
            kind: MatchKind::Domain,
            rank,
        }),
    };
    let mut items = [
        item("Zed", Some(MatchRank::Host)),
        item("Alpha", Some(MatchRank::Domain)),
        item("Beta", Some(MatchRank::Host)),
    ];
    items.sort_by_key(AutofillItem::sort_key);
    let titles: Vec<_> = items.iter().map(|i| i.title.as_str()).collect();
    assert_eq!(titles, ["Beta", "Zed", "Alpha"]);
}
