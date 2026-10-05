//! Picks the vault items an AutoFill credential provider can offer, and matches
//! them against the service identifier the system supplies.
//!
//! An item is a login when its autofill data names a password credential.
//! Items with no role slots fall back to a heuristic: the first confidential
//! credential is the password, and their `Url` credentials are the websites.
//! The username and the fallback URLs are credential values, so collecting
//! them needs an unlocked vault; the password is never collected here, it is
//! read separately once the user picks an account.
//!
//! Websites match through the Public Suffix List, including its private
//! section, so `a.github.io` and `b.github.io` are different sites.

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use url::{Host, Url};

use super::{
    CATEGORY_LOGIN, Error, FieldKind, ItemAutofill, MatchKind, VaultItemCredentialOverview,
    VaultItemOverview, VaultWrapper, Website,
};

/// Credential keys treated as the account name when no `Email` field is
/// present, in preference order.
const USERNAME_KEYS: &[&str] = &["username", "user", "login", "email", "account"];

/// How closely a stored website matched. Lower sorts first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatchRank {
    /// The stored host equals the requested host.
    Host,
    /// Only the registrable domain is shared.
    Domain,
}

/// The stored website that made an item match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchedWebsite {
    /// The stored host, lowercased, with one leading `www.` removed.
    pub host: String,
    pub kind: MatchKind,
    pub rank: MatchRank,
}

/// One vault item as an AutoFill candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutofillItem {
    pub vault_key: String,
    pub item_key: String,
    /// `<vault uuid>/<item uuid>/<password credential uuid>`. Survives renames
    /// of the item and its credentials.
    pub record_id: String,
    pub title: String,
    /// The account name shown beside the item. `None` when the item has no
    /// field that reads as one.
    pub username: Option<String>,
    /// The credential key holding the password to fill.
    pub password_key: String,
    /// The websites the item applies to.
    pub websites: Vec<Website>,
    /// True when `websites` came from the item's `Url` credentials because it
    /// has none of its own.
    pub websites_from_url_fields: bool,
    /// The website that matched the requested service. `None` when collected
    /// without a service.
    pub matched: Option<MatchedWebsite>,
}

impl AutofillItem {
    /// How this item ranks among matches, best first. Ties break on title.
    pub fn sort_key(&self) -> (Option<MatchRank>, String) {
        (
            self.matched.as_ref().map(|m| m.rank),
            self.title.to_lowercase(),
        )
    }
}

/// Collect every AutoFill candidate in an unlocked vault. `service`, when
/// given, keeps only the items matching it, best match first.
pub fn collect_items(vw: &VaultWrapper, service: Option<&str>) -> Result<Vec<AutofillItem>, Error> {
    let target = match service {
        Some(service) => match ParsedUrl::parse(service) {
            Some(target) => Some(target),
            // A service that is not an http(s) site matches nothing.
            None => return Ok(Vec::new()),
        },
        None => None,
    };
    let vault_id = vw.vault_id()?;

    let mut items = Vec::new();
    for overview in vw.list_items()? {
        let credentials = sorted_credentials(overview);
        let Roles { password, username } = pick_roles(overview, &credentials);
        let Some(password) = password else {
            continue;
        };

        let mut websites = overview.autofill.websites.clone();
        let mut from_url_fields = false;
        if websites.is_empty() {
            from_url_fields = true;
            for cred in credentials
                .iter()
                .filter(|c| matches!(c.kind, FieldKind::Url))
            {
                if let Some(value) = read(vw, &overview.key, &cred.key)? {
                    // Only http and https sites are logins. Other schemes
                    // would offer database and API items as logins.
                    if ParsedUrl::parse(&value).is_some() {
                        websites.push(Website::new(value, MatchKind::Domain));
                    }
                }
            }
        }

        let matched = match &target {
            Some(target) => match best_match(&websites, target) {
                Some(matched) => Some(matched),
                None => continue,
            },
            None => None,
        };

        let username = match username {
            Some(cred) => read(vw, &overview.key, &cred.key)?,
            None => None,
        };

        items.push(AutofillItem {
            vault_key: vw.key.clone(),
            item_key: overview.key.clone(),
            record_id: format!("{vault_id}/{}/{}", overview.id, password.id),
            title: overview.title.clone(),
            username,
            password_key: password.key.clone(),
            websites,
            websites_from_url_fields: from_url_fields,
            matched,
        });
    }
    items.sort_by_key(AutofillItem::sort_key);
    Ok(items)
}

/// A login to write: the item, its password, and the optional username and
/// websites.
pub struct LoginWrite<'a> {
    pub item_key: &'a str,
    /// Used only when the item does not exist yet.
    pub title: &'a str,
    /// The credential key for the password. Conventionally `password`.
    pub password_key: &'a str,
    pub password: SecretString,
    pub username: Option<&'a str>,
    /// URLs or bare domains, added with `domain` matching unless the item
    /// already lists them.
    pub websites: &'a [String],
}

/// Write a login into an unlocked vault: the item when it is missing, the
/// password credential, the username credential keyed `username`, the role
/// slots, the websites, and `category: login`. The caller saves the vault.
pub fn write_login(vw: &mut VaultWrapper, login: LoginWrite) -> Result<(), Error> {
    if vw.get_item_overview(login.item_key)?.is_none() {
        vw.add_item(login.item_key, login.title)?;
    }

    vw.add_secret(
        login.item_key,
        login.password_key,
        "Password",
        FieldKind::default(),
        login.password,
    )?;
    let password_id = credential_id(vw, login.item_key, login.password_key)?;

    let mut autofill = vw
        .get_item_overview(login.item_key)?
        .map(|item| item.autofill.clone())
        .unwrap_or_default();
    autofill.password = Some(password_id);

    if let Some(username) = login.username {
        let kind = if looks_like_email(username) {
            FieldKind::Email
        } else {
            FieldKind::Text(Default::default())
        };
        vw.add_secret(
            login.item_key,
            USERNAME_KEYS[0],
            "Username",
            kind,
            SecretString::from(username.to_string()),
        )?;
        autofill.username = Some(credential_id(vw, login.item_key, USERNAME_KEYS[0])?);
    }

    for url in login.websites {
        let url = url.trim();
        if !url.is_empty() && !autofill.websites.iter().any(|w| w.url == url) {
            autofill.websites.push(Website::new(url, MatchKind::Domain));
        }
    }

    vw.set_item_autofill(login.item_key, autofill)?;
    let has_category = vw
        .get_item_overview(login.item_key)?
        .is_some_and(|item| item.category.is_some());
    if !has_category {
        vw.set_item_category(login.item_key, Some(CATEGORY_LOGIN.to_string()))?;
    }
    Ok(())
}

fn credential_id(vw: &VaultWrapper, item_key: &str, cred_key: &str) -> Result<uuid::Uuid, Error> {
    vw.get_secret_overview(item_key, cred_key)?
        .map(|cred| cred.id)
        .ok_or_else(|| Error::InvalidCredentialKey(format!("{item_key}/{cred_key}")))
}

fn looks_like_email(value: &str) -> bool {
    match value.split_once('@') {
        Some((local, host)) => {
            !local.is_empty() && host.contains('.') && !value.chars().any(char::is_whitespace)
        },
        None => false,
    }
}

/// The first website of `websites` that matches `service`, preferring an exact
/// host match over a domain match. `service` is a bare domain or a full URL.
pub fn match_service(websites: &[Website], service: &str) -> Option<MatchedWebsite> {
    best_match(websites, &ParsedUrl::parse(service)?)
}

fn best_match(websites: &[Website], target: &ParsedUrl) -> Option<MatchedWebsite> {
    websites
        .iter()
        .filter_map(|website| match_website(website, target))
        .min_by_key(|matched| matched.rank)
}

fn match_website(website: &Website, target: &ParsedUrl) -> Option<MatchedWebsite> {
    let stored = ParsedUrl::parse(&website.url)?;
    let same_host = stored.host == target.host;
    let matches = match website.match_kind {
        MatchKind::Domain => stored.domain == target.domain,
        MatchKind::Host => same_host,
        MatchKind::StartsWith => {
            // A bare domain has no page to compare, so it matches by host.
            same_host
                && match &target.path {
                    None => true,
                    Some(path) => path.starts_with(stored.path.as_deref().unwrap_or("/")),
                }
        },
    };
    matches.then_some(MatchedWebsite {
        host: stored.host,
        kind: website.match_kind,
        rank: if same_host {
            MatchRank::Host
        } else {
            MatchRank::Domain
        },
    })
}

/// A service identifier or stored URL reduced to what matching compares.
#[derive(Debug, PartialEq, Eq)]
struct ParsedUrl {
    /// Lowercase ASCII host, with one leading `www.` removed.
    host: String,
    /// The registrable domain. The host itself for IP addresses, single-label
    /// hosts, and hosts that are public suffixes.
    domain: String,
    /// Path and query. `None` for a bare domain.
    path: Option<String>,
}

impl ParsedUrl {
    /// Parse a bare domain or an http(s) URL. Any other scheme gives `None`.
    /// Ports are dropped.
    fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        if value.is_empty() {
            return None;
        }
        let has_scheme = value.contains("://");
        // A bare domain has no scheme, which `Url` rejects, so add one.
        let candidate = if has_scheme {
            value.to_string()
        } else {
            format!("https://{value}")
        };
        let url = Url::parse(&candidate).ok()?;
        if !matches!(url.scheme(), "http" | "https") {
            return None;
        }

        let (host, is_ip) = match url.host()? {
            // `Url` has already lowercased the host and converted it to ASCII.
            Host::Domain(domain) => (domain.trim_end_matches('.').to_string(), false),
            Host::Ipv4(ip) => (ip.to_string(), true),
            Host::Ipv6(ip) => (ip.to_string(), true),
        };
        let host = host.strip_prefix("www.").unwrap_or(&host).to_string();
        if host.is_empty() {
            return None;
        }

        let domain = if is_ip {
            host.clone()
        } else {
            psl::domain(host.as_bytes())
                .and_then(|domain| std::str::from_utf8(domain.as_bytes()).ok())
                .unwrap_or(&host)
                .to_string()
        };

        let has_path = url.path() != "/" || url.query().is_some();
        let path = (has_scheme || has_path).then(|| match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None => url.path().to_string(),
        });

        Some(Self { host, domain, path })
    }
}

fn read(vw: &VaultWrapper, item_key: &str, cred_key: &str) -> Result<Option<String>, Error> {
    use secrecy::ExposeSecret;
    let value = vw
        .get_secret(item_key, cred_key)?
        .map(|secret| secret.expose_secret().to_string())
        .filter(|value| !value.trim().is_empty());
    Ok(value)
}

/// An item's credentials in display order. Reordered credentials lead, so the
/// first confidential field is the one the user put at the top.
fn sorted_credentials(overview: &VaultItemOverview) -> Vec<&VaultItemCredentialOverview> {
    let mut credentials: Vec<_> = overview.credentials.values().collect();
    credentials.sort_by(|a, b| {
        (a.position.unwrap_or(u32::MAX), &a.title).cmp(&(b.position.unwrap_or(u32::MAX), &b.title))
    });
    credentials
}

struct Roles<'a> {
    password: Option<&'a VaultItemCredentialOverview>,
    username: Option<&'a VaultItemCredentialOverview>,
}

/// The credentials to fill. Role slots decide when the item has any; an item
/// with none uses the heuristic.
fn pick_roles<'a>(
    overview: &'a VaultItemOverview,
    credentials: &[&'a VaultItemCredentialOverview],
) -> Roles<'a> {
    let autofill: &ItemAutofill = &overview.autofill;
    if autofill.password.is_some() || autofill.username.is_some() {
        return Roles {
            password: autofill.password_credential(overview),
            username: autofill.username_credential(overview),
        };
    }
    Roles {
        password: pick_password(credentials),
        username: pick_username(credentials),
    }
}

/// The credential to fill: a confidential field, preferring one named
/// "password" when the item has several.
fn pick_password<'a>(
    credentials: &[&'a VaultItemCredentialOverview],
) -> Option<&'a VaultItemCredentialOverview> {
    let confidential: Vec<_> = credentials
        .iter()
        .copied()
        .filter(|c| matches!(c.kind, FieldKind::Confidential(_)))
        .collect();
    confidential
        .iter()
        .copied()
        .find(|c| c.key.contains("password") || c.title.to_lowercase().contains("password"))
        .or_else(|| confidential.first().copied())
}

/// The credential that names the account: an `Email` field, else the first
/// credential whose key is a conventional username key.
fn pick_username<'a>(
    credentials: &[&'a VaultItemCredentialOverview],
) -> Option<&'a VaultItemCredentialOverview> {
    if let Some(email) = credentials
        .iter()
        .copied()
        .find(|c| matches!(c.kind, FieldKind::Email))
    {
        return Some(email);
    }
    USERNAME_KEYS.iter().find_map(|wanted| {
        credentials
            .iter()
            .copied()
            .find(|c| c.key == *wanted && !matches!(c.kind, FieldKind::Confidential(_)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(url: &str, kind: MatchKind) -> Website {
        Website::new(url, kind)
    }

    fn domain(url: &str) -> Vec<Website> {
        vec![site(url, MatchKind::Domain)]
    }

    fn matches(websites: &[Website], service: &str) -> bool {
        match_service(websites, service).is_some()
    }

    #[test]
    fn domain_matches_the_same_host() {
        assert!(matches(&domain("https://example.com/login"), "example.com"));
        assert!(matches(
            &domain("example.com"),
            "https://example.com/anything"
        ));
    }

    #[test]
    fn domain_matches_across_subdomains_of_a_registrable_domain() {
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
    fn www_is_ignored() {
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
    fn ports_and_schemes_are_ignored() {
        assert!(matches(
            &[site("http://example.com:8080", MatchKind::Host)],
            "https://example.com:9000/x"
        ));
    }

    #[test]
    fn starts_with_compares_pages_on_the_same_host() {
        let websites = [site("https://example.com/app", MatchKind::StartsWith)];
        assert!(matches(&websites, "https://example.com/app/login"));
        assert!(matches(&websites, "https://example.com/app"));
        assert!(!matches(&websites, "https://example.com/other"));
        assert!(!matches(&websites, "https://sub.example.com/app"));
    }

    #[test]
    fn starts_with_does_not_match_a_longer_host() {
        let websites = [site("https://example.com", MatchKind::StartsWith)];
        assert!(!matches(&websites, "https://example.com.evil.com/login"));
        assert!(matches(&websites, "https://example.com/login"));
    }

    #[test]
    fn starts_with_treats_a_bare_domain_as_a_host_match() {
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
    fn reports_the_stored_host_that_matched() {
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
    fn an_exact_host_match_beats_a_domain_match() {
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
            item_key: title.to_lowercase(),
            record_id: String::new(),
            title: title.to_string(),
            username: None,
            password_key: "password".to_string(),
            websites: Vec::new(),
            websites_from_url_fields: false,
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

    fn login<'a>(websites: &'a [String], username: Option<&'a str>) -> LoginWrite<'a> {
        LoginWrite {
            item_key: "github",
            title: "GitHub",
            password_key: "password",
            password: SecretString::from("hunter2"),
            username,
            websites,
        }
    }

    #[test]
    fn write_login_creates_the_item_credentials_roles_and_websites() {
        use secrecy::ExposeSecret;

        let mut vw = VaultWrapper::new_for_test("personal");
        let websites = vec!["github.com".to_string()];
        write_login(&mut vw, login(&websites, Some("tp"))).unwrap();

        let item = vw.get_item_overview("github").unwrap().unwrap();
        assert_eq!(item.title, "GitHub");
        assert_eq!(item.category.as_deref(), Some(CATEGORY_LOGIN));
        assert_eq!(
            item.autofill.websites,
            vec![Website::new("github.com", MatchKind::Domain)]
        );
        assert_eq!(
            item.autofill.password_credential(item).unwrap().key,
            "password"
        );
        let username = item.autofill.username_credential(item).unwrap();
        assert_eq!(username.key, "username");
        assert!(matches!(username.kind, FieldKind::Text(_)));

        let password = vw.get_secret("github", "password").unwrap().unwrap();
        assert_eq!(password.expose_secret(), "hunter2");
        let username = vw.get_secret("github", "username").unwrap().unwrap();
        assert_eq!(username.expose_secret(), "tp");

        let found = collect_items(&vw, Some("gist.github.com")).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].username.as_deref(), Some("tp"));
        assert_eq!(found[0].matched.as_ref().unwrap().host, "github.com");
        assert!(!found[0].websites_from_url_fields);
        assert!(collect_items(&vw, Some("github.io")).unwrap().is_empty());
    }

    #[test]
    fn write_login_stores_an_email_username_as_email() {
        let mut vw = VaultWrapper::new_for_test("personal");
        write_login(&mut vw, login(&[], Some("tp@example.com"))).unwrap();
        let cred = vw
            .get_secret_overview("github", "username")
            .unwrap()
            .unwrap();
        assert_eq!(cred.kind, FieldKind::Email);
    }

    #[test]
    fn write_login_does_not_duplicate_websites_on_update() {
        let mut vw = VaultWrapper::new_for_test("personal");
        let websites = vec!["github.com".to_string()];
        write_login(&mut vw, login(&websites, None)).unwrap();
        write_login(&mut vw, login(&websites, None)).unwrap();
        let item = vw.get_item_overview("github").unwrap().unwrap();
        assert_eq!(item.autofill.websites.len(), 1);
        assert!(item.autofill.username.is_none());
    }

    #[test]
    fn url_field_fallback_is_limited_to_http_sites() {
        let mut vw = VaultWrapper::new_for_test("personal");
        vw.add_item("database", "Database").unwrap();
        for (key, value) in [("password", "pw"), ("url", "postgres://example.com/db")] {
            let kind = if key == "url" {
                FieldKind::Url
            } else {
                FieldKind::default()
            };
            vw.add_secret("database", key, key, kind, SecretString::from(value))
                .unwrap();
        }
        assert!(collect_items(&vw, Some("example.com")).unwrap().is_empty());

        vw.add_item("blog", "Blog").unwrap();
        vw.add_secret(
            "blog",
            "password",
            "Password",
            FieldKind::default(),
            SecretString::from("pw"),
        )
        .unwrap();
        vw.add_secret(
            "blog",
            "site",
            "Site",
            FieldKind::Url,
            SecretString::from("https://blog.example.com/login"),
        )
        .unwrap();
        let found = collect_items(&vw, Some("example.com")).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].item_key, "blog");
        assert!(found[0].websites_from_url_fields);
    }

    fn overview(creds: &[(&str, FieldKind)]) -> VaultItemOverview {
        let mut item = VaultItemOverview::try_new("Item", "item").unwrap();
        for (key, kind) in creds {
            let cred = VaultItemCredentialOverview::try_new(key, key, kind.clone()).unwrap();
            item.credentials.insert(cred.id, cred);
        }
        item
    }

    fn key_of(item: &VaultItemOverview, key: &str) -> uuid::Uuid {
        item.credentials.values().find(|c| c.key == key).unwrap().id
    }

    #[test]
    fn roles_take_precedence_over_the_heuristic() {
        let mut item = overview(&[
            ("password", FieldKind::default()),
            ("pin", FieldKind::default()),
            ("handle", FieldKind::Text(Default::default())),
        ]);
        item.autofill.password = Some(key_of(&item, "pin"));
        item.autofill.username = Some(key_of(&item, "handle"));
        let credentials = sorted_credentials(&item);
        let roles = pick_roles(&item, &credentials);
        assert_eq!(roles.password.unwrap().key, "pin");
        assert_eq!(roles.username.unwrap().key, "handle");
    }

    #[test]
    fn a_dangling_password_role_is_not_a_login() {
        let mut item = overview(&[("password", FieldKind::default())]);
        item.autofill.password = Some(uuid::Uuid::new_v4());
        let credentials = sorted_credentials(&item);
        assert!(pick_roles(&item, &credentials).password.is_none());
    }

    #[test]
    fn items_without_roles_use_the_heuristic() {
        let item = overview(&[
            ("api-token", FieldKind::default()),
            ("password", FieldKind::default()),
            ("email", FieldKind::Email),
        ]);
        let credentials = sorted_credentials(&item);
        let roles = pick_roles(&item, &credentials);
        assert_eq!(roles.password.unwrap().key, "password");
        assert_eq!(roles.username.unwrap().key, "email");
    }
}
