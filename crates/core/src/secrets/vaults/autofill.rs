//! Picks the vault items an AutoFill credential provider can offer, and matches
//! them against the service identifier the system supplies.
//!
//! An item qualifies when it has a confidential credential to fill. The
//! username and the URLs are credential values, so collecting them needs an
//! unlocked vault; the password is never collected here, it is read separately
//! once the user picks an account.

use serde::{Deserialize, Serialize};

use super::{Error, FieldKind, VaultWrapper};

/// Credential keys treated as the account name when no `Email` field is
/// present, in preference order.
const USERNAME_KEYS: &[&str] = &["username", "user", "login", "email", "account"];

/// One vault item as an AutoFill candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutofillItem {
    pub vault_key: String,
    pub item_key: String,
    pub title: String,
    /// The account name shown beside the item. `None` when the item has no
    /// field that reads as one.
    pub username: Option<String>,
    /// The credential key holding the password to fill.
    pub password_key: String,
    /// Every URL field's value, used for service matching.
    pub urls: Vec<String>,
}

impl AutofillItem {
    /// Whether this item should be offered for `service`, which is a bare
    /// domain or a full URL. Matches on host, treating either host being a
    /// subdomain of the other as a match.
    pub fn matches(&self, service: &str) -> bool {
        let Some(wanted) = service_host(service) else {
            return false;
        };
        self.urls
            .iter()
            .filter_map(|url| service_host(url))
            .any(|host| hosts_match(&host, &wanted))
    }
}

/// Collect every AutoFill candidate in an unlocked vault. `service`, when
/// given, keeps only the items matching it.
pub fn collect_items(
    vw: &VaultWrapper,
    service: Option<&str>,
) -> Result<Vec<AutofillItem>, Error> {
    let mut items = Vec::new();
    for overview in vw.list_items()? {
        let mut credentials: Vec<_> = overview.credentials.values().collect();
        // Reordered credentials lead, so the first confidential field is the
        // one the user put at the top.
        credentials.sort_by(|a, b| {
            (a.position.unwrap_or(u32::MAX), &a.title).cmp(&(b.position.unwrap_or(u32::MAX), &b.title))
        });

        let Some(password) = pick_password(&credentials) else {
            continue;
        };

        let mut urls = Vec::new();
        for cred in credentials.iter().filter(|c| matches!(c.kind, FieldKind::Url)) {
            if let Some(value) = read(vw, &overview.key, &cred.key)? {
                urls.push(value);
            }
        }

        let username = match pick_username(&credentials) {
            Some(cred) => read(vw, &overview.key, &cred.key)?,
            None => None,
        };

        let item = AutofillItem {
            vault_key: vw.key.clone(),
            item_key: overview.key.clone(),
            title: overview.title.clone(),
            username,
            password_key: password.key.clone(),
            urls,
        };
        if service.is_none_or(|service| item.matches(service)) {
            items.push(item);
        }
    }
    items.sort_by_key(|item| item.title.to_lowercase());
    Ok(items)
}

fn read(vw: &VaultWrapper, item_key: &str, cred_key: &str) -> Result<Option<String>, Error> {
    use secrecy::ExposeSecret;
    let value = vw
        .get_secret(item_key, cred_key)?
        .map(|secret| secret.expose_secret().to_string())
        .filter(|value| !value.trim().is_empty());
    Ok(value)
}

/// The credential to fill: a confidential field, preferring one named
/// "password" when the item has several.
fn pick_password<'a>(
    credentials: &[&'a super::VaultItemCredentialOverview],
) -> Option<&'a super::VaultItemCredentialOverview> {
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
    credentials: &[&'a super::VaultItemCredentialOverview],
) -> Option<&'a super::VaultItemCredentialOverview> {
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

/// Reduce a service identifier or a stored URL to a bare lowercase host.
fn service_host(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    // A bare domain has no scheme, which `Url` rejects, so add one.
    let candidate = if value.contains("://") {
        value.to_string()
    } else {
        format!("https://{value}")
    };
    let host = url::Url::parse(&candidate).ok()?.host_str()?.to_lowercase();
    Some(host.trim_start_matches("www.").to_string())
}

fn hosts_match(a: &str, b: &str) -> bool {
    a == b || a.ends_with(&format!(".{b}")) || b.ends_with(&format!(".{a}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(urls: &[&str]) -> AutofillItem {
        AutofillItem {
            vault_key: "personal".to_string(),
            item_key: "example".to_string(),
            title: "Example".to_string(),
            username: None,
            password_key: "password".to_string(),
            urls: urls.iter().map(|u| u.to_string()).collect(),
        }
    }

    #[test]
    fn matches_the_same_host() {
        assert!(item(&["https://example.com/login"]).matches("example.com"));
        assert!(item(&["example.com"]).matches("https://example.com/anything"));
    }

    #[test]
    fn matches_across_subdomains() {
        assert!(item(&["https://accounts.example.com"]).matches("example.com"));
        assert!(item(&["https://example.com"]).matches("login.example.com"));
    }

    #[test]
    fn ignores_www() {
        assert!(item(&["https://www.example.com"]).matches("example.com"));
    }

    #[test]
    fn rejects_an_unrelated_host() {
        assert!(!item(&["https://example.com"]).matches("example.org"));
        assert!(!item(&["https://example.com"]).matches("notexample.com"));
        assert!(!item(&[]).matches("example.com"));
    }
}
