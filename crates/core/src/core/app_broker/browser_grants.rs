//! Lasting permission for a browser to list logins without a prompt.
//!
//! A grant covers listing only. A fill, a one-time code, a save, and a password
//! update always prompt. The grant answers only while the app is unlocked,
//! since the vaults can be read only on the app's authenticated context.
//!
//! A browser is identified by its name and the team id the browser host
//! verified. The extension id the browser reports is not verified, so it is not
//! part of the grant. Grants are kept in the app's data-protection keychain, as
//! the SSH app grants are.

use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::plain_item::PlainItem;
use crate::ssh::app_grants;

const SERVICE: &str = "com.breakfastlabs.frittata.browser-listing-grants";
const ACCOUNT: &str = "grants";

/// Serializes read-modify-write cycles on the grants item within this process.
static WRITE_LOCK: Mutex<()> = Mutex::new(());

/// A browser that can hold a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantBrowser {
    pub team_id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserGrant {
    #[serde(flatten)]
    pub browser: GrantBrowser,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When the grant stops applying. `None` for a grant with no expiration.
    #[serde(
        default,
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub expires_at: Option<OffsetDateTime>,
}

impl BrowserGrant {
    /// Whether the grant still applies at `now`.
    pub fn is_active(&self, now: OffsetDateTime) -> bool {
        self.expires_at.is_none_or(|expires_at| now < expires_at)
    }
}

/// The grant that covers the browser `name` signed by `team_id` at `now`, if
/// any. Expired grants never match.
pub fn find_match<'a>(
    grants: &'a [BrowserGrant],
    name: &str,
    team_id: &str,
    now: OffsetDateTime,
) -> Option<&'a BrowserGrant> {
    if team_id.is_empty() {
        return None;
    }
    grants.iter().find(|grant| {
        grant.browser.team_id == team_id && grant.browser.name == name && grant.is_active(now)
    })
}

fn item() -> PlainItem {
    PlainItem::new(SERVICE, ACCOUNT)
}

/// Every grant, including expired ones.
pub fn load() -> Result<Vec<BrowserGrant>, KeychainError> {
    match item().read()? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| KeychainError::Generic(anyhow::anyhow!("invalid browser grants: {e}"))),
        None => Ok(Vec::new()),
    }
}

fn save(grants: &[BrowserGrant]) -> Result<(), KeychainError> {
    if grants.is_empty() {
        return item().delete();
    }
    let bytes = serde_json::to_vec(grants)
        .map_err(|e| KeychainError::Generic(anyhow::anyhow!("encoding browser grants: {e}")))?;
    item().write(&bytes)
}

/// The grants that still apply.
pub fn list() -> Result<Vec<BrowserGrant>, KeychainError> {
    let now = OffsetDateTime::now_utc();
    Ok(load()?.into_iter().filter(|g| g.is_active(now)).collect())
}

/// Whether a grant covers the browser `name` signed by `team_id` now.
pub fn is_granted(name: &str, team_id: &str) -> Result<bool, KeychainError> {
    let grants = load()?;
    Ok(find_match(&grants, name, team_id, OffsetDateTime::now_utc()).is_some())
}

/// Grant `browser` listing access, for `expires_in` or with no expiration.
/// A browser that already holds a grant has it replaced. Expired grants are
/// dropped on the way.
pub fn add(
    browser: GrantBrowser,
    expires_in: Option<Duration>,
) -> Result<BrowserGrant, KeychainError> {
    if browser.team_id.is_empty() {
        return Err(KeychainError::Generic(anyhow::anyhow!(
            "A browser without a signing team cannot hold a grant."
        )));
    }
    if let Some(expires_in) = expires_in {
        app_grants::validate_expiration(expires_in)
            .map_err(|e| KeychainError::Generic(anyhow::anyhow!(e)))?;
    }
    let now = OffsetDateTime::now_utc();
    let _lock = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut grants: Vec<BrowserGrant> = load()?
        .into_iter()
        .filter(|g| g.is_active(now) && g.browser != browser)
        .collect();
    let grant = BrowserGrant {
        browser,
        created_at: now,
        expires_at: expires_in.map(|d| now + d),
    };
    grants.push(grant.clone());
    save(&grants)?;
    Ok(grant)
}

/// Remove one browser's grant. Returns the removed grant.
pub fn remove(team_id: &str, name: &str) -> Result<Option<BrowserGrant>, KeychainError> {
    let _lock = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut grants = load()?;
    let Some(index) = grants
        .iter()
        .position(|g| g.browser.team_id == team_id && g.browser.name == name)
    else {
        return Ok(None);
    };
    let removed = grants.remove(index);
    save(&grants)?;
    Ok(Some(removed))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-10-01T12:00:00Z.
    const NOW: OffsetDateTime = match OffsetDateTime::from_unix_timestamp(1_790_856_000) {
        Ok(t) => t,
        Err(_) => panic!("invalid timestamp"),
    };

    fn firefox_grant(expires_at: Option<OffsetDateTime>) -> BrowserGrant {
        BrowserGrant {
            browser: GrantBrowser {
                team_id: "43AQ936H96".to_string(),
                name: "Firefox".to_string(),
            },
            created_at: NOW - Duration::hours(1),
            expires_at,
        }
    }

    #[test]
    fn matches_granted_browser() {
        let grants = [firefox_grant(None)];
        assert!(find_match(&grants, "Firefox", "43AQ936H96", NOW).is_some());
    }

    #[test]
    fn expired_grant_does_not_match() {
        let grants = [firefox_grant(Some(NOW - Duration::seconds(1)))];
        assert!(find_match(&grants, "Firefox", "43AQ936H96", NOW).is_none());
        let grants = [firefox_grant(Some(NOW + Duration::seconds(1)))];
        assert!(find_match(&grants, "Firefox", "43AQ936H96", NOW).is_some());
    }

    #[test]
    fn rejects_other_browser() {
        let grants = [firefox_grant(None)];
        assert!(find_match(&grants, "Chrome", "43AQ936H96", NOW).is_none());
        assert!(find_match(&grants, "Firefox", "EQHXZ8M8AV", NOW).is_none());
    }

    #[test]
    fn rejects_empty_team_id() {
        let mut grant = firefox_grant(None);
        grant.browser.team_id = String::new();
        assert!(find_match(&[grant], "Firefox", "", NOW).is_none());
    }

    #[test]
    fn grant_json_round_trip() {
        let grant = firefox_grant(Some(NOW + Duration::hours(1)));
        let json = serde_json::to_string(&grant).unwrap();
        assert!(json.contains("\"team_id\":\"43AQ936H96\""));
        assert_eq!(serde_json::from_str::<BrowserGrant>(&json).unwrap(), grant);
    }
}
