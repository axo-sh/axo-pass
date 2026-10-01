//! Lasting per-app access to SSH keys.
//!
//! A grant lets one signed app use one key without a prompt, until it expires
//! (30 seconds to 12 hours) or indefinitely. Grants are kept in
//! the app's data-protection keychain, which the user and other processes
//! cannot edit, and are checked by the app broker before it prompts. Only keys
//! with [`KeyPolicy::Default`] can be granted: a key with a hardware access
//! control would prompt regardless.
//!
//! An app is identified by its team id and bundle id, which survive app
//! updates. Any process the app spawns (e.g. git hooks run by Fork) carries the
//! app in its caller chain and so inherits the grant.

use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::core::provenance::{ProcessNode, chain_identity};
use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::managed_key::KeyPolicy;
use crate::secrets::keychain::plain_item::PlainItem;

const SERVICE: &str = "com.breakfastlabs.frittata.ssh-app-grants";
const ACCOUNT: &str = "grants";

/// Serializes read-modify-write cycles on the grants item within this process.
static WRITE_LOCK: Mutex<()> = Mutex::new(());

/// An app that can hold a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantApp {
    pub team_id: String,
    pub bundle_id: String,
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppGrant {
    /// Canonical `SHA256:...` fingerprint of the key.
    pub fingerprint: String,
    #[serde(flatten)]
    pub app: GrantApp,
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

/// The shortest expiration a grant can have.
pub const MIN_EXPIRATION: Duration = Duration::seconds(30);
/// The longest expiration a grant can have, short of none at all.
pub const MAX_EXPIRATION: Duration = Duration::hours(12);

impl AppGrant {
    /// Whether the grant still applies at `now`.
    pub fn is_active(&self, now: OffsetDateTime) -> bool {
        self.expires_at.is_none_or(|expires_at| now < expires_at)
    }
}

impl GrantApp {
    fn matches(&self, node: &ProcessNode) -> bool {
        node.verified
            && !self.team_id.is_empty()
            && node.team_id.as_deref() == Some(self.team_id.as_str())
            && node.bundle_id.as_deref() == Some(self.bundle_id.as_str())
    }
}

/// The app a grant would be given to for a request from `chain`: the outermost
/// verified process with a team id and bundle id. `None` when any process in
/// the chain is unverified or no process qualifies.
pub fn candidate_app(chain: &[ProcessNode]) -> Option<GrantApp> {
    chain_identity(chain)?;
    chain
        .iter()
        .rev()
        .find(|node| {
            node.verified
                && node.team_id.as_deref().is_some_and(|t| !t.is_empty())
                && node.bundle_id.as_deref().is_some_and(|b| !b.is_empty())
        })
        .map(|node| GrantApp {
            team_id: node.team_id.clone().unwrap_or_default(),
            bundle_id: node.bundle_id.clone().unwrap_or_default(),
            display_name: node.command.clone(),
        })
}

/// The grant that authorizes a request from `chain` to sign with the key
/// `fingerprint` at `now`, if any. Expired grants never match.
pub fn find_match<'a>(
    grants: &'a [AppGrant],
    fingerprint: &str,
    policy: KeyPolicy,
    chain: &[ProcessNode],
    now: OffsetDateTime,
) -> Option<&'a AppGrant> {
    if policy != KeyPolicy::Default {
        return None;
    }
    chain_identity(chain)?;
    grants.iter().find(|grant| {
        grant.fingerprint == fingerprint
            && grant.is_active(now)
            && chain.iter().any(|node| grant.app.matches(node))
    })
}

fn item() -> PlainItem {
    PlainItem::new(SERVICE, ACCOUNT)
}

/// Every grant, for every key.
pub fn load() -> Result<Vec<AppGrant>, KeychainError> {
    match item().read()? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| KeychainError::Generic(anyhow::anyhow!("invalid app grants: {e}"))),
        None => Ok(Vec::new()),
    }
}

fn save(grants: &[AppGrant]) -> Result<(), KeychainError> {
    if grants.is_empty() {
        return item().delete();
    }
    let bytes = serde_json::to_vec(grants)
        .map_err(|e| KeychainError::Generic(anyhow::anyhow!("encoding app grants: {e}")))?;
    item().write(&bytes)
}

/// The grants for one key that still apply.
pub fn list_for(fingerprint: &str) -> Result<Vec<AppGrant>, KeychainError> {
    let now = OffsetDateTime::now_utc();
    Ok(load()?
        .into_iter()
        .filter(|g| g.fingerprint == fingerprint && g.is_active(now))
        .collect())
}

/// Check that `expires_in` is between [`MIN_EXPIRATION`] and
/// [`MAX_EXPIRATION`].
pub fn validate_expiration(expires_in: Duration) -> Result<(), String> {
    if (MIN_EXPIRATION..=MAX_EXPIRATION).contains(&expires_in) {
        Ok(())
    } else {
        Err(format!(
            "A grant expiration must be between {MIN_EXPIRATION} and {MAX_EXPIRATION}, \
             got {expires_in}."
        ))
    }
}

/// An expiration given in seconds, checked against the allowed range.
pub fn expiration_from_seconds(seconds: u32) -> Result<Duration, String> {
    let expires_in = Duration::seconds(i64::from(seconds));
    validate_expiration(expires_in)?;
    Ok(expires_in)
}

/// Grant `app` access to the key `fingerprint`, for `expires_in` or with no
/// expiration. Granting an app that already holds a grant for the key replaces
/// that grant. Expired grants are dropped on the way.
pub fn add(
    fingerprint: &str,
    app: GrantApp,
    expires_in: Option<Duration>,
) -> Result<AppGrant, KeychainError> {
    if let Some(expires_in) = expires_in {
        validate_expiration(expires_in).map_err(|e| KeychainError::Generic(anyhow::anyhow!(e)))?;
    }
    let now = OffsetDateTime::now_utc();
    let _lock = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut grants: Vec<AppGrant> = load()?
        .into_iter()
        .filter(|g| {
            g.is_active(now)
                && !(g.fingerprint == fingerprint
                    && g.app.team_id == app.team_id
                    && g.app.bundle_id == app.bundle_id)
        })
        .collect();
    let grant = AppGrant {
        fingerprint: fingerprint.to_string(),
        app,
        created_at: now,
        expires_at: expires_in.map(|d| now + d),
    };
    grants.push(grant.clone());
    save(&grants)?;
    Ok(grant)
}

/// Remove one app's grant for a key. Returns the removed grant.
pub fn remove(
    fingerprint: &str,
    team_id: &str,
    bundle_id: &str,
) -> Result<Option<AppGrant>, KeychainError> {
    let _lock = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut grants = load()?;
    let Some(index) = grants.iter().position(|g| {
        g.fingerprint == fingerprint && g.app.team_id == team_id && g.app.bundle_id == bundle_id
    }) else {
        return Ok(None);
    };
    let removed = grants.remove(index);
    save(&grants)?;
    Ok(Some(removed))
}

/// Remove every grant for a key, for when the key is deleted.
pub fn remove_all_for(fingerprint: &str) -> Result<Vec<AppGrant>, KeychainError> {
    let _lock = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let grants = load()?;
    let (removed, kept): (Vec<_>, Vec<_>) = grants
        .into_iter()
        .partition(|g| g.fingerprint == fingerprint);
    if !removed.is_empty() {
        save(&kept)?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "SHA256:abc";
    /// 2026-10-01T12:00:00Z.
    const NOW: OffsetDateTime = match OffsetDateTime::from_unix_timestamp(1_790_856_000) {
        Ok(t) => t,
        Err(_) => panic!("invalid timestamp"),
    };

    fn node(command: &str, bundle_id: Option<&str>, team_id: Option<&str>) -> ProcessNode {
        ProcessNode {
            command: command.to_string(),
            executable: None,
            pid: 1,
            bundle_id: bundle_id.map(String::from),
            team_id: team_id.map(String::from),
            code_id: Some(format!("cdhash:{command}")),
            verified: true,
        }
    }

    fn fork_chain() -> Vec<ProcessNode> {
        vec![
            node("ssh", None, None),
            node("git", None, None),
            node("Fork", Some("com.DanPristupov.Fork"), Some("Q6M7LEEA66")),
        ]
    }

    fn fork_grant() -> AppGrant {
        AppGrant {
            fingerprint: FP.to_string(),
            app: GrantApp {
                team_id: "Q6M7LEEA66".to_string(),
                bundle_id: "com.DanPristupov.Fork".to_string(),
                display_name: "Fork".to_string(),
            },
            created_at: OffsetDateTime::UNIX_EPOCH,
            expires_at: None,
        }
    }

    #[test]
    fn expired_grant_does_not_match() {
        let mut grant = fork_grant();
        grant.expires_at = Some(NOW + Duration::seconds(30));
        let grants = vec![grant];
        assert!(find_match(&grants, FP, KeyPolicy::Default, &fork_chain(), NOW).is_some());
        let later = NOW + Duration::seconds(30);
        assert!(find_match(&grants, FP, KeyPolicy::Default, &fork_chain(), later).is_none());
    }

    #[test]
    fn grant_without_expiration_stays_active() {
        let grant = fork_grant();
        assert!(grant.is_active(NOW + Duration::days(365)));
    }

    #[test]
    fn expiration_bounds() {
        assert!(validate_expiration(Duration::seconds(29)).is_err());
        assert!(validate_expiration(MIN_EXPIRATION).is_ok());
        assert!(validate_expiration(MAX_EXPIRATION).is_ok());
        assert!(validate_expiration(MAX_EXPIRATION + Duration::seconds(1)).is_err());
    }

    #[test]
    fn expiration_json_round_trip() {
        let mut grant = fork_grant();
        grant.expires_at = Some(NOW + Duration::hours(1));
        let json = serde_json::to_value(&grant).unwrap();
        assert_eq!(json["expires_at"], "2026-10-01T13:00:00Z");
        let back: AppGrant = serde_json::from_value(json).unwrap();
        assert_eq!(back, grant);
    }

    #[test]
    fn matches_granted_app_in_chain() {
        let grants = vec![fork_grant()];
        let found = find_match(&grants, FP, KeyPolicy::Default, &fork_chain(), NOW);
        assert_eq!(found, Some(&grants[0]));
    }

    #[test]
    fn rejects_other_key() {
        let grants = vec![fork_grant()];
        assert!(
            find_match(
                &grants,
                "SHA256:other",
                KeyPolicy::Default,
                &fork_chain(),
                NOW
            )
            .is_none()
        );
    }

    #[test]
    fn rejects_hardware_enforced_key() {
        let grants = vec![fork_grant()];
        assert!(
            find_match(
                &grants,
                FP,
                KeyPolicy::AlwaysRequireAuth,
                &fork_chain(),
                NOW
            )
            .is_none()
        );
    }

    #[test]
    fn rejects_chain_with_unverified_node() {
        let grants = vec![fork_grant()];
        let mut chain = fork_chain();
        chain[1].code_id = None;
        assert!(find_match(&grants, FP, KeyPolicy::Default, &chain, NOW).is_none());
    }

    #[test]
    fn rejects_unverified_app_node() {
        let grants = vec![fork_grant()];
        let mut chain = fork_chain();
        chain[2].verified = false;
        assert!(find_match(&grants, FP, KeyPolicy::Default, &chain, NOW).is_none());
    }

    #[test]
    fn rejects_team_mismatch() {
        let grants = vec![fork_grant()];
        let mut chain = fork_chain();
        chain[2].team_id = Some("OTHERTEAM1".to_string());
        assert!(find_match(&grants, FP, KeyPolicy::Default, &chain, NOW).is_none());
    }

    #[test]
    fn rejects_bundle_mismatch() {
        let grants = vec![fork_grant()];
        let mut chain = fork_chain();
        chain[2].bundle_id = Some("com.example.Other".to_string());
        assert!(find_match(&grants, FP, KeyPolicy::Default, &chain, NOW).is_none());
    }

    #[test]
    fn rejects_empty_team_id() {
        let mut grant = fork_grant();
        grant.app.team_id = String::new();
        let mut chain = fork_chain();
        chain[2].team_id = Some(String::new());
        assert!(find_match(&[grant], FP, KeyPolicy::Default, &chain, NOW).is_none());
    }

    #[test]
    fn candidate_is_outermost_signed_app() {
        let mut chain = fork_chain();
        chain.insert(
            1,
            node("helper", Some("com.example.helper"), Some("HELPERTEAM")),
        );
        let app = candidate_app(&chain).unwrap();
        assert_eq!(app.bundle_id, "com.DanPristupov.Fork");
        assert_eq!(app.display_name, "Fork");
    }

    #[test]
    fn no_candidate_without_team_id() {
        let chain = vec![
            node("ssh", None, None),
            node("Terminal", Some("com.apple.Terminal"), None),
        ];
        assert!(candidate_app(&chain).is_none());
    }

    #[test]
    fn no_candidate_for_unverified_chain() {
        let mut chain = fork_chain();
        chain[0].code_id = None;
        assert!(candidate_app(&chain).is_none());
    }

    #[test]
    fn grant_json_is_flat() {
        let json = serde_json::to_value(fork_grant()).unwrap();
        assert_eq!(json["fingerprint"], FP);
        assert_eq!(json["bundle_id"], "com.DanPristupov.Fork");
        assert_eq!(json["team_id"], "Q6M7LEEA66");
        assert_eq!(json["created_at"], "1970-01-01T00:00:00Z");
        assert!(json.get("expires_at").is_none());
        let back: AppGrant = serde_json::from_value(json).unwrap();
        assert_eq!(back, fork_grant());
    }
}
