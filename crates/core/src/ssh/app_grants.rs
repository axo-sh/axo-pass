//! Lasting per-app access to SSH keys.
//!
//! A grant lets one signed app use one key without a prompt. Grants are kept in
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
use time::OffsetDateTime;

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
/// `fingerprint`, if any.
pub fn find_match<'a>(
    grants: &'a [AppGrant],
    fingerprint: &str,
    policy: KeyPolicy,
    chain: &[ProcessNode],
) -> Option<&'a AppGrant> {
    if policy != KeyPolicy::Default {
        return None;
    }
    chain_identity(chain)?;
    grants.iter().find(|grant| {
        grant.fingerprint == fingerprint && chain.iter().any(|node| grant.app.matches(node))
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

/// The grants for one key.
pub fn list_for(fingerprint: &str) -> Result<Vec<AppGrant>, KeychainError> {
    Ok(load()?
        .into_iter()
        .filter(|g| g.fingerprint == fingerprint)
        .collect())
}

/// Grant `app` lasting access to the key `fingerprint`. Granting an app that
/// already holds a grant for the key keeps the existing grant.
pub fn add(fingerprint: &str, app: GrantApp) -> Result<AppGrant, KeychainError> {
    let _lock = WRITE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut grants = load()?;
    if let Some(existing) = grants.iter().find(|g| {
        g.fingerprint == fingerprint
            && g.app.team_id == app.team_id
            && g.app.bundle_id == app.bundle_id
    }) {
        return Ok(existing.clone());
    }
    let grant = AppGrant {
        fingerprint: fingerprint.to_string(),
        app,
        created_at: OffsetDateTime::now_utc(),
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
        }
    }

    #[test]
    fn matches_granted_app_in_chain() {
        let grants = vec![fork_grant()];
        let found = find_match(&grants, FP, KeyPolicy::Default, &fork_chain());
        assert_eq!(found, Some(&grants[0]));
    }

    #[test]
    fn rejects_other_key() {
        let grants = vec![fork_grant()];
        assert!(find_match(&grants, "SHA256:other", KeyPolicy::Default, &fork_chain()).is_none());
    }

    #[test]
    fn rejects_hardware_enforced_key() {
        let grants = vec![fork_grant()];
        assert!(find_match(&grants, FP, KeyPolicy::AlwaysRequireAuth, &fork_chain()).is_none());
    }

    #[test]
    fn rejects_chain_with_unverified_node() {
        let grants = vec![fork_grant()];
        let mut chain = fork_chain();
        chain[1].code_id = None;
        assert!(find_match(&grants, FP, KeyPolicy::Default, &chain).is_none());
    }

    #[test]
    fn rejects_unverified_app_node() {
        let grants = vec![fork_grant()];
        let mut chain = fork_chain();
        chain[2].verified = false;
        assert!(find_match(&grants, FP, KeyPolicy::Default, &chain).is_none());
    }

    #[test]
    fn rejects_team_mismatch() {
        let grants = vec![fork_grant()];
        let mut chain = fork_chain();
        chain[2].team_id = Some("OTHERTEAM1".to_string());
        assert!(find_match(&grants, FP, KeyPolicy::Default, &chain).is_none());
    }

    #[test]
    fn rejects_bundle_mismatch() {
        let grants = vec![fork_grant()];
        let mut chain = fork_chain();
        chain[2].bundle_id = Some("com.example.Other".to_string());
        assert!(find_match(&grants, FP, KeyPolicy::Default, &chain).is_none());
    }

    #[test]
    fn rejects_empty_team_id() {
        let mut grant = fork_grant();
        grant.app.team_id = String::new();
        let mut chain = fork_chain();
        chain[2].team_id = Some(String::new());
        assert!(find_match(&[grant], FP, KeyPolicy::Default, &chain).is_none());
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
        let back: AppGrant = serde_json::from_value(json).unwrap();
        assert_eq!(back, fork_grant());
    }
}
