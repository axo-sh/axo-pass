use axo_pass_core::audit;
use axo_pass_core::core::app_broker::browser_grants::{self, GrantBrowser};
use axo_pass_core::ssh::app_grants;

use crate::*;

/// A browser that holds lasting permission to list logins. Mirrors
/// [`browser_grants::BrowserGrant`].
#[derive(uniffi::Record, Clone)]
pub struct BrowserListingGrant {
    pub name: String,
    pub team_id: String,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds. `None` for a grant with no expiration.
    pub expires_at: Option<i64>,
}

impl From<browser_grants::BrowserGrant> for BrowserListingGrant {
    fn from(grant: browser_grants::BrowserGrant) -> Self {
        BrowserListingGrant {
            name: grant.browser.name,
            team_id: grant.browser.team_id,
            created_at: grant.created_at.unix_timestamp(),
            expires_at: grant.expires_at.map(|t| t.unix_timestamp()),
        }
    }
}

/// Record an `auth.browser_grant_add` or `auth.browser_grant_remove` event.
/// `expires_in_seconds` is the added grant's expiration, if it has one.
fn record_browser_grant_event(
    action: audit::Action,
    browser: &GrantBrowser,
    expires_in_seconds: Option<u32>,
    peer: Option<RequestActor>,
    result: &Result<(), FfiError>,
) {
    let mut event = audit::AuditEvent::new(
        audit::process_source(),
        action,
        if result.is_ok() {
            audit::Outcome::Succeeded
        } else {
            audit::Outcome::Failed
        },
    )
    .detail("grant", format!("browser:{}", browser.name))
    .detail("browser", browser.name.clone())
    .detail("browser_team_id", browser.team_id.clone())
    .maybe_actor(peer.map(audit::Actor::from));
    if let Some(seconds) = expires_in_seconds {
        event = event.detail("expires_in", seconds.to_string());
    }
    if let Err(e) = result {
        event = event.message(e.to_string());
    }
    audit::record(event);
}

#[uniffi::export(async_runtime = "tokio")]
impl AxoPass {
    /// The browsers with lasting permission to list logins.
    pub async fn list_browser_listing_grants(&self) -> Result<Vec<BrowserListingGrant>, FfiError> {
        tokio::task::spawn_blocking(browser_grants::list)
            .await
            .map_err(|e| FfiError::Internal(e.to_string()))?
            .map(|grants| grants.into_iter().map(Into::into).collect())
            .map_err(FfiError::from)
    }

    /// Let a browser list logins without a prompt while the app is unlocked.
    /// `peer` is the requester the grant was given from, for the audit event.
    pub async fn add_browser_listing_grant(
        &self,
        name: String,
        team_id: String,
        // Seconds until the grant expires, from 30 seconds to 30 days. `None`
        // for a grant with no expiration.
        expires_in_seconds: Option<u32>,
        peer: Option<RequestActor>,
    ) -> Result<(), FfiError> {
        let browser = GrantBrowser { team_id, name };
        let granted = browser.clone();
        let result = tokio::task::spawn_blocking(move || {
            let expires_in = expires_in_seconds
                .map(app_grants::expiration_from_seconds)
                .transpose()
                .map_err(FfiError::InvalidInput)?;
            browser_grants::add(granted, expires_in)
                .map(|_| ())
                .map_err(FfiError::from)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?;

        record_browser_grant_event(
            audit::Action::AuthBrowserGrantAdd,
            &browser,
            expires_in_seconds,
            peer,
            &result,
        );
        result
    }

    /// Remove a browser's permission to list logins without a prompt.
    pub async fn remove_browser_listing_grant(
        &self,
        name: String,
        team_id: String,
    ) -> Result<(), FfiError> {
        let browser = GrantBrowser { team_id, name };
        let removed = browser.clone();
        let result = tokio::task::spawn_blocking(move || {
            browser_grants::remove(&removed.team_id, &removed.name)
                .map(|_| ())
                .map_err(FfiError::from)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?;

        record_browser_grant_event(
            audit::Action::AuthBrowserGrantRemove,
            &browser,
            None,
            None,
            &result,
        );
        result
    }
}
