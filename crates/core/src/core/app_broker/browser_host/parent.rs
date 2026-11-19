//! Identify the browser that started the host, from the parent audit token.

use super::super::browsers::{Browser, browser_requirement};
use crate::core::provenance::{PeerIdentity, PeerPolicy, get_audit_token_for_pid, get_parent_pid};

/// The verified parent: which browser it is, and its identity for the log.
pub(super) struct VerifiedParent {
    pub(super) browser: Browser,
    pub(super) peer: PeerIdentity,
}

/// Verify that the parent process is the main process of a browser in
/// [`Browser::ALL`], running as this user.
///
/// The token names one process instance, so the code signature checked is that
/// of the process the token was read from. The parent pid is read again after
/// the check. A changed parent means the original parent exited and the host
/// was reparented while the token was read, so the result is refused.
pub(super) fn verify_parent() -> Result<VerifiedParent, String> {
    let pid = std::process::id();
    let ppid = get_parent_pid(pid).map_err(|e| e.to_string())?;
    if ppid <= 1 {
        return Err(format!("No parent process (parent pid {ppid})"));
    }

    let token = get_audit_token_for_pid(ppid).map_err(|e| e.to_string())?;
    // Word 5 of an audit token is the pid.
    if token[5] != ppid {
        return Err(format!(
            "Audit token names pid {}, not the parent {ppid}",
            token[5]
        ));
    }

    let policy = PeerPolicy {
        same_user: true,
        requirement: Some(browser_requirement()),
        executable: None,
    };
    let peer = PeerIdentity::verify_audit_token(token, &policy).map_err(|e| e.to_string())?;

    let after = get_parent_pid(pid).map_err(|e| e.to_string())?;
    if after != ppid {
        return Err(format!(
            "Parent changed from {ppid} to {after} during the check"
        ));
    }

    let team = peer.team_id().unwrap_or_default();
    let browser = Browser::from_team_id(&team)
        .ok_or_else(|| format!("Parent team {team:?} is not a known browser"))?;
    Ok(VerifiedParent { browser, peer })
}

// Linux has no parent process lookup or code requirement yet.
#[cfg(all(test, macos))]
mod tests {
    use super::*;

    /// The test runner is started by cargo, which no browser team signs.
    #[test]
    fn refuses_non_browser_parent() {
        let error = verify_parent().err().expect("cargo is not a browser");
        assert!(error.contains("code requirement"), "{error}");
    }
}
