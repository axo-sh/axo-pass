mod helpers;
mod kinfo;
mod peer;
mod proc_info;
mod signing_info;

pub(crate) use helpers::{get_audit_token_for_pid, get_parent_pid};
use objc2_security::SecCode;
pub use peer::{PeerError, PeerIdentity, PeerPolicy, own_signing_info};
pub use proc_info::ProcInfo;

use crate::core::provenance::Provenance;

/// Our own team identifier, from our code signature. `None` for an unsigned or
/// ad-hoc signed local build.
pub fn team_identifier() -> Option<String> {
    own_signing_info()
        .map(|info| info.team_identifier)
        .filter(|team| !team.is_empty())
}

impl Provenance {
    /// Resolve the chain from a process whose SecCode is already in hand. The
    /// head of the chain is then the process that was identified, not whatever
    /// holds `pid` by the time the chain is walked.
    pub(crate) fn resolve_from_sec_code(pid: u32, code: &SecCode) -> Self {
        let Some(head) = ProcInfo::from_sec_code(pid, code) else {
            return Self::resolve(pid);
        };
        let parent_pid = head.parent_pid();
        let mut proc_info = vec![head];
        if let Some(parent_pid) = parent_pid {
            proc_info.extend(Self::get_process_chain(parent_pid));
        }
        Provenance { proc_info }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The test binary is at least linker-signed, so it passes the validity
    /// check and gets a cdhash identity.
    #[test]
    fn current_process_has_verified_code_id() {
        let info = ProcInfo::lookup(std::process::id()).unwrap();
        let code_id = info.code_id().unwrap();
        assert!(code_id.starts_with("cdhash:"), "{code_id}");
        assert!(info.verified());
        assert!(!info.is_system());
    }

    /// Xcode's git claims a team identifier but is signed by Apple's own
    /// certificate, which has no matching subject OU.
    #[test]
    fn apple_signed_xcode_git_verified() {
        use std::process::{Command, Stdio};

        let path = "/Applications/Xcode.app/Contents/Developer/usr/bin/git";
        if !std::path::Path::new(path).exists() {
            return;
        }
        // Reads stdin, so the process stays alive until stdin closes.
        let mut child = Command::new(path)
            .args(["hash-object", "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let info = ProcInfo::lookup(child.id());
        drop(child.stdin.take());
        child.wait().unwrap();
        assert!(info.unwrap().verified());
    }
}
