mod helpers;
mod kinfo;
mod peer;
mod proc_info;
mod signing_info;

use std::collections::HashSet;
use std::fmt;

use objc2_security::SecCode;
use serde::{Deserialize, Serialize};

use crate::audit::Actor;
use crate::core::provenance::helpers::get_parent_pid;
pub use crate::core::provenance::peer::{PeerError, PeerIdentity, PeerPolicy};
use crate::core::provenance::proc_info::ProcInfo;

pub struct Provenance {
    proc_info: Vec<ProcInfo>,
}

/// One process in a resolved caller chain, with the detail a prompt needs to
/// let the user inspect an unexpected caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessNode {
    pub command: String,
    pub executable: Option<String>,
    pub pid: u32,
    pub bundle_id: Option<String>,
    pub team_id: Option<String>,
    /// Verified code identity. See [`ProcInfo::code_id`].
    #[serde(default)]
    pub code_id: Option<String>,
}

/// An identity for a whole caller chain, for keying approvals that are reused
/// across requests. Two chains share an identity only when every user-visible
/// process in them runs the same verified code, in the same order.
///
/// `None` when the chain is empty or any process in it could not be verified.
/// A request with no identity must not reuse an approval.
///
/// Ancestors are found by parent pid, so a parent that exits while the chain
/// is resolved can be replaced by an unrelated process that reuses its pid.
pub fn chain_identity(chain: &[ProcessNode]) -> Option<String> {
    if chain.is_empty() {
        return None;
    }
    chain
        .iter()
        .map(|node| node.code_id.as_deref())
        .collect::<Option<Vec<_>>>()
        .map(|ids| ids.join("\n"))
}

impl Provenance {
    pub fn resolve(pid: u32) -> Self {
        Provenance {
            proc_info: Self::get_process_chain(pid),
        }
    }

    #[allow(dead_code)]
    pub fn resolve_current() -> Option<Self> {
        let pid = std::process::id();
        Some(Self::resolve(pid))
    }

    pub fn resolve_current_parent() -> Option<Self> {
        ProcInfo::lookup(std::process::id())?
            .parent_pid()
            .map(Self::resolve)
    }

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

    /// Walk parent pids from `pid`, innermost first. A process we cannot get
    /// a SecCode for (e.g. `login`, which is SIP-restricted and runs as
    /// uid 0) still yields its ppid via `pidinfo`, so the walk continues
    /// past it instead of stopping there.
    fn get_process_chain(pid: u32) -> Vec<ProcInfo> {
        const MAX_DEPTH: usize = 32;

        let mut out = Vec::new();
        let mut visited = HashSet::new();
        let mut current = Some(pid);

        while let Some(current_pid) = current {
            if out.len() >= MAX_DEPTH || !visited.insert(current_pid) {
                break;
            }

            let (proc_info, parent_pid) = match ProcInfo::lookup(current_pid) {
                Some(info) => {
                    let parent_pid = info.parent_pid();
                    (info, parent_pid)
                },
                None => {
                    let parent_pid = Self::lookup_parent_pid(current_pid);
                    (
                        ProcInfo::pid_and_parent(current_pid, parent_pid),
                        parent_pid,
                    )
                },
            };
            out.push(proc_info);

            current = match parent_pid {
                Some(0) | Some(1) | None => None,
                Some(ppid) if ppid == current_pid => None,
                Some(ppid) => Some(ppid),
            };
        }

        out
    }

    /// Get the parent pid for `pid` without needing a `SecCode`, so this
    /// works across uids.
    fn lookup_parent_pid(pid: u32) -> Option<u32> {
        get_parent_pid(pid)
            .inspect_err(|e| log::error!("lookup_parent_pid({pid}): {e}"))
            .ok()
    }

    /// Get a short, human-readable name for the caller, assuming to be the last
    /// user-visible process in the chain (i.e. excluding system processes).
    pub fn caller(&self) -> Option<String> {
        let visible_procs = self
            .proc_info
            .iter()
            .filter(|p| p.is_user_visible())
            .collect::<Vec<_>>();

        let head = visible_procs.first()?;
        let tail = visible_procs.last()?;
        if head.pid() == tail.pid() {
            Some(format!("{head}"))
        } else {
            Some(format!("{tail} ({head})"))
        }
    }

    /// The user-visible process chain, innermost first.
    pub fn chain_labels(&self) -> Vec<String> {
        self.proc_info
            .iter()
            .filter(|p| p.is_user_visible())
            .map(|p| p.command().to_string())
            .collect()
    }

    /// The user-visible process chain with per-process detail, innermost first.
    pub fn chain_nodes(&self) -> Vec<ProcessNode> {
        self.proc_info
            .iter()
            .filter(|p| p.is_user_visible())
            .map(|p| ProcessNode {
                command: p.command().to_string(),
                executable: p.executable_path(),
                pid: p.pid(),
                bundle_id: p.bundle_id(),
                team_id: p.team_id(),
                code_id: p.code_id().map(String::from),
            })
            .collect()
    }

    fn head(&self) -> Option<&ProcInfo> {
        self.proc_info.iter().find(|p| p.is_user_visible())
    }

    /// pid of the innermost user-visible process.
    pub fn head_pid(&self) -> Option<u32> {
        self.head().map(|p| p.pid())
    }

    /// Executable path of the innermost user-visible process.
    pub fn head_executable(&self) -> Option<String> {
        self.head().and_then(|p| p.executable_path())
    }

    /// Bundle identifier of the innermost user-visible process.
    pub fn head_bundle_id(&self) -> Option<String> {
        self.head().and_then(|p| p.bundle_id())
    }

    /// Team identifier of the innermost user-visible process.
    pub fn head_team_id(&self) -> Option<String> {
        self.head().and_then(|p| p.team_id())
    }
}

impl Actor {
    /// Build an actor from an identified socket peer.
    pub fn from_peer(peer: &PeerIdentity) -> Self {
        Actor {
            caller: peer.caller(),
            pid: Some(peer.pid()),
            executable: peer.executable(),
            bundle_id: peer.bundle_id(),
            team_id: peer.team_id(),
            chain: peer.provenance().chain_labels(),
            chain_detail: peer.provenance().chain_nodes(),
        }
    }

    /// Build an actor from a resolved process chain.
    pub fn from_provenance(provenance: &Provenance) -> Self {
        Actor {
            caller: provenance.caller(),
            pid: provenance.head_pid(),
            executable: provenance.head_executable(),
            bundle_id: provenance.head_bundle_id(),
            team_id: provenance.head_team_id(),
            chain: provenance.chain_labels(),
            chain_detail: provenance.chain_nodes(),
        }
    }
}

impl fmt::Debug for Provenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            let chain = self
                .proc_info
                .iter()
                .filter(|info| !info.is_system())
                .map(|info| format!("{info:#}"))
                .collect::<Vec<_>>()
                .join(" <- ");
            return write!(f, "{chain}");
        }
        f.debug_struct("Provenance")
            .field("proc_info", &self.proc_info)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(code_id: Option<&str>) -> ProcessNode {
        ProcessNode {
            command: "test".to_string(),
            executable: None,
            pid: 42,
            bundle_id: None,
            team_id: None,
            code_id: code_id.map(String::from),
        }
    }

    #[test]
    fn chain_identity_requires_every_node_verified() {
        assert_eq!(chain_identity(&[]), None);
        assert_eq!(chain_identity(&[node(Some("cdhash:aa")), node(None)]), None);
        assert_eq!(
            chain_identity(&[node(Some("cdhash:aa")), node(Some("path:/usr/bin/login"))]),
            Some("cdhash:aa\npath:/usr/bin/login".to_string())
        );
    }

    #[test]
    fn chain_identity_distinguishes_order() {
        let a = chain_identity(&[node(Some("cdhash:aa")), node(Some("cdhash:bb"))]);
        let b = chain_identity(&[node(Some("cdhash:bb")), node(Some("cdhash:aa"))]);
        assert_ne!(a, b);
    }

    /// The test binary is at least linker-signed, so it passes the validity
    /// check and gets a cdhash identity.
    #[test]
    fn current_process_has_a_verified_code_id() {
        let info = ProcInfo::lookup(std::process::id()).unwrap();
        let code_id = info.code_id().unwrap();
        assert!(code_id.starts_with("cdhash:"), "{code_id}");
        assert!(!info.is_system());
    }
}
