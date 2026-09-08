mod helpers;
mod peer;
mod proc_info;
mod signing_info;

use std::fmt;

use objc2_security::SecCode;
use serde::{Deserialize, Serialize};

use crate::audit::Actor;
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

    /// Recursively get the process chain for a given pid
    fn get_process_chain(pid: u32) -> Vec<ProcInfo> {
        let Some(current_proc_info) = ProcInfo::lookup(pid) else {
            return vec![ProcInfo::pid_only(pid)];
        };
        let parent_pid = current_proc_info.parent_pid();
        let mut out = vec![current_proc_info];
        if let Some(parent_id) = parent_pid {
            out.extend(Self::get_process_chain(parent_id));
        }
        out
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
