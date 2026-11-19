//! Linux stubs for the process identity types in `provenance`.
//!
//! The types match the macOS ones in `peer.rs` and `proc_info.rs`. Peer
//! identification fails with [`PeerError::Unsupported`] until the Linux peer
//! check exists. Process lookup finds nothing.

use std::fmt::{self, Display};
use std::path::PathBuf;

use thiserror::Error;

use crate::core::provenance::Provenance;

/// Requirements a peer must satisfy.
#[derive(Debug, Clone, Default)]
pub struct PeerPolicy {
    /// Require the peer to run as the same effective user as us.
    pub same_user: bool,

    /// Code requirement in text form. macOS only, ignored on Linux.
    pub requirement: Option<String>,

    /// The peer's main executable must be this exact file.
    pub executable: Option<PathBuf>,
}

impl PeerPolicy {
    /// Accept only `executable_name` beside this process's own executable.
    pub fn sibling_executable(executable_name: &str) -> Self {
        let executable = std::env::current_exe()
            .ok()
            .and_then(|exe| Some(exe.parent()?.join(executable_name)));
        PeerPolicy {
            same_user: true,
            requirement: None,
            executable,
        }
    }

    /// Accept only the executable at `relative` in an app bundle. There are no
    /// bundles on Linux, so this policy accepts no executable.
    pub fn bundled_executable(_relative: &str) -> Self {
        PeerPolicy {
            same_user: true,
            requirement: None,
            executable: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum PeerError {
    #[error("Peer identification is not supported on this platform")]
    Unsupported,

    #[error("Could not read the peer's credentials: {0}")]
    AuditToken(#[from] std::io::Error),

    #[error("Peer runs as uid {peer}, not {ours}")]
    ForeignUser { peer: u32, ours: u32 },

    #[error("Could not identify the peer process: {0}")]
    Unidentified(String),

    #[error("Peer failed the code requirement: {0}")]
    RequirementFailed(String),

    #[error("Peer runs {actual}, not {expected}")]
    WrongExecutable { expected: String, actual: String },
}

impl PeerError {
    /// The peer closed its end before it could be identified.
    pub fn is_disconnected(&self) -> bool {
        matches!(self, Self::AuditToken(e) if e.raw_os_error() == Some(libc::ENOTCONN))
    }
}

/// An identified peer. No value of this type exists on Linux yet.
pub struct PeerIdentity {
    pid: u32,
    provenance: Provenance,
}

impl PeerIdentity {
    /// Describe the peer without applying any policy to it.
    pub fn identify(_fd: std::os::fd::RawFd) -> Result<Self, PeerError> {
        Err(PeerError::Unsupported)
    }

    /// Describe the peer, failing if it does not satisfy `policy`.
    pub fn verify(_fd: std::os::fd::RawFd, _policy: &PeerPolicy) -> Result<Self, PeerError> {
        Err(PeerError::Unsupported)
    }

    /// Describe a process from a macOS audit token.
    pub fn verify_audit_token(_token: [u32; 8], _policy: &PeerPolicy) -> Result<Self, PeerError> {
        Err(PeerError::Unsupported)
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn label(&self) -> Option<String> {
        None
    }

    pub fn caller(&self) -> Option<String> {
        self.provenance.caller()
    }

    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    pub fn executable(&self) -> Option<String> {
        None
    }

    pub fn bundle_id(&self) -> Option<String> {
        None
    }

    pub fn team_id(&self) -> Option<String> {
        None
    }
}

impl fmt::Debug for PeerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerIdentity")
            .field("pid", &self.pid)
            .finish()
    }
}

/// Parent pid of `pid`.
pub fn get_parent_pid(_pid: u32) -> anyhow::Result<u32> {
    anyhow::bail!("process lookup is not supported on this platform")
}

/// macOS audit token of `pid`.
pub fn get_audit_token_for_pid(_pid: u32) -> anyhow::Result<[u32; 8]> {
    anyhow::bail!("audit tokens are not supported on this platform")
}

/// One process in a caller chain. Lookup finds nothing on Linux.
#[derive(Debug)]
pub struct ProcInfo {
    pid: u32,
    parent_pid: Option<u32>,
}

impl ProcInfo {
    pub fn pid_and_parent(pid: u32, parent_pid: Option<u32>) -> Self {
        ProcInfo { pid, parent_pid }
    }

    pub fn lookup(_pid: u32) -> Option<Self> {
        None
    }

    pub fn verified(&self) -> bool {
        false
    }

    pub fn code_id(&self) -> Option<&str> {
        None
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn parent_pid(&self) -> Option<u32> {
        self.parent_pid
    }

    pub(crate) fn command(&self) -> &str {
        "?"
    }

    pub(crate) fn executable_path(&self) -> Option<String> {
        None
    }

    pub(crate) fn bundle_id(&self) -> Option<String> {
        None
    }

    pub(crate) fn team_id(&self) -> Option<String> {
        None
    }

    pub fn is_user_visible(&self) -> bool {
        !self.is_system()
    }

    pub fn is_system(&self) -> bool {
        self.pid == 0 || self.pid == 1
    }
}

impl Display for ProcInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.command())
    }
}
