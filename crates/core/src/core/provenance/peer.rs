//! Identifies the process on the other end of a Unix domain socket.
//!
//! File permissions bound a socket to one user, so on a personal Mac any code
//! the user runs can connect. The signing broker needs more than that, so it
//! identifies the peer and checks it against a policy.
//!
//! Identification starts from the peer's audit token rather than its pid.
//! `getsockopt(LOCAL_PEERTOKEN)` reports the token of the process that opened
//! the connection, and the token names that specific process instance. A pid
//! read from the same socket can be recycled onto an unrelated process between
//! reading it and looking it up.

use std::fmt;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::core::provenance::Provenance;
use crate::core::provenance::helpers::{
    check_requirement, get_sec_code_for_audit_token, get_sec_code_for_self,
    get_static_code_for_sec_code,
};
use crate::core::provenance::signing_info::SigningInfo;

// Socket option level and name for the peer's audit token. From `sys/un.h`,
// which libc does not expose.
const SOL_LOCAL: libc::c_int = 0;
const LOCAL_PEERTOKEN: libc::c_int = 0x006;

/// Requirements a peer must satisfy. Every field is optional; a default policy
/// checks nothing and only reports who connected.
#[derive(Debug, Clone, Default)]
pub struct PeerPolicy {
    /// Require the peer to run as the same effective user as us.
    pub same_user: bool,

    /// A code requirement in text form the peer's running code must satisfy,
    /// e.g. `anchor apple generic and certificate leaf[subject.OU] = "TEAMID"`.
    pub requirement: Option<String>,

    /// The peer's main executable must be this exact file.
    pub executable: Option<PathBuf>,
}

impl PeerPolicy {
    /// Accept only `executable_name` sitting beside this process's own
    /// executable and signed by the same team.
    ///
    /// A process with no team identifier is an unsigned or ad-hoc signed local
    /// build. There is no anchor to check against, so the returned policy keeps
    /// the path and user checks and omits the code requirement.
    pub fn sibling_executable(executable_name: &str) -> Self {
        let signing_info = get_sec_code_for_self()
            .and_then(|code| get_static_code_for_sec_code(&code))
            .inspect_err(|e| log::warn!("Could not read our own code signature: {e}"))
            .ok()
            .and_then(|static_code| SigningInfo::from_sec_code(&static_code));

        let executable = signing_info
            .as_ref()
            .and_then(|info| info.main_executable.to_file_path().ok())
            .and_then(|path| Some(path.parent()?.join(executable_name)));

        let requirement = signing_info
            .as_ref()
            .map(|info| info.team_identifier.as_str())
            .filter(|team| !team.is_empty())
            .map(|team| {
                format!("anchor apple generic and certificate leaf[subject.OU] = \"{team}\"")
            });

        PeerPolicy {
            same_user: true,
            requirement,
            executable,
        }
    }
}

#[derive(Debug, Error)]
pub enum PeerError {
    #[error("Could not read the peer's audit token: {0}")]
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

/// An identified peer: which process connected, and what it is.
pub struct PeerIdentity {
    pid: u32,
    euid: u32,
    signing_info: Option<SigningInfo>,
    provenance: Provenance,
}

impl PeerIdentity {
    /// Describe the peer without applying any policy to it.
    pub fn identify(fd: RawFd) -> Result<Self, PeerError> {
        Self::verify(fd, &PeerPolicy::default())
    }

    /// Describe the peer, failing if it does not satisfy `policy`.
    pub fn verify(fd: RawFd, policy: &PeerPolicy) -> Result<Self, PeerError> {
        let token = AuditToken::for_peer(fd)?;

        if policy.same_user {
            let ours = unsafe { libc::geteuid() };
            if token.euid() != ours {
                return Err(PeerError::ForeignUser {
                    peer: token.euid(),
                    ours,
                });
            }
        }

        let code = get_sec_code_for_audit_token(token.as_bytes())
            .map_err(|e| PeerError::Unidentified(e.to_string()))?;

        // Check the requirement before reading anything else out of the peer,
        // so nothing reported by this function comes from rejected code.
        if let Some(requirement) = &policy.requirement {
            check_requirement(&code, requirement)
                .map_err(|e| PeerError::RequirementFailed(e.to_string()))?;
        }

        let signing_info = get_static_code_for_sec_code(&code)
            .map_err(|e| PeerError::Unidentified(e.to_string()))
            .map(|static_code| SigningInfo::from_sec_code(&static_code))?;

        if let Some(expected) = &policy.executable {
            let actual = signing_info
                .as_ref()
                .and_then(|info| info.main_executable.to_file_path().ok());
            let matches = actual
                .as_deref()
                .is_some_and(|actual| same_file(actual, expected));
            if !matches {
                return Err(PeerError::WrongExecutable {
                    expected: expected.display().to_string(),
                    actual: actual.map_or("?".to_string(), |p| p.display().to_string()),
                });
            }
        }

        let pid = token.pid();
        Ok(PeerIdentity {
            pid,
            euid: token.euid(),
            signing_info,
            provenance: Provenance::resolve_from_sec_code(pid, &code),
        })
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// A short, human-readable name for the peer itself.
    pub fn label(&self) -> Option<String> {
        self.signing_info.as_ref().map(|info| info.display_label())
    }

    /// A short, human-readable name for the root of the peer's process chain.
    /// This is the peer's own ancestry, so it names the requesting application
    /// only when that application started the peer. A long-running daemon is
    /// started by launchd, so its chain leads there instead.
    pub fn caller(&self) -> Option<String> {
        self.provenance.caller()
    }
}

impl fmt::Debug for PeerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            return write!(f, "pid {}: {:#?}", self.pid, self.provenance);
        }
        f.debug_struct("PeerIdentity")
            .field("pid", &self.pid)
            .field("euid", &self.euid)
            .field("signing_info", &self.signing_info)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    use super::*;

    /// Both ends of a socket pair are this process, so identification should
    /// come back describing the test binary itself.
    #[test]
    fn identifies_the_peer_of_a_socket_pair() {
        let (ours, _theirs) = UnixStream::pair().unwrap();
        let peer = PeerIdentity::identify(ours.as_raw_fd()).unwrap();
        assert_eq!(peer.pid(), std::process::id());
    }

    /// The same-user check passes against ourselves, and the executable check
    /// resolves to this test binary.
    #[test]
    fn accepts_a_peer_matching_the_policy() {
        let (ours, _theirs) = UnixStream::pair().unwrap();
        let policy = PeerPolicy {
            same_user: true,
            requirement: None,
            executable: Some(std::env::current_exe().unwrap()),
        };
        PeerIdentity::verify(ours.as_raw_fd(), &policy).unwrap();
    }

    #[test]
    fn rejects_a_peer_running_a_different_executable() {
        let (ours, _theirs) = UnixStream::pair().unwrap();
        let policy = PeerPolicy {
            executable: Some(PathBuf::from("/usr/bin/true")),
            ..PeerPolicy::default()
        };
        let error = PeerIdentity::verify(ours.as_raw_fd(), &policy).unwrap_err();
        assert!(
            matches!(error, PeerError::WrongExecutable { .. }),
            "{error}"
        );
    }

    #[test]
    fn rejects_a_peer_failing_the_code_requirement() {
        let (ours, _theirs) = UnixStream::pair().unwrap();
        let policy = PeerPolicy {
            requirement: Some("identifier \"com.apple.finder\"".to_string()),
            ..PeerPolicy::default()
        };
        let error = PeerIdentity::verify(ours.as_raw_fd(), &policy).unwrap_err();
        assert!(matches!(error, PeerError::RequirementFailed(_)), "{error}");
    }
}

/// Compare two executable paths, resolving symlinks where possible so a build
/// staged through one is not treated as a different binary.
fn same_file(a: &Path, b: &Path) -> bool {
    let resolve = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    resolve(a) == resolve(b)
}

/// A macOS audit token: eight words naming one process instance. The field
/// order follows the `audit_token_to_*` accessors in `bsm/libbsm.h`.
#[derive(Clone, Copy)]
struct AuditToken([u32; 8]);

impl AuditToken {
    /// Read the token of the process on the other end of `fd`.
    fn for_peer(fd: RawFd) -> std::io::Result<Self> {
        let mut token = [0u32; 8];
        let mut len = std::mem::size_of_val(&token) as libc::socklen_t;
        let status = unsafe {
            libc::getsockopt(
                fd,
                SOL_LOCAL,
                LOCAL_PEERTOKEN,
                token.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if status != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if len as usize != std::mem::size_of_val(&token) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("LOCAL_PEERTOKEN returned {len} bytes"),
            ));
        }
        Ok(AuditToken(token))
    }

    fn euid(&self) -> u32 {
        self.0[1]
    }

    fn pid(&self) -> u32 {
        self.0[5]
    }

    fn as_bytes(&self) -> &[u8] {
        // SAFETY: reading a [u32; 8] as its own bytes, which is the layout the
        // audit guest attribute expects.
        unsafe {
            std::slice::from_raw_parts(self.0.as_ptr().cast::<u8>(), std::mem::size_of_val(&self.0))
        }
    }
}
