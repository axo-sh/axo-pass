//! iOS process identity types for `provenance`.
//!
//! The types match the macOS ones in `peer.rs` and `proc_info.rs`. An iOS app
//! has no broker socket, so peer identification refuses every client. Process
//! lookup finds nothing. The team identifier is the one real value, since the
//! App Group identifier needs it.

use std::fmt::{self, Display};
use std::path::PathBuf;
use std::ptr::{self, NonNull};
use std::sync::OnceLock;

use objc2_core_foundation::{CFBoolean, CFDictionary, CFMutableDictionary, CFString, CFType};
use objc2_security::{
    SecItemAdd, SecItemCopyMatching, errSecItemNotFound, errSecSuccess, kSecAttrAccessGroup,
    kSecAttrAccessible, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, kSecAttrAccount,
    kSecAttrService, kSecClass, kSecClassGenericPassword, kSecReturnAttributes,
};
use thiserror::Error;

use crate::core::objc_helpers::dict_proxy::CFDictionaryProxy;
use crate::core::provenance::Provenance;

/// Service of the keychain item that reveals the access group prefix.
const PROBE_SERVICE: &str = "com.breakfastlabs.frittata.team-probe";

/// Our own team identifier, from the keychain access group of our signature.
/// `None` if the keychain gives no access group.
///
/// The first access group of an app is `<team>.<bundle id>`. A new keychain
/// item that names no group lands in it, and its attributes report the
/// group.
pub fn team_identifier() -> Option<String> {
    static TEAM: OnceLock<Option<String>> = OnceLock::new();
    TEAM.get_or_init(probe_team).clone()
}

fn probe_team() -> Option<String> {
    let group = probe_access_group()
        .inspect_err(|e| log::warn!("Could not read the keychain access group: {e}"))
        .ok()?;
    let (team, _) = group.split_once('.')?;
    (!team.is_empty()).then(|| team.to_string())
}

/// Access group of the probe item. Creates the item if it does not exist.
fn probe_access_group() -> anyhow::Result<String> {
    unsafe {
        let query = CFMutableDictionary::<CFString, CFType>::empty();
        query.add(kSecClass, kSecClassGenericPassword);
        query.add(kSecAttrService, &CFString::from_str(PROBE_SERVICE));
        query.add(kSecAttrAccount, &CFString::from_str("team"));
        query.add(kSecReturnAttributes, CFBoolean::new(true));

        let mut ret: *const CFType = ptr::null();
        let mut status = SecItemCopyMatching(query.as_opaque(), &mut ret);
        if status == errSecItemNotFound {
            query.add(
                kSecAttrAccessible,
                kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            );
            ret = ptr::null();
            status = SecItemAdd(query.as_opaque(), &mut ret);
        }
        if status != errSecSuccess {
            anyhow::bail!("keychain probe failed: {status}");
        }
        let Some(ret) = NonNull::new(ret.cast_mut()) else {
            anyhow::bail!("keychain probe returned no attributes");
        };
        // Both calls follow the Create Rule, so the proxy owns the result.
        let attributes = CFDictionaryProxy::from_raw(ret.as_ptr().cast::<CFDictionary>().cast_const())
            .ok_or_else(|| anyhow::anyhow!("keychain probe returned no attributes"))?;
        attributes
            .get_string(kSecAttrAccessGroup.to_string())
            .ok_or_else(|| anyhow::anyhow!("keychain item has no access group"))
    }
}

/// Requirements a peer must satisfy.
#[derive(Debug, Clone, Default)]
pub struct PeerPolicy {
    /// Require the peer to run as the same effective user as us.
    pub same_user: bool,

    /// Code requirement in text form. macOS only, ignored on iOS.
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

    /// Accept only the executable at `relative` in an app bundle. No peer is
    /// accepted on iOS, so this policy accepts no executable.
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

/// An identified peer. No value of this type exists on iOS.
pub struct PeerIdentity {
    pid: u32,
    provenance: Provenance,
}

impl PeerIdentity {
    /// Describe the peer without applying any policy to it. Always refuses.
    pub fn identify(_fd: std::os::fd::RawFd) -> Result<Self, PeerError> {
        Err(PeerError::Unsupported)
    }

    /// Describe the peer, failing if it does not satisfy `policy`. Always
    /// refuses.
    pub fn verify(_fd: std::os::fd::RawFd, _policy: &PeerPolicy) -> Result<Self, PeerError> {
        Err(PeerError::Unsupported)
    }

    /// Describe a process from a macOS audit token. Always refuses.
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
#[cfg(feature = "desktop")]
pub fn get_audit_token_for_pid(_pid: u32) -> anyhow::Result<[u32; 8]> {
    anyhow::bail!("audit tokens are not supported on this platform")
}

/// One process in a caller chain. Lookup finds nothing on iOS.
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
