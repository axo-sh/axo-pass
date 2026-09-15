use std::fmt::{self, Display};

use libproc::proc_pid::pidpath;
use objc2_security::SecCode;

use crate::core::provenance::helpers::{
    check_requirement, check_valid, get_effective_uid, get_host_for_sec_code, get_parent_pid,
    get_sec_code_for_pid, get_static_code_for_sec_code,
};
use crate::core::provenance::signing_info::SigningInfo;

const APPLE_LOGIN_REQUIREMENT: &str = r#"anchor apple and identifier "com.apple.login""#;

#[derive(Debug)]
pub struct ProcInfo {
    pid: u32,
    parent_pid: Option<u32>,
    command: String,
    signing_info: Option<SigningInfo>,
    host: Option<SigningInfo>,

    /// A verified identity for the code this process runs, or `None` when it
    /// could not be verified. See [`ProcInfo::code_id`].
    code_id: Option<String>,

    /// See [`ProcInfo::verified`].
    verified: bool,

    /// True when the process is Apple's `login`, checked against a code
    /// requirement rather than read from the self-reported identifier.
    is_apple_login: bool,
}

impl ProcInfo {
    /// A process we could not get a SecCode for (e.g. it runs as another
    /// uid and is SIP-restricted), but whose ppid and executable path are
    /// still readable via sysctl/proc_pidpath so the walk can continue
    /// past it.
    pub fn pid_and_parent(pid: u32, parent_pid: Option<u32>) -> Self {
        let path = pidpath(pid as i32).ok();
        let command = path
            .as_deref()
            .and_then(|path| {
                std::path::Path::new(path)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
            })
            .unwrap_or_else(|| "?".to_string());

        // A process running as another user cannot be started or controlled by
        // code running as this user, so the kernel's record of its executable
        // path identifies it. A process running as this user must pass a
        // signature check instead, which this one did not get.
        let ours = unsafe { libc::geteuid() };
        let code_id = match get_effective_uid(pid) {
            Ok(uid) if uid != ours => path.map(|path| format!("path:{path}")),
            Ok(_) => None,
            Err(e) => {
                log::error!("ProcInfo::pid_and_parent({pid}) uid: {e}");
                None
            },
        };

        ProcInfo {
            pid,
            parent_pid,
            command,
            signing_info: None,
            host: None,
            // Nothing here is self-reported: the path and uid come from the
            // kernel.
            verified: code_id.is_some(),
            code_id,
            is_apple_login: false,
        }
    }

    pub fn lookup(pid: u32) -> Option<Self> {
        let code = get_sec_code_for_pid(pid)
            .inspect_err(|e| log::error!("ProcInfo lookup: {e}"))
            .ok()?;
        Self::from_sec_code(pid, &code)
    }

    /// Describe a process whose SecCode is already in hand, so the process is
    /// not looked up by pid a second time.
    pub fn from_sec_code(pid: u32, code: &SecCode) -> Option<Self> {
        let static_code = get_static_code_for_sec_code(code)
            .inspect_err(|e| log::error!("ProcInfo lookup: {e}"))
            .ok()?;

        // Get signing info for the executable
        let signing_info = SigningInfo::from_sec_code(&static_code);

        // get parent pid via sysctl(KERN_PROC_PID) rather than proc_pidinfo, so
        // this works even when `pid` runs as another uid (e.g. `login`, uid 0)
        let ppid = get_parent_pid(pid)
            .inspect_err(|e| log::error!("ProcInfo::from_sec_code({pid}) ppid: {e}"))
            .ok();

        // get the process host
        let host_signing_info = get_host_for_sec_code(code)
            .inspect_err(|e| log::error!("ProcInfo lookup host: {e}"))
            .ok()
            .and_then(|h| SigningInfo::from_sec_code(&h));

        // The cdhash is only an identity once the running code has been checked
        // against it. Everything else in the signing info is self-reported.
        let code_id = match check_valid(code) {
            Ok(()) => signing_info
                .as_ref()
                .and_then(|s| s.cdhash.as_ref())
                .map(|cdhash| format!("cdhash:{cdhash}")),
            Err(e) => {
                log::warn!("ProcInfo::from_sec_code({pid}) validity: {e}");
                None
            },
        };

        // The team identifier comes from an entitlement the binary sets itself,
        // so a claimed team counts only when an Apple-issued certificate for
        // that team signed the code.
        let team_ok = match signing_info
            .as_ref()
            .map(|s| s.team_identifier.as_str())
            .filter(|team| !team.is_empty())
        {
            None => true,
            Some(team) => {
                let requirement =
                    format!(r#"anchor apple generic and certificate leaf[subject.OU] = "{team}""#);
                check_requirement(code, &requirement)
                    .inspect_err(|e| log::warn!("ProcInfo::from_sec_code({pid}) team: {e}"))
                    .is_ok()
            },
        };
        let verified = code_id.is_some() && team_ok;

        let is_apple_login = code_id.is_some()
            && signing_info
                .as_ref()
                .is_some_and(|s| s.identifier == "com.apple.login")
            && check_requirement(code, APPLE_LOGIN_REQUIREMENT)
                .inspect_err(|e| log::warn!("ProcInfo::from_sec_code({pid}): {e}"))
                .is_ok();

        Some(ProcInfo {
            pid,
            parent_pid: ppid,
            command: match signing_info {
                Some(ref s) => s.display_label(),
                None => "?".to_string(),
            },
            signing_info,
            host: host_signing_info,
            code_id,
            verified,
            is_apple_login,
        })
    }

    /// True when the details reported for this process can be trusted: its
    /// running code passed `SecCodeCheckValidity`, and any team identifier it
    /// claims is backed by an Apple-issued certificate for that team. For a
    /// process running as another user with no SecCode, true when its kernel
    /// path was read.
    ///
    /// False means the bundle id, team id, and display name were reported by
    /// the binary itself and may be forged.
    pub fn verified(&self) -> bool {
        self.verified
    }

    /// A verified identity for the code this process runs:
    ///
    /// - `cdhash:<hex>` for a process whose running code passed
    ///   `SecCodeCheckValidity`. Ad-hoc signed binaries qualify.
    /// - `path:<executable>` for a process running as another user that we
    ///   could not get a SecCode for.
    /// - `None` otherwise.
    ///
    /// For an interpreter, this identifies the interpreter and not the script
    /// it runs.
    pub fn code_id(&self) -> Option<&str> {
        self.code_id.as_deref()
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn parent_pid(&self) -> Option<u32> {
        self.parent_pid
    }

    pub(crate) fn command(&self) -> &str {
        &self.command
    }

    pub(crate) fn executable_path(&self) -> Option<String> {
        self.signing_info
            .as_ref()
            .and_then(|s| s.main_executable.to_file_path().ok())
            .map(|p| p.display().to_string())
    }

    pub(crate) fn bundle_id(&self) -> Option<String> {
        self.signing_info
            .as_ref()
            .map(|s| s.identifier.clone())
            .filter(|s| !s.is_empty())
    }

    pub(crate) fn team_id(&self) -> Option<String> {
        self.signing_info
            .as_ref()
            .map(|s| s.team_identifier.clone())
            .filter(|s| !s.is_empty())
    }

    // Returns true if this process appears to be part of axo/axo-pass.
    // pub fn is_axo(&self) -> bool {
    //     let name = self.short_name();
    //     name.to_lowercase().contains("axo")
    // }

    pub fn is_user_visible(&self) -> bool {
        // if no signing info, assume it's user visible (e.g. a script or unsigned
        // binary)
        if self.signing_info.is_none() {
            return true;
        }
        // don't show kernel or launchd processes
        if self.is_system() {
            return false;
        }
        true
    }

    pub fn is_system(&self) -> bool {
        self.pid == 0 || self.pid == 1 || self.is_apple_login
    }
}

impl Display for ProcInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            match self.signing_info {
                Some(ref info) => write!(
                    f,
                    "{} ({}:{})",
                    self.command,
                    info.identifier,
                    info.main_executable
                        .to_file_path()
                        .map(|p| p.display().to_string())
                        .unwrap_or("?".to_string())
                )?,
                None => write!(f, "{}", self.command)?,
            };
            match self.host {
                Some(ref host_info) if !host_info.is_kernel() => {
                    write!(f, " [{}]", host_info.display_label())
                },
                _ => Ok(()),
            }
        } else {
            write!(f, "{}", self.command)
        }
    }
}
