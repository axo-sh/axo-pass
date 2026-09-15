use std::fmt::{self, Display};

use libproc::proc_pid::pidpath;
use objc2_security::SecCode;

use crate::core::provenance::helpers::{
    get_host_for_sec_code, get_parent_pid, get_sec_code_for_pid, get_static_code_for_sec_code,
};
use crate::core::provenance::signing_info::SigningInfo;

#[derive(Debug)]
pub struct ProcInfo {
    pid: u32,
    parent_pid: Option<u32>,
    command: String,
    signing_info: Option<SigningInfo>,
    host: Option<SigningInfo>,
}

impl ProcInfo {
    /// A process we could not get a SecCode for (e.g. it runs as another
    /// uid and is SIP-restricted), but whose ppid and executable path are
    /// still readable via pidinfo/proc_pidpath so the walk can continue
    /// past it.
    pub fn pid_and_parent(pid: u32, parent_pid: Option<u32>) -> Self {
        let command = pidpath(pid as i32)
            .ok()
            .and_then(|path| {
                std::path::Path::new(&path)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
            })
            .unwrap_or_else(|| "?".to_string());
        ProcInfo {
            pid,
            parent_pid,
            command,
            signing_info: None,
            host: None,
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

        Some(ProcInfo {
            pid,
            parent_pid: ppid,
            command: match signing_info {
                Some(ref s) => s.display_label(),
                None => "?".to_string(),
            },
            signing_info,
            host: host_signing_info,
        })
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
        self.pid == 0
            || self.pid == 1
            || self
                .signing_info
                .as_ref()
                .is_some_and(|s| s.identifier == "com.apple.login")
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
