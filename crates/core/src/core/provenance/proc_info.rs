use std::fmt::{self, Display};

use libproc::bsd_info::BSDInfo;
use libproc::proc_pid::pidinfo;

use crate::core::provenance::helpers::{
    get_host_for_sec_code, get_sec_code_for_pid, get_static_code_for_sec_code,
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
    pub fn pid_only(pid: u32) -> Self {
        ProcInfo {
            pid,
            parent_pid: None,
            command: "?".to_string(),
            signing_info: None,
            host: None,
        }
    }

    pub fn lookup(pid: u32) -> Option<Self> {
        let code = get_sec_code_for_pid(pid)
            .inspect_err(|e| log::error!("ProcInfo lookup: {e}"))
            .ok()?;
        let static_code = get_static_code_for_sec_code(&code)
            .inspect_err(|e| log::error!("ProcInfo lookup: {e}"))
            .ok()?;

        // Get signing info for the executable
        let signing_info = SigningInfo::from_sec_code(&static_code);

        // get parent pid
        let ppid = pidinfo::<BSDInfo>(pid as i32, 0)
            .ok()
            .map(|info| info.pbi_ppid);

        // get the process host
        let host_signing_info = get_host_for_sec_code(&code)
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
                .map_or(false, |s| s.identifier == "com.apple.login")
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
                Some(ref host_info) => write!(f, " [{}]", host_info.display_label()),
                None => Ok(()),
            }
        } else {
            write!(f, "{}", self.command)
        }
    }
}
