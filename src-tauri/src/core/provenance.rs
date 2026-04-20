mod helpers;
mod proc_info;
mod signing_info;

use std::fmt;

use crate::core::provenance::proc_info::ProcInfo;

pub struct Provenance {
    proc_info: Vec<ProcInfo>,
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
}

impl fmt::Debug for Provenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            writeln!(f, "Provenance {{")?;
            for info in &self.proc_info {
                if info.is_system() {
                    continue;
                }
                writeln!(f, "    {info:#}")?;
            }
            write!(f, "}}")?;
            return Ok(());
        }
        f.debug_struct("Provenance")
            .field("proc_info", &self.proc_info)
            .finish()
    }
}
