use std::fmt::Display;
use std::process::Command;

use tokio::net::UnixStream;

pub fn get_peer_pid(stream: &UnixStream) -> Option<u32> {
    stream
        .peer_cred()
        .ok()
        .and_then(|cred| cred.pid())
        .map(|pid| pid as u32)
}

/// Get process info (ppid, command) for a given PID using ps
fn get_process_info(pid: u32) -> Option<(Option<u32>, String)> {
    let output = Command::new("ps")
        .args(["-o", "ppid=,comm=", "-p", &pid.to_string()])
        .output()
        .ok()?;

    let stdout = String::from_utf8(output.stdout).ok()?;
    let line = stdout.trim();
    if line.is_empty() {
        return None;
    }

    let mut parts = line.splitn(2, char::is_whitespace);
    let ppid = parts.next()?.trim().parse::<u32>().ok();
    let comm = parts.next().unwrap_or("?").trim().to_string();

    Some((ppid, comm))
}

pub struct ProcInfo {
    pub pid: u32,
    pub command: String,
}

impl ProcInfo {
    /// Returns true if this process appears to be part of axo/axo-pass.
    pub fn is_axo(&self) -> bool {
        let name = self.short_name();
        name.to_lowercase().contains("axo")
    }

    /// Returns a short, human-readable name for the process.
    fn short_name(&self) -> &str {
        // If the path contains a *.app component, use that (strip ".app").
        // Otherwise use the last path component.
        let mut last = &self.command as &str;
        for part in self.command.split('/') {
            if part.ends_with(".app") {
                return part.trim_end_matches(".app");
            }
            if !part.is_empty() {
                last = part;
            }
        }
        last
    }
}

impl Display for ProcInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            return write!(f, "{}({})", self.command, self.pid);
        }
        write!(f, "{}", self.short_name())
    }
}

/// Get the process ancestry chain from a given PID up to (but not including) init.
pub fn get_process_chain(pid: u32) -> Vec<ProcInfo> {
    let mut chain = Vec::new();
    let mut current_pid = pid;

    for _ in 0..64 {
        match get_process_info(current_pid) {
            Some((ppid, cmd)) => {
                chain.push(ProcInfo {
                    pid: current_pid,
                    command: cmd,
                });
                match ppid {
                    Some(p) if p > 1 && p != current_pid => {
                        current_pid = p;
                    },
                    _ => break,
                }
            },
            None => {
                chain.push(ProcInfo {
                    pid: current_pid,
                    command: "?".to_string(),
                });
                break;
            },
        }
        if current_pid == 1 {
            break;
        }
    }

    chain
}

/// Build an optional caller description string from a process chain.
/// Returns None if the chain is empty or the immediate caller is axo.
pub fn caller_description(chain: &[ProcInfo]) -> Option<String> {
    let head = chain.first()?;
    if head.is_axo() {
        return None;
    }
    let tail = chain.last()?;
    if head.pid == tail.pid {
        Some(format!("{head}"))
    } else {
        Some(format!("{tail} ({head})"))
    }
}

/// Returns a caller description string for the parent process of the current
/// process. Returns None if the parent is axo itself (e.g. the GUI app) or if
/// the parent chain cannot be determined.
pub fn get_parent_process_description() -> Option<String> {
    let my_pid = std::process::id();
    let (ppid, _) = get_process_info(my_pid)?;
    let ppid = ppid?;
    let chain = get_process_chain(ppid);
    caller_description(&chain)
}
