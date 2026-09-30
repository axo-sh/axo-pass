use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use std::io;

use axo_pass_core::ssh::agent_client::{
    AgentInfo, AgentStatus, Launcher, LaunchdService, default_lock_path, default_socket_path,
    get_agent_status_for_socket, launchd_service,
};
use clap::{Parser, Subcommand};

use crate::cli;
use crate::cli::commands::ssh_agent::server::{SshAgentServer, StopReason};

/// First delay before restarting a failed listener.
const MIN_BACKOFF: Duration = Duration::from_secs(1);
/// Longest delay between listener restarts.
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// A listener that ran at least this long resets the backoff when it fails.
const HEALTHY_RUN: Duration = Duration::from_secs(60);
/// Exit code for the restart extension. launchd restarts the agent on any
/// nonzero exit.
const EX_TEMPFAIL: i32 = 75;

static LAUNCHER: OnceLock<Launcher> = OnceLock::new();

/// The running agent's info. The launcher is `Detached` if the agent was not
/// started through `run`.
pub fn current_agent_info() -> AgentInfo {
    AgentInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        launcher: LAUNCHER.get().copied().unwrap_or(Launcher::Detached),
    }
}

#[derive(Parser, Debug)]
pub struct AgentCommand {
    #[command(subcommand)]
    subcommand: AgentSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum AgentSubcommand {
    /// Start the agent in the background unless one is already running
    Start,

    /// Run the agent in the foreground. Started by launchd.
    #[command(hide = true)]
    Run {
        /// Set by `ap agent start`. Runs in a new session, and exits 0 if
        /// another agent holds the lock instead of waiting for it.
        #[arg(long)]
        daemonized: bool,
    },
}

impl AgentCommand {
    /// `start` spawns the agent before the tokio runtime exists.
    pub fn should_detach(&self) -> bool {
        matches!(self.subcommand, AgentSubcommand::Start)
    }

    /// `run` logs to the agent log file, since its stderr is /dev/null.
    pub fn logs_to_file(&self) -> bool {
        matches!(self.subcommand, AgentSubcommand::Run { .. })
    }

    pub async fn execute(&self) -> ! {
        match self.subcommand {
            AgentSubcommand::Start => spawn_detached(),
            AgentSubcommand::Run { daemonized } => run(daemonized).await,
        }
    }
}

/// Starts the agent as a separate process by re-executing `ap` with
/// `agent run --daemonized`, then exits. Exits without spawning if an agent
/// is already running on the socket. The lock is the only guard against two
/// agents, since a spawned agent exits 0 if it cannot take it. We cannot use
/// fork because the agent uses Security.framework, XPC, and LAContext, which
/// are not supported in a forked child.
pub fn spawn_detached() -> ! {
    if get_agent_status_for_socket(default_socket_path()) == AgentStatus::Running {
        log::info!("Agent is already running");
        std::process::exit(0);
    }
    // Only the app can register the service, so a stopped service agent
    // cannot be started from here. A detached agent would run alongside a
    // service that the app then sees as healthy.
    if launchd_service() == LaunchdService::Loaded {
        eprintln!(
            "The agent is managed by launchd and is not running. Start it from Axo Pass, or log in again."
        );
        std::process::exit(1);
    }

    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(e) => {
            log::error!("Failed to resolve ap executable path: {e}");
            std::process::exit(1);
        },
    };
    let spawned = Command::new(&exe)
        .args(["agent", "run", "--daemonized"])
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    match spawned {
        Ok(child) => {
            log::debug!("Agent started with pid {}", child.id());
            std::process::exit(0);
        },
        Err(e) => {
            log::error!("Failed to start agent process {}: {e}", exe.display());
            std::process::exit(1);
        },
    }
}

/// Runs the SSH listener until SIGTERM, SIGINT, the shutdown extension, or the
/// restart extension. A listener that fails is restarted with backoff. Keys
/// added with `ssh-add` survive a listener restart, since the same server is
/// reused.
///
/// The process owns the socket while it holds an exclusive lock on the agent
/// lock file. A daemonized agent exits 0 if another agent holds the lock. A
/// foreground agent waits for it, so a launchd agent takes over when a
/// detached agent exits.
pub async fn run(daemonized: bool) -> ! {
    if daemonized {
        // The spawned child is never a process group leader, so this succeeds
        // unless the process was started some other way.
        if unsafe { libc::setsid() } == -1 {
            log::warn!("setsid failed: {}", io::Error::last_os_error());
        }
    }
    let launcher = if daemonized {
        Launcher::Detached
    } else {
        Launcher::Launchd
    };
    let _ = LAUNCHER.set(launcher);

    log::info!(
        "agent: starting (pid {}, version {}, launcher {launcher})",
        std::process::id(),
        env!("CARGO_PKG_VERSION")
    );
    cli::log_panics();

    // Held until the process exits. The kernel releases it when the process
    // dies.
    let _lock = match acquire_lock(!daemonized).await {
        Ok(Some(lock)) => lock,
        Ok(None) => {
            log::info!("agent: another agent holds the lock, exiting");
            std::process::exit(0);
        },
        Err(e) => {
            log::error!("agent: failed to take the agent lock: {e}");
            std::process::exit(1);
        },
    };

    let server = SshAgentServer::new();
    let mut backoff = MIN_BACKOFF;
    loop {
        if let Err(e) = remove_existing_socket() {
            log::error!("agent: {e}");
        } else {
            let started = Instant::now();
            match server.run().await {
                Ok(StopReason::Signal | StopReason::Shutdown) => {
                    log::info!("agent: exited");
                    std::process::exit(0);
                },
                Ok(StopReason::Restart) => {
                    log::info!("agent: exiting for restart");
                    std::process::exit(EX_TEMPFAIL);
                },
                Ok(StopReason::ListenerExited) => {},
                Err(e) => log::error!("agent: SSH listener failed: {e}"),
            }
            if started.elapsed() >= HEALTHY_RUN {
                backoff = MIN_BACKOFF;
            }
        }

        log::info!("agent: restarting SSH listener in {}s", backoff.as_secs());
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// Removes the socket file left by a previous agent. The caller holds the
/// agent lock, so any existing socket file is stale.
fn remove_existing_socket() -> Result<(), String> {
    let socket_path = default_socket_path();
    match fs::remove_file(&socket_path) {
        Ok(()) => {
            log::info!("agent: removed stale socket {}", socket_path.display());
            Ok(())
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!(
            "failed to remove stale socket {}: {e}",
            socket_path.display()
        )),
    }
}

/// Takes the exclusive agent lock. Returns `None` if another process holds it
/// and `wait` is false. With `wait`, blocks until the holder exits.
async fn acquire_lock(wait: bool) -> io::Result<Option<File>> {
    let lock_path = default_lock_path();
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock_path)?;

    if flock(&file, false)? {
        return Ok(Some(file));
    }
    if !wait {
        return Ok(None);
    }
    log::info!(
        "agent: another agent holds {}, waiting for it to exit",
        lock_path.display()
    );
    let file = tokio::task::spawn_blocking(move || flock(&file, true).map(|_| file))
        .await
        .map_err(io::Error::other)??;
    log::info!("agent: took the agent lock");
    Ok(Some(file))
}

/// Takes an exclusive `flock`. Without `block`, returns `Ok(false)` if another
/// process holds the lock.
fn flock(file: &File, block: bool) -> io::Result<bool> {
    let op = if block {
        libc::LOCK_EX
    } else {
        libc::LOCK_EX | libc::LOCK_NB
    };
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), op) } == 0 {
            return Ok(true);
        }
        let err = io::Error::last_os_error();
        match err.kind() {
            io::ErrorKind::WouldBlock => return Ok(false),
            io::ErrorKind::Interrupted => continue,
            _ => return Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_is_exclusive_until_released() {
        let path = std::env::temp_dir().join(format!("ap-agent-lock-{}", std::process::id()));
        let first = File::create(&path).unwrap();
        let second = File::open(&path).unwrap();

        assert!(flock(&first, false).unwrap());
        assert!(!flock(&second, false).unwrap());
        drop(first);
        assert!(flock(&second, false).unwrap());

        let _ = fs::remove_file(&path);
    }
}
