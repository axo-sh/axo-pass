use std::fs;
use std::time::{Duration, Instant};

use axo_pass_core::ssh::agent_client::{
    AgentStatus, default_socket_path, get_agent_status_for_socket,
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

#[derive(Parser, Debug)]
pub struct AgentCommand {
    #[command(subcommand)]
    subcommand: AgentSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum AgentSubcommand {
    /// Run the agent in the foreground. Started by launchd.
    Run,
}

impl AgentCommand {
    pub async fn execute(&self) -> ! {
        match self.subcommand {
            AgentSubcommand::Run => run().await,
        }
    }
}

/// Runs the SSH listener until SIGTERM, SIGINT, or the shutdown extension.
/// A listener that fails is restarted with backoff. Keys added with `ssh-add`
/// survive a restart, since the same server is reused.
///
/// Exits 0 if another agent already answers on the socket. launchd's
/// `KeepAlive { SuccessfulExit = false }` leaves that exit alone.
async fn run() -> ! {
    log::info!(
        "agent: starting (pid {}, version {})",
        std::process::id(),
        env!("CARGO_PKG_VERSION")
    );
    cli::log_panics();

    let server = SshAgentServer::new();
    let mut backoff = MIN_BACKOFF;
    loop {
        if let Err(e) = prepare_socket() {
            log::error!("agent: {e}");
        } else {
            let started = Instant::now();
            match server.run().await {
                Ok(StopReason::Signal | StopReason::Shutdown) => {
                    log::info!("agent: exited");
                    std::process::exit(0);
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

/// Removes a stale socket so the listener can bind. Exits 0 if another agent
/// is listening.
fn prepare_socket() -> Result<(), String> {
    let socket_path = default_socket_path();
    match get_agent_status_for_socket(&socket_path) {
        AgentStatus::NotRunning => Ok(()),
        AgentStatus::Running => {
            log::info!(
                "agent: another agent is listening on {}, exiting",
                socket_path.display()
            );
            std::process::exit(0);
        },
        AgentStatus::StaleSocket => {
            log::info!("agent: removing stale socket {}", socket_path.display());
            fs::remove_file(&socket_path).map_err(|e| {
                format!(
                    "failed to remove stale socket {}: {e}",
                    socket_path.display()
                )
            })
        },
    }
}
