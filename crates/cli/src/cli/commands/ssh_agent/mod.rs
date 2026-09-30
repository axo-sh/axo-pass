mod audit;
mod client;
mod credential;
mod destination_constraint;
mod managed_credential;
pub(crate) mod server;
mod session;
mod session_binding;
mod stored_credential;
mod userauth_request;

use std::fs;
use std::process::{Command, Stdio};

use axo_pass_core::ssh::agent_client::default_socket_path;
pub use axo_pass_core::ssh::agent_client::{
    AgentStatus, get_agent_status_for_socket, get_system_socket_path, list_axo_agent_identities,
    list_system_agent_identities,
};
use clap::{Parser, Subcommand};
use clml::cprintln;
use server::SshAgentServer;

use crate::cli;
pub use crate::cli::commands::ssh_agent::client::{
    SshAgentClientError, get_agent_status, stop_ssh_agent,
};

#[derive(Parser, Debug)]
pub struct SshAgentCommand {
    #[command(subcommand)]
    subcommand: SshAgentSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum SshAgentSubcommand {
    /// Start the SSH agent
    Start {
        /// Debug mode: run SSH agent in the foreground
        #[arg(short = 'd')]
        debug: bool,

        /// Set by the detaching parent when it re-executes `ap` as the agent
        /// process. Runs in the foreground in a new session and logs to a file.
        #[arg(long, hide = true)]
        daemonized: bool,
    },

    /// Stop SSH agent
    Stop,

    /// Get SSH agent status
    Status,
}

impl SshAgentCommand {
    pub fn should_detach(&self) -> bool {
        match &self.subcommand {
            SshAgentSubcommand::Start { debug, daemonized } => !*debug && !*daemonized,
            _ => false,
        }
    }

    pub fn is_daemonized(&self) -> bool {
        matches!(
            &self.subcommand,
            SshAgentSubcommand::Start {
                daemonized: true,
                ..
            }
        )
    }

    /// Starts the agent as a separate process by re-executing `ap` with
    /// `--daemonized`, then exits. The agent uses Security.framework, XPC, and
    /// LAContext, which are not supported in a forked child that has not called
    /// exec, so the agent must not be created with fork alone.
    pub fn spawn_detached(&self) -> ! {
        let exe = match std::env::current_exe() {
            Ok(exe) => exe,
            Err(e) => {
                log::error!("Failed to resolve ap executable path: {e}");
                std::process::exit(1);
            },
        };
        let spawned = Command::new(&exe)
            .args(["ssh-agent", "start", "--daemonized"])
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        match spawned {
            Ok(child) => {
                log::debug!("SSH agent started with pid {}", child.id());
                std::process::exit(0);
            },
            Err(e) => {
                log::error!("Failed to start SSH agent process {}: {e}", exe.display());
                std::process::exit(1);
            },
        }
    }

    /// Detaches the re-executed agent from the parent's session and controlling
    /// terminal.
    pub fn detach_session(&self) {
        // The spawned child is never a process group leader, so this succeeds
        // unless the process was started some other way.
        if unsafe { libc::setsid() } == -1 {
            log::warn!("setsid failed: {}", std::io::Error::last_os_error());
        }
    }

    // code to run before detach (i.e. tokio is not initialized, user can still
    // interact with the program)
    pub fn pre_run(&self) {
        if matches!(&self.subcommand, SshAgentSubcommand::Start { .. }) {
            match get_agent_status() {
                AgentStatus::Running => {
                    log::info!("SSH agent is already running.");
                    std::process::exit(0);
                },
                AgentStatus::StaleSocket => {
                    let socket_path = default_socket_path();
                    let replace = inquire::Confirm::new(&format!(
                        "Stale socket found ({}). Replace it?",
                        socket_path.display()
                    ))
                    .with_default(true)
                    .prompt()
                    .unwrap_or(false);

                    if !replace {
                        std::process::exit(1);
                    } else if let Err(e) = fs::remove_file(&socket_path) {
                        log::error!("Failed to remove stale socket: {e}");
                        std::process::exit(1);
                    }
                },
                _ => {},
            }
        }
    }

    pub async fn run(&self) -> ! {
        match &self.subcommand {
            SshAgentSubcommand::Start { .. } => {
                log::info!("Starting SSH agent...");
                cli::log_panics();
                let server = SshAgentServer::new();
                if let Err(e) = server.run().await {
                    log::error!("SSH Agent failed: {e}");
                    std::process::exit(1);
                }
                log::info!("SSH agent exited.");
                std::process::exit(0)
            },

            SshAgentSubcommand::Stop => match stop_ssh_agent().await {
                Ok(_) => {
                    println!("SSH agent stopped.");
                    std::process::exit(0)
                },
                Err(e) => match e {
                    SshAgentClientError::NoSocketFound => {
                        println!("SSH agent is not running.");
                        std::process::exit(0)
                    },
                    _ => {
                        log::error!("{e}");
                        std::process::exit(1)
                    },
                },
            },
            SshAgentSubcommand::Status => match get_agent_status() {
                AgentStatus::Running => {
                    cprintln!("SSH agent status: <green>running</green>");
                    std::process::exit(0)
                },
                AgentStatus::NotRunning => {
                    cprintln!("SSH agent status: <yellow>not running</yellow>");
                    std::process::exit(1)
                },
                AgentStatus::StaleSocket => {
                    cprintln!("SSH agent status: <yellow>not running</yellow>");
                    println!("Warning: stale socket found");
                    std::process::exit(1)
                },
            },
        }
    }
}
