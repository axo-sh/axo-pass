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

pub use axo_pass_core::ssh::agent_client::{
    AgentStatus, get_agent_status_for_socket, get_system_socket_path, list_axo_agent_identities,
    list_system_agent_identities,
};
use clap::{Parser, Subcommand};
use clml::cprintln;

use crate::cli::commands::agent;
pub use crate::cli::commands::ssh_agent::client::{
    SshAgentClientError, get_agent_status, request_agent_info, restart_ssh_agent, stop_ssh_agent,
};

#[derive(Parser, Debug)]
pub struct SshAgentCommand {
    #[command(subcommand)]
    subcommand: SshAgentSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum SshAgentSubcommand {
    /// Start the SSH agent. Same as `ap agent start`.
    Start {
        /// Debug mode: run the agent in the foreground
        #[arg(short = 'd')]
        debug: bool,
    },

    /// Stop SSH agent
    Stop,

    /// Get SSH agent status
    Status,
}

impl SshAgentCommand {
    /// `start` without `-d` spawns the agent before the tokio runtime exists.
    pub fn should_detach(&self) -> bool {
        matches!(&self.subcommand, SshAgentSubcommand::Start { debug: false })
    }

    pub async fn run(&self) -> ! {
        match &self.subcommand {
            SshAgentSubcommand::Start { .. } => agent::run(false).await,

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
                    match request_agent_info().await {
                        Ok(info) => {
                            println!("Version: {}", info.version);
                            println!("Started by: {}", info.launcher);
                        },
                        Err(e) => log::debug!("Failed to get agent info: {e}"),
                    }
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
