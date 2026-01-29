mod client;
mod credential;
mod destination_constraint;
mod managed_credential;
mod server;
mod session;
mod session_binding;
mod stored_credential;
mod userauth_request;

use clap::{Parser, Subcommand, command};
use color_print::cprintln;
pub use server::SshAgentServer;

pub use crate::cli::commands::ssh_agent::client::{
    AgentStatus, SshAgentClientError, get_agent_status, get_agent_status_for_socket,
    get_system_socket_path, list_axo_agent_identities, list_system_agent_identities,
    stop_ssh_agent,
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
    },

    /// Stop SSH agent
    Stop,

    /// Get SSH agent status
    Status,
}

impl SshAgentCommand {
    pub fn should_detach(&self) -> bool {
        match &self.subcommand {
            SshAgentSubcommand::Start { debug } => !*debug,
            _ => false,
        }
    }

    pub async fn run(&self) {
        match &self.subcommand {
            SshAgentSubcommand::Start { .. } => {
                if matches!(get_agent_status().await, AgentStatus::Running) {
                    log::info!("SSH agent is already running.");
                    std::process::exit(1);
                }

                log::info!("Starting SSH agent...");
                let server = SshAgentServer::new();
                if let Err(e) = server.run().await {
                    log::error!("SSH Agent failed: {e}");
                }
            },

            SshAgentSubcommand::Stop => match stop_ssh_agent().await {
                Ok(_) => {
                    println!("SSH agent stopped.");
                },
                Err(e) => match e {
                    SshAgentClientError::NoSocketFound => {
                        println!("SSH agent is not running.");
                    },
                    _ => {
                        log::error!("{e}");
                        std::process::exit(1);
                    },
                },
            },
            SshAgentSubcommand::Status => match get_agent_status().await {
                AgentStatus::Running => {
                    cprintln!("SSH agent status: <green>running</green>");
                    std::process::exit(0);
                },
                AgentStatus::NotRunning => {
                    cprintln!("SSH agent status: <yellow>not running</yellow>");
                    std::process::exit(1);
                },
                AgentStatus::StaleSocket => {
                    cprintln!("SSH agent status: <yellow>not running</yellow>");
                    println!("Warning: stale socket found");
                    std::process::exit(1);
                },
            },
        }
    }
}
