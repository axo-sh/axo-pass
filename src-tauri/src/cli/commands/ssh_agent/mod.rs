mod client;
mod server;
mod session;
mod stored_credential;

use clap::{Parser, Subcommand, command};
use color_print::cformat;
pub use server::SshAgentServer;

use crate::cli::commands::ssh_agent::client::{
    AgentStatus, StopSshAgentError, get_agent_status, stop_ssh_agent,
};

#[derive(Parser, Debug)]
pub struct SshAgentCommand {
    #[command(subcommand)]
    subcommand: SshAgentSubcommand,
}

#[derive(Subcommand, Debug)]
enum SshAgentSubcommand {
    Start,
    Stop,
    Status,
}

impl SshAgentCommand {
    pub async fn run(&self) {
        match &self.subcommand {
            SshAgentSubcommand::Start => {
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
                    log::info!("SSH agent stopped.");
                },
                Err(e) => match e {
                    StopSshAgentError::NoSocketFound => {
                        log::info!("SSH agent is not running.");
                    },
                    _ => {
                        log::error!("{e}");
                        std::process::exit(1);
                    },
                },
            },
            SshAgentSubcommand::Status => match get_agent_status().await {
                AgentStatus::Running => {
                    log::info!("{}", cformat!("SSH agent status: <green>running</green>"));
                    std::process::exit(0);
                },
                AgentStatus::NotRunning => {
                    log::info!(
                        "{}",
                        cformat!("SSH agent status: <yellow>not running</yellow>")
                    );
                    std::process::exit(1);
                },
                AgentStatus::StaleSocket => {
                    log::info!(
                        "{}",
                        cformat!("SSH agent status: <yellow>not running</yellow>")
                    );
                    log::info!("Warning: stale socket found");
                    std::process::exit(1);
                },
            },
        }
    }
}
