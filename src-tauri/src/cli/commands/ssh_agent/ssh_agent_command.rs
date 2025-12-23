use clap::{Parser, Subcommand, command};

use crate::cli::commands::ssh_agent::SshAgentServer;

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
                log::info!("Starting SSH agent...");
                let server = SshAgentServer::new();
                if let Err(e) = server.run().await {
                    log::error!("SSH Agent failed: {e}");
                }
            },
            SshAgentSubcommand::Stop => {
                todo!("stop ssh agent")
            },
            SshAgentSubcommand::Status => {
                todo!("get ssh agent status")
            },
        }
    }
}
