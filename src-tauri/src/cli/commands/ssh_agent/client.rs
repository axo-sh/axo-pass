use std::io;

use ssh_agent_lib::agent::Session;
use ssh_agent_lib::client::Client;
use ssh_agent_lib::proto::Extension;
use thiserror::Error;
use tokio::net::UnixStream;

use crate::cli::commands::ssh_agent::SshAgentServer;

pub enum AgentStatus {
    Running,
    NotRunning,
    StaleSocket,
}

pub async fn get_agent_status() -> AgentStatus {
    let socket_path = SshAgentServer::default_socket_path();
    if !socket_path.exists() {
        return AgentStatus::NotRunning;
    }

    match tokio::net::UnixStream::connect(&socket_path).await {
        Ok(_) => AgentStatus::Running,
        Err(_) => AgentStatus::StaleSocket,
    }
}

#[derive(Error, Debug)]
pub enum StopSshAgentError {
    #[error("Failed to connect to SSH agent: {0}")]
    ConnectionError(#[from] io::Error),

    #[error("SSH agent error: {0}")]
    AgentError(#[from] ssh_agent_lib::error::AgentError),

    #[error("Socket file not found")]
    NoSocketFound,
}

pub async fn stop_ssh_agent() -> Result<(), StopSshAgentError> {
    let socket_path = SshAgentServer::default_socket_path();
    if !socket_path.exists() {
        return Err(StopSshAgentError::NoSocketFound);
    }
    let stream = UnixStream::connect(&socket_path).await?;
    let request = Extension {
        name: "ssh-shutdown@pass.axo.sh".to_string(),
        details: Vec::new().into(),
    };
    let _ = Client::new(stream).extension(request).await?;
    Ok(())
}
