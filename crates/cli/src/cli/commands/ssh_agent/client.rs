use axo_pass_core::ssh::agent_client::{
    AgentStatus, default_socket_path, get_agent_status_for_socket,
};
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::client::Client;
use ssh_agent_lib::proto::Extension;
use thiserror::Error;
use tokio::net::UnixStream;

use crate::cli::commands::ssh_agent::session::AXO_SHUTDOWN_EXT;

pub fn get_agent_status() -> AgentStatus {
    let socket_path = default_socket_path();
    get_agent_status_for_socket(&socket_path)
}

#[derive(Error, Debug)]
pub enum SshAgentClientError {
    #[error("Failed to connect to SSH agent: {0}")]
    ConnectionError(#[from] std::io::Error),

    #[error("SSH agent error: {0}")]
    AgentError(#[from] ssh_agent_lib::error::AgentError),

    #[error("Socket file not found")]
    NoSocketFound,
}

pub async fn stop_ssh_agent() -> Result<(), SshAgentClientError> {
    let socket_path = default_socket_path();
    if !socket_path.exists() {
        return Err(SshAgentClientError::NoSocketFound);
    }
    let stream = UnixStream::connect(&socket_path).await?;
    let request = Extension {
        name: AXO_SHUTDOWN_EXT.to_string(),
        details: Vec::new().into(),
    };
    let _ = Client::new(stream).extension(request).await?;
    Ok(())
}
