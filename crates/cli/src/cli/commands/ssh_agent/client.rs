use axo_pass_core::ssh::agent_client::{
    AgentStatus, default_socket_path, get_agent_status_for_socket,
};
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::client::Client;
use ssh_agent_lib::proto::Extension;
use thiserror::Error;
use tokio::net::UnixStream;

use crate::cli::commands::agent::AgentInfo;
use crate::cli::commands::ssh_agent::session::{
    AXO_AGENT_INFO_EXT, AXO_RESTART_EXT, AXO_SHUTDOWN_EXT,
};

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

    #[error("Invalid response from SSH agent: {0}")]
    InvalidResponse(String),

    #[error("Socket file not found")]
    NoSocketFound,
}

/// Connects to the agent and sends an extension request with no payload.
async fn send_extension(name: &str) -> Result<Option<Extension>, SshAgentClientError> {
    let socket_path = default_socket_path();
    if !socket_path.exists() {
        return Err(SshAgentClientError::NoSocketFound);
    }
    let stream = UnixStream::connect(&socket_path).await?;
    let request = Extension {
        name: name.to_string(),
        details: Vec::new().into(),
    };
    Ok(Client::new(stream).extension(request).await?)
}

pub async fn stop_ssh_agent() -> Result<(), SshAgentClientError> {
    send_extension(AXO_SHUTDOWN_EXT).await?;
    Ok(())
}

/// Asks the running agent to exit with a nonzero code so launchd starts it
/// again.
pub async fn restart_ssh_agent() -> Result<(), SshAgentClientError> {
    send_extension(AXO_RESTART_EXT).await?;
    Ok(())
}

/// Asks the running agent for its version and launcher.
pub async fn request_agent_info() -> Result<AgentInfo, SshAgentClientError> {
    let response = send_extension(AXO_AGENT_INFO_EXT)
        .await?
        .ok_or_else(|| SshAgentClientError::InvalidResponse("empty response".to_string()))?;
    serde_json::from_slice(response.details.as_ref())
        .map_err(|e| SshAgentClientError::InvalidResponse(e.to_string()))
}
