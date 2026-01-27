use std::io;
use std::path::Path;

use ssh_agent_lib::agent::Session;
use ssh_agent_lib::client::Client;
use ssh_agent_lib::proto::{Extension, Identity};
use thiserror::Error;
use tokio::net::UnixStream;

use crate::cli::commands::ssh_agent::SshAgentServer;
use crate::cli::commands::ssh_agent::session::AXO_SHUTDOWN_EXT;

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
pub enum SshAgentClientError {
    #[error("Failed to connect to SSH agent: {0}")]
    ConnectionError(#[from] io::Error),

    #[error("SSH agent error: {0}")]
    AgentError(#[from] ssh_agent_lib::error::AgentError),

    #[error("Socket file not found")]
    NoSocketFound,

    #[error("Request error: {0}")]
    RequestError(String),
}

pub async fn stop_ssh_agent() -> Result<(), SshAgentClientError> {
    let socket_path = SshAgentServer::default_socket_path();
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

pub async fn list_system_agent_identities() -> Result<Vec<Identity>, SshAgentClientError> {
    // in the terminal,we set ORIGINAL_SSH_AUTH_SOCK in a preexec hook if our agent
    // is running
    let socket_path = std::env::var("ORIGINAL_SSH_AUTH_SOCK")
        .ok()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok());
    match socket_path {
        Some(path) => list_identities_from_agent(path).await,
        None => Ok(Vec::new()),
    }
}

pub async fn list_axo_agent_identities() -> Result<Vec<Identity>, SshAgentClientError> {
    let socket_path = SshAgentServer::default_socket_path();
    if !socket_path.exists() {
        return Ok(Vec::new());
    }
    // todo: implement our our protocol we so we can fetch additional
    // metadata like constraints
    list_identities_from_agent(&socket_path).await
}

async fn list_identities_from_agent<P>(socket_path: P) -> Result<Vec<Identity>, SshAgentClientError>
where
    P: AsRef<Path>,
{
    let stream = UnixStream::connect(&socket_path).await?;
    let mut client = Client::new(stream);
    let identities = client.request_identities().await.map_err(|e| {
        SshAgentClientError::RequestError(format!("Failed to request identities: {e}"))
    })?;
    Ok(identities)
}
