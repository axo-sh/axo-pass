use std::io;
use std::path::{Path, PathBuf};

use ssh_agent_lib::agent::Session;
use ssh_agent_lib::client::Client;
use ssh_agent_lib::proto::Identity;
use thiserror::Error;
use tokio::net::UnixStream;

use crate::core::dirs::app_data_dir;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentStatus {
    Running,
    NotRunning,
    StaleSocket,
}

pub fn default_socket_path() -> PathBuf {
    // typically: ~/Library/Application Support/Axo Pass/agent.sock
    app_data_dir().join("agent.sock")
}

pub fn get_agent_status_for_socket<P: AsRef<Path>>(socket_path: P) -> AgentStatus {
    let socket_path = socket_path.as_ref();
    if !socket_path.exists() {
        return AgentStatus::NotRunning;
    }

    // note: not using the tokio UnixStream because we want to run this check
    // prior to forking the daemon, and initializing a tokio runtime to execute the
    // async code causes the forked process to crash/
    match std::os::unix::net::UnixStream::connect(socket_path) {
        Ok(_) => AgentStatus::Running,
        Err(_) => AgentStatus::StaleSocket,
    }
}

pub fn get_system_socket_path() -> Option<String> {
    std::env::var("ORIGINAL_SSH_AUTH_SOCK")
        .ok()
        .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
}

#[derive(Error, Debug)]
pub enum SshAgentClientError {
    #[error("Failed to connect to SSH agent: {0}")]
    ConnectionError(#[from] io::Error),

    #[error("SSH agent error: {0}")]
    AgentError(#[from] ssh_agent_lib::error::AgentError),

    #[error("Request error: {0}")]
    RequestError(String),
}

pub async fn list_system_agent_identities() -> Result<Vec<Identity>, SshAgentClientError> {
    // in the terminal, we set ORIGINAL_SSH_AUTH_SOCK in a preexec hook if our agent
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
    let socket_path = default_socket_path();
    if !socket_path.exists() {
        return Ok(Vec::new());
    }
    // todo: implement our own protocol so we can fetch additional
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
