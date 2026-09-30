use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use ssh_agent_lib::agent::Session;
use ssh_agent_lib::client::Client;
use ssh_agent_lib::proto::Identity;
use thiserror::Error;
use tokio::net::UnixStream;

use crate::core::dirs::app_data_dir;
use crate::shell_integration::ap_bin_path;

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

/// The lock file an agent holds for the life of its process. Typically
/// ~/Library/Application Support/Axo Pass/agent.lock.
pub fn default_lock_path() -> PathBuf {
    app_data_dir().join("agent.lock")
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

/// Starts the Axo Pass agent by running `ap agent start`. That process spawns
/// the detached agent and exits as soon as the spawn succeeds, before the agent
/// has bound the socket, so this polls briefly afterward rather than trusting
/// the exit status alone. The agent removes a stale socket itself once it
/// holds the agent lock.
pub fn start_agent() -> Result<(), String> {
    let socket_path = default_socket_path();
    let ap = ap_bin_path().ok_or("Could not determine ap binary path")?;
    let status = Command::new(&ap)
        .args(["agent", "start"])
        .status()
        .map_err(|e| format!("Failed to run ap agent start: {e}"))?;
    if !status.success() {
        return Err(format!("ap agent start exited with {status}"));
    }

    const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);
    const POLL_ATTEMPTS: u32 = 40; // 2s
    for _ in 0..POLL_ATTEMPTS {
        if get_agent_status_for_socket(&socket_path) == AgentStatus::Running {
            return Ok(());
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    Err("SSH agent did not come up in time".to_string())
}

/// Stops the Axo Pass SSH agent by running `ap ssh-agent stop`. The stop
/// request is delivered before the CLI exits, but the agent's own socket
/// cleanup runs after that, so this polls briefly for the socket to go away.
pub fn stop_agent() -> Result<(), String> {
    let socket_path = default_socket_path();
    let ap = ap_bin_path().ok_or("Could not determine ap binary path")?;
    let status = Command::new(&ap)
        .args(["ssh-agent", "stop"])
        .status()
        .map_err(|e| format!("Failed to run ap ssh-agent stop: {e}"))?;
    if !status.success() {
        return Err(format!("ap ssh-agent stop exited with {status}"));
    }

    const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);
    const POLL_ATTEMPTS: u32 = 40; // 2s
    for _ in 0..POLL_ATTEMPTS {
        if get_agent_status_for_socket(&socket_path) != AgentStatus::Running {
            return Ok(());
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    Err("SSH agent did not shut down in time".to_string())
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
