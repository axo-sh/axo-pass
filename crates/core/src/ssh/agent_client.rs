use std::path::{Path, PathBuf};
use std::process::Command;
use std::{fmt, io};

use serde::{Deserialize, Serialize};
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::client::Client;
use ssh_agent_lib::proto::{Extension, Identity};
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

    #[error("Invalid response from SSH agent: {0}")]
    InvalidResponse(String),

    #[error("Socket file not found")]
    NoSocketFound,
}

/// The label of the launchd service in the app's bundle.
const LAUNCHD_LABEL: &str = "com.breakfastlabs.frittata.agent";

/// State of the agent's launchd service, as seen from `ap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchdService {
    /// `ap` is not running from an app bundle, so there is no service.
    NotInBundle,
    /// launchd has the service loaded. It runs the agent and restarts it if
    /// it fails, but not after an exit 0 such as `ap ssh-agent stop`.
    Loaded,
    /// The app has not registered the service, or the user has not allowed it.
    NotLoaded,
}

/// Whether launchd has the agent's service loaded. Only the app can register
/// or unregister it, through `SMAppService`, but `launchctl print` can read
/// its state.
pub fn launchd_service() -> LaunchdService {
    if crate::core::app_broker::app_bundle_path().is_none() {
        return LaunchdService::NotInBundle;
    }
    let target = format!("gui/{}/{LAUNCHD_LABEL}", unsafe { libc::getuid() });
    let loaded = Command::new("/bin/launchctl")
        .args(["print", &target])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .inspect_err(|e| log::debug!("Failed to run launchctl: {e}"))
        .unwrap_or(false);
    if loaded {
        LaunchdService::Loaded
    } else {
        LaunchdService::NotLoaded
    }
}

/// Makes the agent exit with code 0, which launchd does not restart.
pub const AXO_SHUTDOWN_EXT: &str = "ssh-shutdown@pass.axo.sh";
/// Makes the agent exit with `EX_TEMPFAIL` so launchd starts it again.
pub const AXO_RESTART_EXT: &str = "restart@pass.axo.sh";
/// Returns the agent's [`AgentInfo`] as JSON.
pub const AXO_AGENT_INFO_EXT: &str = "agent-info@pass.axo.sh";

/// How the running agent was started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Launcher {
    /// `ap agent run` in the foreground, as started by launchd.
    Launchd,
    /// `ap agent run --daemonized`, as started by `ap agent start`.
    Detached,
}

impl fmt::Display for Launcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Launcher::Launchd => "launchd",
            Launcher::Detached => "detached",
        })
    }
}

/// The agent's answer to the `agent-info@pass.axo.sh` extension, encoded as
/// JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInfo {
    pub version: String,
    pub launcher: Launcher,
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

/// Asks the running agent to exit with code 0.
pub async fn request_agent_shutdown() -> Result<(), SshAgentClientError> {
    send_extension(AXO_SHUTDOWN_EXT).await?;
    Ok(())
}

/// Asks the running agent to exit with a nonzero code so launchd starts it
/// again.
pub async fn request_agent_restart() -> Result<(), SshAgentClientError> {
    send_extension(AXO_RESTART_EXT).await?;
    Ok(())
}

/// Restarts the running agent and waits for it to stop answering on its
/// socket. Nothing here starts it again: launchd does that for an agent it
/// owns, and for a detached agent the caller must run [`start_agent`].
pub async fn restart_agent() -> Result<(), String> {
    request_agent_restart()
        .await
        .map_err(|e| format!("Failed to restart SSH agent: {e}"))?;

    let socket_path = default_socket_path();
    for _ in 0..40 {
        if get_agent_status_for_socket(&socket_path) != AgentStatus::Running {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    Err("SSH agent did not shut down in time".to_string())
}

/// Asks the running agent for its version and launcher.
pub async fn request_agent_info() -> Result<AgentInfo, SshAgentClientError> {
    let response = send_extension(AXO_AGENT_INFO_EXT)
        .await?
        .ok_or_else(|| SshAgentClientError::InvalidResponse("empty response".to_string()))?;
    serde_json::from_slice(response.details.as_ref())
        .map_err(|e| SshAgentClientError::InvalidResponse(e.to_string()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_info_round_trips_as_json() {
        let info = AgentInfo {
            version: "1.2.3".to_string(),
            launcher: Launcher::Detached,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert_eq!(json, r#"{"version":"1.2.3","launcher":"detached"}"#);
        assert_eq!(serde_json::from_str::<AgentInfo>(&json).unwrap(), info);
    }
}
