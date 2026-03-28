use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::cli::commands::ssh_agent::{
    AgentStatus, SshAgentServer, get_agent_status_for_socket, get_system_socket_path,
};

#[derive(Debug, Clone, Serialize)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub enum SshAgentStatus {
    Running,
    NotRunning,
    StaleSocket,
}

impl From<AgentStatus> for SshAgentStatus {
    fn from(status: AgentStatus) -> Self {
        match status {
            AgentStatus::Running => SshAgentStatus::Running,
            AgentStatus::NotRunning => SshAgentStatus::NotRunning,
            AgentStatus::StaleSocket => SshAgentStatus::StaleSocket,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub enum SshAgentType {
    Axo,
    System,
}

#[derive(Debug, Clone, Serialize)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub struct SshAgentStatusResponse {
    pub status: SshAgentStatus,
    pub socket_path: Option<String>,
}

#[tauri::command]
pub fn get_ssh_agent_status(agent_type: SshAgentType) -> SshAgentStatusResponse {
    let (status, socket_path) = match agent_type {
        SshAgentType::Axo => {
            let path = SshAgentServer::default_socket_path();
            let status = get_agent_status_for_socket(&path);
            log::debug!(
                "Axo SSH agent status: {:?}, socket path: {}",
                status,
                path.to_string_lossy()
            );
            (status, Some(path.to_string_lossy().to_string()))
        },
        SshAgentType::System => {
            let path = get_system_socket_path();
            let status = match &path {
                Some(p) => get_agent_status_for_socket(p),
                None => AgentStatus::NotRunning,
            };
            (status, path)
        },
    };

    SshAgentStatusResponse {
        status: status.into(),
        socket_path,
    }
}
