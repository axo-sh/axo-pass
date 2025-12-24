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
