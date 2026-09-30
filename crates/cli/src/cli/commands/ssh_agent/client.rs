use axo_pass_core::ssh::agent_client::{
    AgentStatus, default_socket_path, get_agent_status_for_socket,
};
pub use axo_pass_core::ssh::agent_client::{
    SshAgentClientError, request_agent_info, request_agent_shutdown as stop_ssh_agent,
};

pub fn get_agent_status() -> AgentStatus {
    let socket_path = default_socket_path();
    get_agent_status_for_socket(&socket_path)
}
