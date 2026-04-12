use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use ssh_agent_lib::agent::{Agent, Session};
use thiserror::Error;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, broadcast};

use crate::core::provenance;
use crate::cli::commands::ssh_agent::session::SshAgentSession;
use crate::cli::commands::ssh_agent::stored_credential::StoredCredential;
use crate::core::dirs::app_data_dir;

#[derive(Clone)]
pub struct SshAgentServer {
    pub credentials: Arc<Mutex<Vec<StoredCredential>>>,
    pub socket_path: Arc<Mutex<Option<PathBuf>>>,
    pub shutdown_sender: broadcast::Sender<()>,
}

#[derive(Error, Debug)]
pub enum SshAgentError {
    #[error(
      "Found existing SSH agent socket file {}; if no SSH agent is running, please remove this file.",
      .0.display()
    )]
    ServerSocketFileExists(PathBuf),

    #[error("Could not create SSH agent socket: {0}")]
    CouldNotCreateSocket(String),
}

impl Default for SshAgentServer {
    fn default() -> Self {
        Self::new()
    }
}

impl SshAgentServer {
    pub fn new() -> Self {
        let (shutdown_sender, _) = broadcast::channel(1);
        SshAgentServer {
            credentials: Arc::new(Mutex::new(Vec::new())),
            socket_path: Arc::new(Mutex::new(None)),
            shutdown_sender,
        }
    }

    pub async fn run(&self) -> Result<(), SshAgentError> {
        if let Some(socket_path) = self.socket_path.lock().await.as_ref() {
            return Err(SshAgentError::ServerSocketFileExists(socket_path.clone()));
        }
        let socket_path = SshAgentServer::default_socket_path();
        if socket_path.exists() {
            return Err(SshAgentError::ServerSocketFileExists(socket_path.clone()));
        }

        if let Some(parent) = socket_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                SshAgentError::CouldNotCreateSocket(format!(
                    "Failed to create socket parent directory {}: {e}",
                    parent.display()
                ))
            })?;
        }
        *self.socket_path.lock().await = Some(socket_path.clone());

        log::debug!("SSH Agent socket path: {}", socket_path.display());
        let listener = UnixListener::bind(&socket_path).map_err(|e| {
            let _ = fs::remove_file(&socket_path);
            SshAgentError::CouldNotCreateSocket(format!(
                "Failed to bind to socket {}: {e}",
                socket_path.display()
            ))
        })?;

        fs::set_permissions(&socket_path, Permissions::from_mode(0o600)).map_err(|e| {
            let _ = fs::remove_file(&socket_path);
            SshAgentError::CouldNotCreateSocket(format!(
                "Failed to set permissions on socket {}: {e}",
                socket_path.display()
            ))
        })?;

        let mut shutdown_rx = self.shutdown_sender.subscribe();
        tokio::select! {
            result = ssh_agent_lib::agent::listen(listener, self.clone()) => {
              if let Err(e) = result {
                log::error!("ssh-agent error: {e}");
              }
            }
            _ = tokio::signal::ctrl_c() => {
                log::info!("ssh-agent: Received Ctrl+C, shutting down...");
            }
            _ = shutdown_rx.recv() => {
                log::info!("ssh-agent: Shutting down...");
            }
        }
        let _ = fs::remove_file(&socket_path);
        Ok(())
    }

    pub fn default_socket_path() -> PathBuf {
        // typically: ~/Library/Application Support/Axo Pass/agent.sock
        app_data_dir().join("agent.sock")
    }
}

impl Agent<UnixListener> for SshAgentServer {
    fn new_session(&mut self, socket: &UnixStream) -> impl Session {
        let chain = match provenance::get_peer_pid(socket) {
            Some(peer_pid) => provenance::get_process_chain(peer_pid),
            None => Vec::new(),
        };
        let chain_str = chain
            .iter()
            .map(|p| format!("{p:#}"))
            .collect::<Vec<_>>()
            .join(" → ");
        log::debug!("SSH Agent: Connection from: {chain_str}");
        SshAgentSession::new(self.credentials.clone(), chain, self.shutdown_sender.clone())
    }
}
