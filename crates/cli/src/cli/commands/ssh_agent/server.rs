use std::fs::{self, Permissions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axo_pass_core::audit::{Action, Actor, Outcome};
use axo_pass_core::core::provenance::PeerIdentity;
use axo_pass_core::ssh::agent_client::default_socket_path;
use ssh_agent_lib::agent::{Agent, Session};
use thiserror::Error;
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{Mutex, broadcast};

use crate::cli::commands::ssh_agent::audit;
use crate::cli::commands::ssh_agent::session::SshAgentSession;
use crate::cli::commands::ssh_agent::stored_credential::StoredCredential;

#[derive(Clone)]
pub struct SshAgentServer {
    pub credentials: Arc<Mutex<Vec<StoredCredential>>>,
    pub socket_path: Arc<Mutex<Option<PathBuf>>>,
    pub shutdown_sender: broadcast::Sender<StopReason>,
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

/// Why [`SshAgentServer::run`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// SIGINT or SIGTERM.
    Signal,
    /// A client sent the shutdown extension.
    Shutdown,
    /// A client sent the restart extension. The process should exit nonzero.
    Restart,
    /// The listener ended on its own. The server can be run again.
    ListenerExited,
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

    pub async fn run(&self) -> Result<StopReason, SshAgentError> {
        // check if this server is already running
        if let Some(socket_path) = self.socket_path.lock().await.as_ref() {
            return Err(SshAgentError::ServerSocketFileExists(socket_path.clone()));
        }

        // check if the default socket path exist (created by another agent/stale file)
        let socket_path = default_socket_path();
        if socket_path.exists() {
            return Err(SshAgentError::ServerSocketFileExists(socket_path.clone()));
        }

        *self.socket_path.lock().await = Some(socket_path.clone());
        let result = self.serve(&socket_path).await;
        *self.socket_path.lock().await = None;
        result
    }

    /// Binds the agent socket and serves until a signal, the shutdown
    /// extension, or the listener ends. The socket file is removed on return,
    /// so the server can be run again with the same credentials.
    async fn serve(&self, socket_path: &Path) -> Result<StopReason, SshAgentError> {
        if let Some(parent) = socket_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                SshAgentError::CouldNotCreateSocket(format!(
                    "Failed to create socket parent directory {}: {e}",
                    parent.display()
                ))
            })?;
        }
        log::debug!("SSH Agent socket path: {}", socket_path.display());
        let listener = UnixListener::bind(socket_path).map_err(|e| {
            let _ = fs::remove_file(socket_path);
            SshAgentError::CouldNotCreateSocket(format!(
                "Failed to bind to socket {}: {e}",
                socket_path.display()
            ))
        })?;

        fs::set_permissions(socket_path, Permissions::from_mode(0o600)).map_err(|e| {
            let _ = fs::remove_file(socket_path);
            SshAgentError::CouldNotCreateSocket(format!(
                "Failed to set permissions on socket {}: {e}",
                socket_path.display()
            ))
        })?;

        audit::record_lifecycle(Action::SshAgentStart, Outcome::Succeeded, None, None);

        let mut shutdown_rx = self.shutdown_sender.subscribe();
        let mut sigterm = signal(SignalKind::terminate()).map_err(|e| {
            let _ = fs::remove_file(socket_path);
            SshAgentError::CouldNotCreateSocket(format!("Failed to install SIGTERM handler: {e}"))
        })?;
        // Installing a handler replaces the default SIGHUP action, which would
        // terminate the process.
        let mut sighup = signal(SignalKind::hangup()).map_err(|e| {
            let _ = fs::remove_file(socket_path);
            SshAgentError::CouldNotCreateSocket(format!("Failed to install SIGHUP handler: {e}"))
        })?;

        let listen = ssh_agent_lib::agent::listen(listener, self.clone());
        tokio::pin!(listen);
        let reason = loop {
            tokio::select! {
                result = &mut listen => {
                    match result {
                        Ok(()) => log::error!("ssh-agent: listener exited"),
                        Err(e) => log::error!("ssh-agent: listener failed: {e}"),
                    }
                    break StopReason::ListenerExited;
                }
                _ = tokio::signal::ctrl_c() => {
                    log::info!("ssh-agent: Received SIGINT, shutting down...");
                    break StopReason::Signal;
                }
                _ = sigterm.recv() => {
                    log::info!("ssh-agent: Received SIGTERM, shutting down...");
                    break StopReason::Signal;
                }
                _ = sighup.recv() => {
                    log::info!("ssh-agent: Received SIGHUP, ignoring");
                }
                request = shutdown_rx.recv() => {
                    log::info!("ssh-agent: Shutting down...");
                    break request.unwrap_or(StopReason::Shutdown);
                }
            }
        };
        // Remove the socket path first so new clients fail immediately instead
        // of connecting to a listener that is no longer accepting.
        let _ = fs::remove_file(socket_path);

        // ssh_agent_lib::agent::listen spawns a detached task per connection and
        // gives us no handle to join. Give in-flight sessions a moment to finish
        // their current request/response before the runtime is torn down, or
        // they hit the tail end of a read/write with a shutdown-related IO error.
        tokio::time::sleep(Duration::from_millis(300)).await;

        audit::record_lifecycle(Action::SshAgentStop, Outcome::Succeeded, None, None);
        Ok(reason)
    }
}

impl Agent<UnixListener> for SshAgentServer {
    fn new_session(&mut self, socket: &UnixStream) -> impl Session {
        // From the audit token, not `peer_cred().pid()`: a pid can be recycled
        // onto an unrelated process between reading it and resolving it, and
        // this name ends up in a signing prompt.
        let peer = PeerIdentity::identify(socket.as_raw_fd())
            .inspect_err(|e| log::debug!("SSH agent caller unidentified: {e}"))
            .ok()
            .inspect(|peer| log::debug!("SSH agent caller: {peer:#?}"));
        let caller = peer.as_ref().and_then(|peer| peer.caller());
        let actor = peer.as_ref().map(Actor::from_peer);

        SshAgentSession::new(
            self.credentials.clone(),
            caller,
            actor,
            self.shutdown_sender.clone(),
        )
    }
}
