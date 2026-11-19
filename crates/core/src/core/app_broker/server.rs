//! The server side of the broker, run by the app: bind the socket, accept
//! connections, and serve them one at a time.

use std::fs::{self, Permissions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as AsyncBufReader};
use tokio::net::{UnixListener, UnixStream};

#[cfg(target_os = "macos")]
use super::access::extension_policy;
use super::access::{
    Client, RequestScope, agent_policy, browser_host_policy, record_rejected_peer, verify_client,
};
use super::dispatch::serve_request;
use super::in_flight::client_disconnected;
use super::wire::{WireRequest, WireResponse};
#[cfg(target_os = "macos")]
use super::{autofill_service_name, mach};
use super::{Authorizers, broker_socket_path};
use crate::core::provenance::PeerIdentity;

/// Serve requests on the socket until `shutdown` resolves, then remove the
/// socket. There is no Mach service on Linux.
#[cfg(not(target_os = "macos"))]
pub async fn serve(
    authorizers: Authorizers,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) -> std::io::Result<()> {
    serve_on(
        broker_socket_path(),
        vec![
            Client {
                policy: agent_policy(),
                scope: RequestScope::Agent,
            },
            Client {
                policy: browser_host_policy(),
                scope: RequestScope::BrowserHost,
            },
        ],
        authorizers,
        shutdown,
    )
    .await
}

/// Serve requests until `shutdown` resolves, then remove the socket and the
/// Mach service.
///
/// `ap` connects to the socket in the app data directory. When this build is
/// signed, the AutoFill extension reaches the broker through a Mach service
/// named under the App Group (see [`mach`]). The extension is sandboxed, and a
/// Mach service lookup is the one path to the app it has that touches no
/// files.
#[cfg(target_os = "macos")]
pub async fn serve(
    authorizers: Authorizers,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) -> std::io::Result<()> {
    let autofill = match autofill_service_name() {
        Some(name) => match mach::MachService::start(
            &name,
            extension_policy(),
            RequestScope::AutofillExtension,
            authorizers.clone(),
        ) {
            Ok(service) => Some(service),
            Err(e) => {
                log::warn!("AutoFill broker failed to start on {name}: {e}");
                None
            },
        },
        None => {
            log::debug!("No team identifier: not serving the AutoFill broker");
            None
        },
    };

    let result = serve_on(
        broker_socket_path(),
        vec![
            Client {
                policy: agent_policy(),
                scope: RequestScope::Agent,
            },
            Client {
                policy: browser_host_policy(),
                scope: RequestScope::BrowserHost,
            },
        ],
        authorizers,
        shutdown,
    )
    .await;

    if let Some(autofill) = autofill {
        autofill.stop();
    }
    result
}

/// The body of [`serve`], with the socket path and the clients supplied rather
/// than derived, so tests can bind a scratch socket and choose who it accepts
/// and what they may ask for. A peer is matched against each client's policy in
/// order, and the first it satisfies gives the scope.
///
/// Binding replaces a socket left behind by a crashed app: only one app runs at
/// a time, and a stale file would otherwise keep the broker offline
/// permanently.
pub(super) async fn serve_on(
    socket_path: PathBuf,
    clients: Vec<Client>,
    authorizers: Authorizers,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) -> std::io::Result<()> {
    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if socket_path.exists() {
        // Only remove a socket nothing is listening on.
        match std::os::unix::net::UnixStream::connect(&socket_path) {
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!("another app broker owns {}", socket_path.display()),
                ));
            },
            Err(_) => {
                log::debug!("Replacing stale app broker socket {socket_path:?}");
                fs::remove_file(&socket_path)?;
            },
        }
    }

    let listener = UnixListener::bind(&socket_path)?;
    fs::set_permissions(&socket_path, Permissions::from_mode(0o600)).inspect_err(|_| {
        let _ = fs::remove_file(&socket_path);
    })?;
    log::debug!("App broker listening on {}", socket_path.display());

    tokio::select! {
        _ = accept_loop(listener, authorizers, clients) => {},
        _ = shutdown => log::debug!("App broker shutting down"),
    }
    let _ = fs::remove_file(&socket_path);
    Ok(())
}

async fn accept_loop(listener: UnixListener, authorizers: Authorizers, clients: Vec<Client>) {
    let turns = Arc::new(tokio::sync::Mutex::new(()));
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                // Writes to a closed peer must fail with EPIPE, not raise
                // SIGPIPE, which would terminate the host process.
                #[cfg(target_os = "macos")]
                if let Err(e) = socket2::SockRef::from(&stream).set_nosigpipe(true) {
                    log::debug!("App broker could not set SO_NOSIGPIPE: {e}");
                }
                let (peer, scope) = match verify_client(stream.as_raw_fd(), &clients) {
                    Ok(verified) => verified,
                    // A client that gave up while its connection waited to be
                    // accepted. Nothing connected that could be checked, so
                    // nothing was refused.
                    Err(e) if e.is_disconnected() => {
                        log::debug!("App broker client disconnected before it was accepted");
                        continue;
                    },
                    Err(e) => {
                        log::warn!("App broker refused a connection: {e}");
                        record_rejected_peer(&e, PeerIdentity::identify(stream.as_raw_fd()).ok());
                        continue;
                    },
                };
                log::debug!("App broker peer: {peer:#?}");

                let authorizers = authorizers.clone();
                let turns = turns.clone();
                // Each connection runs in its own task so that a pending prompt
                // does not hold up a locked listing. Requests that may prompt
                // take turns, see `handle_connection`.
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_connection(stream, &peer, scope, authorizers, &turns).await
                    {
                        log::debug!("App broker connection failed: {e}");
                    }
                });
            },
            Err(e) => {
                log::error!("App broker accept failed: {e}");
                return;
            },
        }
    }
}

async fn handle_connection(
    stream: UnixStream,
    peer: &PeerIdentity,
    scope: RequestScope,
    authorizers: Authorizers,
    turns: &tokio::sync::Mutex<()>,
) -> std::io::Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = AsyncBufReader::new(read_half);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;
    let request: WireRequest = serde_json::from_str(&request_line)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    // Requests that may prompt are served one at a time, as two prompts at once
    // would contend for the screen and the system's authentication session. A
    // locked listing never prompts and does not wait.
    let _turn = match request {
        WireRequest::ListLoginsLocked { .. } => None,
        _ => Some(turns.lock().await),
    };

    // A client that gave up while its connection waited to be accepted has
    // already closed it. Its request is not served at all, so the app shows no
    // prompt and records nothing for it.
    let disconnected = tokio::select! {
        biased;
        () = client_disconnected(&mut reader) => true,
        () = std::future::ready(()) => false,
    };
    if disconnected {
        log::debug!("App broker client disconnected before its request was served");
        return Ok(());
    }

    let response = serve_request(
        request,
        peer,
        scope,
        authorizers,
        client_disconnected(&mut reader),
    )
    .await?;
    match response {
        Some(response) => write_response(&mut write_half, &response).await,
        None => Ok(()),
    }
}

async fn write_response(
    write_half: &mut tokio::net::unix::OwnedWriteHalf,
    response: &WireResponse,
) -> std::io::Result<()> {
    let mut line =
        serde_json::to_vec(response).map_err(|e| std::io::Error::other(e.to_string()))?;
    line.push(b'\n');
    write_half.write_all(&line).await?;
    write_half.flush().await
}
