//! The client side of the broker, used by `ap`: connect to the app's socket,
//! starting the app when nothing is listening, and exchange one request.

use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::time::Duration;

use zeroize::Zeroizing;

use super::platform::launch_app;
use super::wire::{WireRequest, WireResponse};
use super::{BrokerError, broker_socket_path};

/// How long a client waits for the user to answer the app's prompt before
/// giving up. Disconnecting ends the prompt, see `InFlightRequest`.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(120);

/// How long a query for a setting waits for the app to answer. The app answers
/// from memory or the keychain, so a longer wait means it is stuck.
const QUERY_TIMEOUT: Duration = Duration::from_secs(1);

/// How long to wait for a cold app launch to start serving.
const LAUNCH_TIMEOUT: Duration = Duration::from_secs(20);
const LAUNCH_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Initial capacity of the buffer a response line is read into.
const RESPONSE_CAPACITY: usize = 32 * 1024;

pub(super) fn send_request(request: &WireRequest) -> Result<WireResponse, BrokerError> {
    send_request_for(request, None)
}

/// Send `request` on behalf of `requester`, a client connected to the caller,
/// such as an `ssh` process talking to the agent. When the requester
/// disconnects before the app answers, the connection to the broker is closed,
/// which ends the app's prompt, and this returns
/// [`BrokerError::RequesterDisconnected`].
pub(super) fn send_request_for(
    request: &WireRequest,
    requester: Option<BorrowedFd<'_>>,
) -> Result<WireResponse, BrokerError> {
    let stream = match connect() {
        Ok(stream) => stream,
        Err(_) => {
            // Nothing listening. The app owns the keys, so start it and wait
            // rather than failing.
            launch_app()?;
            wait_for_broker()?
        },
    };
    exchange(&stream, request, requester, RESPONSE_TIMEOUT)
}

/// Send `request` to an app that is already running. Fails with
/// [`BrokerError::Unavailable`] if nothing is listening, and never starts the
/// app. Gives up after [`QUERY_TIMEOUT`]. For requests made while recording
/// something else, which must not start the app or wait on a prompt.
pub(super) fn query_request(request: &WireRequest) -> Result<WireResponse, BrokerError> {
    let stream = connect().map_err(|_| BrokerError::Unavailable)?;
    exchange(&stream, request, None, QUERY_TIMEOUT)
}

/// Write `request` to `stream` and read the response line, waiting at most
/// `timeout` for the response.
fn exchange(
    stream: &std::os::unix::net::UnixStream,
    request: &WireRequest,
    requester: Option<BorrowedFd<'_>>,
    timeout: Duration,
) -> Result<WireResponse, BrokerError> {
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|e| BrokerError::Failed(e.to_string()))?;

    let mut line = serde_json::to_vec(request).map_err(|e| BrokerError::Failed(e.to_string()))?;
    line.push(b'\n');
    let mut writer = stream;
    writer
        .write_all(&line)
        .and_then(|()| writer.flush())
        .map_err(|e| BrokerError::Failed(format!("Failed to send request: {e}")))?;

    if let Some(requester) = requester {
        wait_for_response(stream, requester)?;
    }

    // Zeroized when dropped, as a response can carry a private key. Sized so a
    // key response does not grow the buffer and leave copies behind.
    let mut response_line = Zeroizing::new(String::with_capacity(RESPONSE_CAPACITY));
    BufReader::new(stream)
        .read_line(&mut response_line)
        .map_err(|e| match e.kind() {
            // macOS reports an expired socket read timeout as WouldBlock.
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                BrokerError::Failed("Timed out waiting for a response".to_string())
            },
            _ => BrokerError::Failed(format!("Failed to read response: {e}")),
        })?;
    if response_line.trim().is_empty() {
        // The app went away mid-request.
        return Err(BrokerError::Disconnected);
    }

    serde_json::from_str(&response_line)
        .map_err(|e| BrokerError::Failed(format!("Malformed response: {e}")))
}

/// Wait until the broker's response can be read, for up to
/// [`RESPONSE_TIMEOUT`]. Returns early with
/// [`BrokerError::RequesterDisconnected`] if `requester` closes its end first.
///
/// A requester only waits while the request is out, so its socket turning
/// readable means it disconnected. If it sent data instead, it is left alone
/// and only the broker is watched.
pub(super) fn wait_for_response(
    stream: &std::os::unix::net::UnixStream,
    requester: BorrowedFd<'_>,
) -> Result<(), BrokerError> {
    let timed_out = || BrokerError::Failed("Timed out waiting for a response".to_string());
    let deadline = std::time::Instant::now() + RESPONSE_TIMEOUT;
    let mut watch_requester = true;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(timed_out());
        }
        let mut fds = [
            libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                // poll skips a negative descriptor.
                fd: if watch_requester {
                    requester.as_raw_fd()
                } else {
                    -1
                },
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
        if ready < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(BrokerError::Failed(format!(
                "Failed to wait for a response: {e}"
            )));
        }
        if ready == 0 {
            return Err(timed_out());
        }
        // Readable, closed, or failed: the read that follows reports which.
        if fds[0].revents != 0 {
            return Ok(());
        }
        if fds[1].revents != 0 {
            let mut byte = 0u8;
            let peeked = unsafe {
                libc::recv(
                    requester.as_raw_fd(),
                    (&raw mut byte).cast(),
                    1,
                    libc::MSG_PEEK | libc::MSG_DONTWAIT,
                )
            };
            match peeked {
                0 => return Err(BrokerError::RequesterDisconnected),
                n if n > 0 => watch_requester = false,
                _ => {
                    let e = std::io::Error::last_os_error();
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        return Err(BrokerError::RequesterDisconnected);
                    }
                },
            }
        }
    }
}

fn connect() -> std::io::Result<std::os::unix::net::UnixStream> {
    std::os::unix::net::UnixStream::connect(broker_socket_path())
}

fn wait_for_broker() -> Result<std::os::unix::net::UnixStream, BrokerError> {
    let deadline = std::time::Instant::now() + LAUNCH_TIMEOUT;
    loop {
        if let Ok(stream) = connect() {
            return Ok(stream);
        }
        if std::time::Instant::now() >= deadline {
            log::warn!("The app did not start serving signing requests in time");
            return Err(BrokerError::Unavailable);
        }
        std::thread::sleep(LAUNCH_POLL_INTERVAL);
    }
}
