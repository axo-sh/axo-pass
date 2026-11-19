//! Broker parts for Linux. There is no Mach service and no app bundle.

use std::os::fd::AsFd;
use std::path::PathBuf;

use crate::core::app_broker::access::{Client, RequestScope, agent_policy, browser_host_policy};
use crate::core::app_broker::browsers::Browser;
use crate::core::app_broker::server::serve_on;
use crate::core::app_broker::{Authorizers, BrokerError, broker_socket_path};

/// Serve requests on the socket until `shutdown` resolves, then remove the
/// socket. There is no Mach service on Linux.
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

/// Nothing to set. Linux has no `SO_NOSIGPIPE` socket option.
pub(in crate::core::app_broker) fn disable_sigpipe(_stream: &impl AsFd) {}

/// Linux stub with no directories, so no browser counts as installed and
/// no manifest is written. The Linux paths are not decided yet.
pub(in crate::core::app_broker) fn support_dirs(_browser: Browser) -> &'static [&'static str] {
    &[]
}

/// There is no app bundle on Linux.
pub(crate) fn app_bundle_path() -> Option<PathBuf> {
    None
}

/// Nothing starts the daemon from the client on Linux. Socket activation
/// starts it when the client connects.
pub(in crate::core::app_broker) fn launch_app() -> Result<(), BrokerError> {
    Err(BrokerError::Unavailable)
}
