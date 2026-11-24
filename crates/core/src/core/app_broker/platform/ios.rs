//! Broker parts for iOS. There is no broker, Mach service, or app bundle
//! lookup on iOS.

use std::os::fd::AsFd;
use std::path::PathBuf;

use crate::core::app_broker::browsers::Browser;
use crate::core::app_broker::{Authorizers, BrokerError};

/// Serve nothing until `shutdown` resolves. iOS has no broker socket.
pub async fn serve(
    _authorizers: Authorizers,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) -> std::io::Result<()> {
    let _ = shutdown.await;
    Ok(())
}

/// Nothing to set. The broker does not run on iOS.
pub(in crate::core::app_broker) fn disable_sigpipe(_stream: &impl AsFd) {}

/// No directories, so no browser counts as installed.
pub(in crate::core::app_broker) fn support_dirs(_browser: Browser) -> &'static [&'static str] {
    &[]
}

/// There is no app bundle to launch from the app on iOS.
pub(crate) fn app_bundle_path() -> Option<PathBuf> {
    None
}

/// Nothing starts the app from a client on iOS.
pub(in crate::core::app_broker) fn launch_app() -> Result<(), BrokerError> {
    Err(BrokerError::Unavailable)
}
