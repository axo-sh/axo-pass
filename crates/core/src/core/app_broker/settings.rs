//! `ap`'s side of the protected settings: ask the running app for them. See
//! [`ProtectedSettings`].

use super::BrokerError;
use super::client::query_request;
use super::wire::{WireRequest, WireResponse};
use crate::core::protected_settings::ProtectedSettings;

/// Read the protected settings from the app. Blocking. Fails with
/// [`BrokerError::Unavailable`] if the app is not running, and never starts it.
pub fn request_protected_settings() -> Result<ProtectedSettings, BrokerError> {
    match query_request(&WireRequest::GetProtectedSettings)? {
        WireResponse::ProtectedSettings { settings } => Ok(settings),
        WireResponse::Failed { message } => Err(BrokerError::Failed(message)),
        _ => Err(BrokerError::Failed(
            "Unexpected response to a settings request".to_string(),
        )),
    }
}
