use serde::Serialize;

use crate::secrets::keychain::generic_password::PasswordEntry;

/// Trait for password requests that can be handled by the generic handler
pub trait PasswordRequest: Clone + Serialize {
    /// Get the key identifier for keychain operations
    fn entry(&self) -> Option<PasswordEntry>;

    /// Check if this request has a saved password available
    fn has_saved_password(&self) -> bool;

    /// Check if this request is currently attempting to use saved password
    fn is_attempting_saved_password(&self) -> bool;

    /// Set whether this request should attempt to use saved password
    fn set_attempting_saved_password(&mut self, attempting: bool);

    /// Set whether this request has a saved password available
    fn set_has_saved_password(&mut self, has_saved: bool);
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasswordResponse {
    UseSavedPassword,
    Confirmed,
    Cancelled,
    Password {
        value: String,
        save_to_keychain: bool,
    },
}

impl PasswordResponse {
    pub fn is_password(&self) -> bool {
        matches!(self, PasswordResponse::Password { .. })
    }

    pub fn into_password(self) -> Option<(String, bool)> {
        match self {
            PasswordResponse::Password {
                value,
                save_to_keychain,
            } => Some((value, save_to_keychain)),
            _ => None,
        }
    }

    pub fn is_use_saved_password(&self) -> bool {
        matches!(self, PasswordResponse::UseSavedPassword)
    }

    pub fn is_cancelled(&self) -> bool {
        matches!(self, PasswordResponse::Cancelled)
    }

    pub fn is_confirmed(&self) -> bool {
        matches!(self, PasswordResponse::Confirmed)
    }
}

/// Internal state for the password request state machine
#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestEvent<R: PasswordRequest> {
    /// Initial request for password
    GetPassword(R),
    /// Request for user confirmation
    Confirm { description: Option<String> },
    /// Display a message to the user
    Message { description: Option<String> },
    /// Internal state: successfully retrieved password
    Success(String),
}
