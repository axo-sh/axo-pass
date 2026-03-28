use std::fmt::Display;
use std::sync::PoisonError;

use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::vaults::Error as VaultError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub enum AppErrorType {
    AuthenticationRequired,
    AuthenticationFailed,
    AuthenticationCancelled,
    AuthenticationExpired,
    NotFound,
    Internal,
    Unknown,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[typeshare]
pub struct AppError {
    #[serde(rename = "type")]
    error: AppErrorType,

    #[serde(rename = "message", skip_serializing_if = "Option::is_none")]
    user_message: Option<String>,

    #[serde(skip)]
    source: Option<String>,
}

impl AppError {
    pub fn new(
        error_type: AppErrorType,
        user_message: Option<String>,
        source: Option<String>,
    ) -> Self {
        let obj = Self {
            error: error_type,
            user_message,
            source,
        };
        // by default, log the error when it's created
        log::error!("{obj}");
        log::debug!(
            "AppError backtrace:\n{}",
            std::backtrace::Backtrace::capture()
        );
        obj
    }

    fn with_message(mut self, message: &str) -> Self {
        self.user_message = Some(message.to_string());
        self
    }

    fn internal_source(message: &str, source: &str) -> Self {
        Self::new(
            AppErrorType::Internal,
            Some(message.to_string()),
            Some(source.to_string()),
        )
    }

    pub fn internal(message: &str) -> Self {
        Self::new(AppErrorType::Internal, Some(message.to_string()), None)
    }

    pub fn not_found(message: &str) -> Self {
        Self::new(AppErrorType::NotFound, Some(message.to_string()), None)
    }
}

impl Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AppError({:?})", self.error)?;
        if let Some(msg) = &self.user_message {
            write!(f, ": {msg}")?;
        }
        if let Some(source) = &self.source {
            write!(f, "\nsource: {source:#}")?;
        }
        Ok(())
    }
}

impl From<AppErrorType> for AppError {
    fn from(error_type: AppErrorType) -> Self {
        let message = match error_type {
            AppErrorType::AuthenticationRequired => "Authentication is required.",
            AppErrorType::AuthenticationFailed => "Authentication failed.",
            AppErrorType::AuthenticationCancelled => "Authentication cancelled.",
            AppErrorType::AuthenticationExpired => "Authentication has expired.",
            AppErrorType::NotFound => "Requested item was not found.",
            AppErrorType::Internal => "An internal error occurred.",
            AppErrorType::Unknown => "An unknown error occurred.",
        };
        Self {
            error: error_type,
            user_message: Some(message.to_string()),
            source: None,
        }
    }
}

impl From<&KeychainError> for AppError {
    fn from(e: &KeychainError) -> Self {
        match e {
            KeychainError::UserCancelled => AppErrorType::AuthenticationCancelled.into(),
            KeychainError::AuthenticationExpired => AppErrorType::AuthenticationExpired.into(),
            _ => AppError::internal_source("Keychain error", &format!("{e:#}")),
        }
    }
}

impl From<KeychainError> for AppError {
    fn from(e: KeychainError) -> Self {
        (&e).into()
    }
}

impl From<&VaultError> for AppError {
    fn from(e: &VaultError) -> Self {
        match e {
            VaultError::VaultLocked => AppErrorType::AuthenticationRequired.into(),
            VaultError::VaultInvalidAuth(e) => e.into(),
            VaultError::KeyCreationFailed(e) | VaultError::KeyRetrievalFailed(e) => e.into(),
            _ => AppError::internal_source("Vault error", &format!("{e:#}")),
        }
    }
}

impl From<VaultError> for AppError {
    fn from(e: VaultError) -> Self {
        (&e).into()
    }
}

impl<T> From<PoisonError<T>> for AppError {
    fn from(e: PoisonError<T>) -> Self {
        AppError::new(
            AppErrorType::Internal,
            Some(format!("Failed to acquire state lock")),
            Some(format!("{e:#}")),
        )
    }
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        if let Some(vault_error) = e.downcast_ref::<VaultError>() {
            vault_error.into()
        } else if let Some(keychain_error) = e.downcast_ref::<KeychainError>() {
            keychain_error.into()
        } else if let Some(error_str) = e.downcast_ref::<&str>() {
            // if a context is attached, we can downcast to string
            AppError {
                error: AppErrorType::Internal,
                user_message: Some(error_str.to_string()),
                source: Some(format!("{e:#}")),
            }
        } else {
            AppError {
                error: AppErrorType::Internal,
                user_message: None,
                source: Some(format!("{e:#}")),
            }
        }
    }
}

pub trait ErrorContext<T, E> {
    fn error_context<C>(self, context: C) -> Result<T, AppError>
    where
        C: Display + Send + Sync + 'static;
}

impl<T, E> ErrorContext<T, E> for Result<T, E>
where
    E: Into<anyhow::Error>,
{
    fn error_context<C>(self, context: C) -> Result<T, AppError>
    where
        C: Display + Send + Sync + 'static,
    {
        match self {
            Ok(ok) => Ok(ok),
            Err(error) => {
                let anyhow_err: anyhow::Error = error.into();
                let app_error: AppError = anyhow_err.into();
                Err(app_error.with_message(&context.to_string()))
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;

    use super::*;
    use crate::secrets::keychain::errors::KeychainError;
    use crate::secrets::vaults::Error as VaultError;

    #[test]
    fn test_app_error_from_anyhow_error() {
        let anyhow_err = anyhow!("Base error");
        let app_error: AppError = anyhow_err.into();
        assert_eq!(
            app_error,
            AppError {
                error: AppErrorType::Internal,
                user_message: Some("Base error".to_string()),
                source: Some("Base error".to_string()),
            }
        );
    }
    #[test]
    fn test_app_error_from_anyhow_context() {
        let anyhow_err = anyhow!("Base error").context("Additional context");
        let app_error: AppError = anyhow_err.into();
        assert_eq!(
            app_error,
            AppError {
                error: AppErrorType::Internal,
                user_message: Some("Additional context".to_string()),
                source: Some("Additional context: Base error".to_string()),
            }
        );
    }

    #[test]
    fn test_display_error_type_only() {
        let err = AppError::from(AppErrorType::Internal);
        assert_eq!(
            err.to_string(),
            "AppError(Internal): An internal error occurred."
        );
    }

    #[test]
    fn test_display_with_user_message() {
        let mut err = AppError::from(AppErrorType::NotFound);
        err.user_message = Some("item not found".to_string());
        assert_eq!(err.to_string(), "AppError(NotFound): item not found");
    }

    #[test]
    fn test_display_with_source() {
        let err = AppError::internal_source("user message", "underlying cause");
        assert_eq!(
            err.to_string(),
            "AppError(Internal): user message\nsource: underlying cause"
        );
    }

    #[test]
    fn test_display_with_message_and_source() {
        let err = AppError::new(
            AppErrorType::AuthenticationFailed,
            Some("bad credentials".to_string()),
            Some("token expired".to_string()),
        );
        assert_eq!(
            err.to_string(),
            "AppError(AuthenticationFailed): bad credentials\nsource: token expired"
        );
    }

    #[test]
    fn test_json_serialization() {
        let err = AppError::new(
            AppErrorType::AuthenticationFailed,
            Some("bad credentials".to_string()),
            Some("token expired".to_string()),
        );
        let json = serde_json::to_string(&err).unwrap();
        assert_eq!(
            json,
            r#"{"type":"authentication_failed","message":"bad credentials"}"#
        );
    }

    #[test]
    fn test_error_context_ok_passthrough() {
        let result: Result<i32, anyhow::Error> = Ok(42);
        assert_eq!(result.error_context("should not matter").unwrap(), 42);
    }

    #[test]
    fn test_error_context_plain_error_uses_context_as_message() {
        let result: Result<(), anyhow::Error> = Err(anyhow!("underlying problem"));
        let err = result.error_context("Something went wrong").unwrap_err();
        assert_eq!(
            err,
            AppError {
                error: AppErrorType::Internal,
                user_message: Some("Something went wrong".to_string()),
                source: Some("underlying problem".to_string()),
            }
        );
    }

    #[test]
    fn test_error_context_preserves_vault_locked_type() {
        let result: Result<(), VaultError> = Err(VaultError::VaultLocked);
        let err = result.error_context("Could not access vault").unwrap_err();
        assert_eq!(
            err,
            AppError {
                error: AppErrorType::AuthenticationRequired,
                user_message: Some("Could not access vault".to_string()),
                source: None,
            }
        );
    }

    #[test]
    fn test_error_context_preserves_keychain_user_cancelled_type() {
        let result: Result<(), KeychainError> = Err(KeychainError::UserCancelled);
        let err = result.error_context("Operation cancelled").unwrap_err();
        assert_eq!(
            err,
            AppError {
                error: AppErrorType::AuthenticationCancelled,
                user_message: Some("Operation cancelled".to_string()),
                source: None,
            }
        );
    }

    #[test]
    fn test_error_context_preserves_keychain_auth_expired_type() {
        let result: Result<(), KeychainError> = Err(KeychainError::AuthenticationExpired);
        let err = result.error_context("Session expired").unwrap_err();
        assert_eq!(
            err,
            AppError {
                error: AppErrorType::AuthenticationExpired,
                user_message: Some("Session expired".to_string()),
                source: None,
            }
        );
    }
}
