//! Settings that other processes running as the user must not be able to
//! change.
//!
//! `config.toml` is user-writable, so a setting that limits what is recorded
//! on disk cannot live there. The settings are one JSON value in a
//! data-protection keychain item, which only code signed into the app's
//! keychain access group can read or write. See [`PlainItem`].
//!
//! `ap` holds no keychain entitlements. It reads the settings from the app
//! over the broker, and the app answers from the keychain. A new setting is a
//! new field with a serde default.

use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::audit::{self, Source};
#[cfg(feature = "desktop")]
use crate::core::app_broker;
use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::plain_item::PlainItem;

const SERVICE: &str = "com.breakfastlabs.frittata.protected-settings";
const ACCOUNT: &str = "settings";

/// Serializes updates, which read the item and write it back.
static UPDATE: Mutex<()> = Mutex::new(());

/// Every field has a default, which is the safe value. A missing item, an
/// unreadable item, and an unreachable app all give the defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedSettings {
    /// Whether the audit log records names, paths, and hosts. Off by default.
    #[serde(default)]
    pub audit_include_details: bool,
}

fn item() -> PlainItem {
    PlainItem::new(SERVICE, ACCOUNT)
}

impl ProtectedSettings {
    /// The settings as seen by this process. The app reads the keychain. Any
    /// other process asks the app, and gets the defaults if the app does not
    /// answer. Never starts the app.
    pub fn current() -> Self {
        if audit::process_source() == Source::App {
            return Self::load();
        }
        Self::request_from_app()
    }

    #[cfg(feature = "desktop")]
    fn request_from_app() -> Self {
        app_broker::request_protected_settings().unwrap_or_else(|e| {
            log::debug!("Protected settings unavailable, using defaults: {e}");
            Self::default()
        })
    }

    #[cfg(not(feature = "desktop"))]
    fn request_from_app() -> Self {
        Self::default()
    }

    /// Read the keychain item. Needs the app's keychain access group. Gives the
    /// defaults if the item is missing or cannot be read.
    pub fn load() -> Self {
        Self::try_load().unwrap_or_else(|e| {
            log::warn!("Failed to read protected settings: {e}");
            Self::default()
        })
    }

    fn try_load() -> Result<Self, KeychainError> {
        let Some(bytes) = item().read()? else {
            return Ok(Self::default());
        };
        Ok(serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            log::warn!("Protected settings are not valid, using defaults: {e}");
            Self::default()
        }))
    }

    /// Change the stored settings with `change`, and return the result. Fails
    /// if the item cannot be read or written, so a read error never overwrites
    /// stored settings with defaults.
    pub fn update(change: impl FnOnce(&mut Self)) -> Result<Self, KeychainError> {
        let _guard = UPDATE.lock().unwrap_or_else(|e| e.into_inner());
        let mut settings = Self::try_load()?;
        change(&mut settings);
        let bytes = serde_json::to_vec(&settings)
            .map_err(|e| KeychainError::AddFailed(format!("settings are not serializable: {e}")))?;
        item().write(&bytes)?;
        Ok(settings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_object_gives_defaults() {
        let parsed: ProtectedSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed, ProtectedSettings::default());
        assert!(!parsed.audit_include_details);
    }

    #[test]
    fn unknown_fields_ignored() {
        let parsed: ProtectedSettings =
            serde_json::from_str(r#"{"audit_include_details":true,"later":1}"#).unwrap();
        assert!(parsed.audit_include_details);
    }

    #[test]
    fn round_trip() {
        let settings = ProtectedSettings {
            audit_include_details: true,
        };
        let json = serde_json::to_string(&settings).unwrap();
        assert_eq!(
            serde_json::from_str::<ProtectedSettings>(&json).unwrap(),
            settings
        );
    }
}
