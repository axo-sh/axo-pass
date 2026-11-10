//! The browsers the native messaging host serves: how each is identified, and
//! where each looks for the host's native messaging manifest.
//!
//! The host checks the installed manifest at startup. The app writes the same
//! manifests from this table.

use std::path::PathBuf;

/// Native messaging host name. Names the manifest file, and the extension
/// passes it to `runtime.connectNative`.
pub const NATIVE_HOST_NAME: &str = "com.breakfastlabs.axo_pass";

/// Gecko id of the Firefox extension, listed in the Firefox manifest's
/// `allowed_extensions`.
pub const FIREFOX_EXTENSION_ID: &str = "axo-pass@breakfastlabs.com";

/// Id of the Chrome extension, derived from the `key` in its manifest and
/// listed in the Chrome manifest's `allowed_origins`.
///
/// Placeholder until the Chrome package key exists. A release build verifies
/// no Chrome extension until it is set.
pub const CHROME_EXTENSION_ID: &str = "unset";

/// A browser whose main process may start the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Browser {
    Chrome,
    Firefox,
}

impl Browser {
    pub const ALL: [Browser; 2] = [Browser::Chrome, Browser::Firefox];

    /// Display name in prompts, notifications, and grant keys.
    pub fn name(self) -> &'static str {
        match self {
            Browser::Chrome => "Google Chrome",
            Browser::Firefox => "Firefox",
        }
    }

    /// Team identifier of the browser code signature.
    pub fn team_id(self) -> &'static str {
        match self {
            Browser::Chrome => "EQHXZ8M8AV",
            Browser::Firefox => "43AQ936H96",
        }
    }

    pub fn from_team_id(team_id: &str) -> Option<Browser> {
        Self::ALL.into_iter().find(|b| b.team_id() == team_id)
    }

    /// Directory the browser reads native messaging manifests from, for the
    /// current user.
    pub fn manifest_dir(self) -> Option<PathBuf> {
        let relative = match self {
            Browser::Chrome => "Library/Application Support/Google/Chrome/NativeMessagingHosts",
            Browser::Firefox => "Library/Application Support/Mozilla/NativeMessagingHosts",
        };
        Some(dirs::home_dir()?.join(relative))
    }

    /// Path of the host manifest the app installs for this browser.
    pub fn manifest_path(self) -> Option<PathBuf> {
        Some(
            self.manifest_dir()?
                .join(format!("{NATIVE_HOST_NAME}.json")),
        )
    }

    /// The extension identity this browser passes the host: the origin for
    /// Chrome, the extension id for Firefox.
    pub fn expected_extension(self) -> String {
        match self {
            Browser::Chrome => format!("chrome-extension://{CHROME_EXTENSION_ID}/"),
            Browser::Firefox => FIREFOX_EXTENSION_ID.to_string(),
        }
    }
}

/// Code requirement satisfied by the main process of any browser in
/// [`Browser::ALL`].
pub(super) fn browser_requirement() -> String {
    let teams = Browser::ALL
        .iter()
        .map(|b| format!("certificate leaf[subject.OU] = \"{}\"", b.team_id()))
        .collect::<Vec<_>>()
        .join(" or ");
    format!("anchor apple generic and ({teams})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requirement_names_every_team() {
        let requirement = browser_requirement();
        assert_eq!(
            requirement,
            "anchor apple generic and (certificate leaf[subject.OU] = \"EQHXZ8M8AV\" or \
             certificate leaf[subject.OU] = \"43AQ936H96\")"
        );
    }

    #[test]
    fn manifest_paths_are_per_browser() {
        let chrome = Browser::Chrome.manifest_path().unwrap();
        let firefox = Browser::Firefox.manifest_path().unwrap();
        assert!(
            chrome.ends_with("Google/Chrome/NativeMessagingHosts/com.breakfastlabs.axo_pass.json")
        );
        assert!(firefox.ends_with("Mozilla/NativeMessagingHosts/com.breakfastlabs.axo_pass.json"));
    }

    #[test]
    fn team_ids_map_back_to_browsers() {
        for browser in Browser::ALL {
            assert_eq!(Browser::from_team_id(browser.team_id()), Some(browser));
        }
        assert_eq!(Browser::from_team_id("ABCDE12345"), None);
    }
}
