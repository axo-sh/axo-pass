//! The browsers the native messaging host serves: how each is identified, and
//! where each looks for the host's native messaging manifest.
//!
//! The host checks the installed manifest at startup. The app writes the same
//! manifests from this table.

use std::path::{Path, PathBuf};

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

    /// Short lowercase identifier for command arguments.
    pub fn id(self) -> &'static str {
        match self {
            Browser::Chrome => "chrome",
            Browser::Firefox => "firefox",
        }
    }

    pub fn from_id(id: &str) -> Option<Browser> {
        Self::ALL.into_iter().find(|b| b.id() == id)
    }

    /// Support directories the browser creates for the user, relative to the
    /// home directory. The browser counts as installed if any of them exists.
    /// The first entry holds the manifest directory.
    fn support_dirs(self) -> &'static [&'static str] {
        match self {
            Browser::Chrome => &["Library/Application Support/Google/Chrome"],
            Browser::Firefox => &[
                "Library/Application Support/Mozilla",
                "Library/Application Support/Firefox",
            ],
        }
    }

    /// Whether the browser has a support directory under `home`.
    pub fn is_installed_in(self, home: &Path) -> bool {
        self.support_dirs()
            .iter()
            .any(|dir| home.join(dir).is_dir())
    }

    /// Directory the browser reads native messaging manifests from, under
    /// `home`.
    pub fn manifest_dir_in(self, home: &Path) -> PathBuf {
        home.join(self.support_dirs()[0])
            .join("NativeMessagingHosts")
    }

    /// Path of the host manifest the app installs for this browser, under
    /// `home`.
    pub fn manifest_path_in(self, home: &Path) -> PathBuf {
        self.manifest_dir_in(home)
            .join(format!("{NATIVE_HOST_NAME}.json"))
    }

    /// Directory the browser reads native messaging manifests from, for the
    /// current user.
    pub fn manifest_dir(self) -> Option<PathBuf> {
        Some(self.manifest_dir_in(&dirs::home_dir()?))
    }

    /// Path of the host manifest the app installs for this browser, for the
    /// current user.
    pub fn manifest_path(self) -> Option<PathBuf> {
        Some(self.manifest_path_in(&dirs::home_dir()?))
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

/// Compare two paths after resolving symlinks. A path that does not resolve
/// matches nothing.
pub(super) fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
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

    #[test]
    fn ids_map_back_to_browsers() {
        for browser in Browser::ALL {
            assert_eq!(Browser::from_id(browser.id()), Some(browser));
        }
        assert_eq!(Browser::from_id("safari"), None);
    }
}
