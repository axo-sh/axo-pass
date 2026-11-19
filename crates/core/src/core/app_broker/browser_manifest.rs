//! Native messaging manifests for the browsers in [`Browser::ALL`].
//!
//! Each manifest names the host executable and the extension allowed to start
//! it. Chrome lists the extension origin in `allowed_origins`. Firefox lists
//! the extension id in `allowed_extensions`.
//!
//! Store extensions cannot install a manifest, so the app installs one for
//! each installed browser on launch. The manifest directories are writable by
//! the user, so the launch check also rewrites any manifest we own that names
//! another host. A manifest whose `name` is not [`NATIVE_HOST_NAME`] is never
//! written.
//!
//! Known limitation: development and release builds each point the manifests
//! at their own host, so they rewrite each other's manifests. The last app
//! launched wins.

use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;
use thiserror::Error;

use super::BROWSER_HOST_EXECUTABLE_NAME;
use super::browsers::{
    Browser, CHROME_EXTENSION_ID, FIREFOX_EXTENSION_ID, NATIVE_HOST_NAME, same_file,
};
use crate::core::files::write_atomic;

const DESCRIPTION: &str = "Axo Pass";

/// State of the installed manifest for one browser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestState {
    /// No manifest file.
    NotInstalled,
    /// Manifest names the expected host and extension.
    Current,
    /// Manifest is ours and names another host executable, or none.
    PointsElsewhere { path: Option<PathBuf> },
    /// Manifest is ours and names the expected host. Its type or allowed
    /// extensions differ from the expected manifest.
    Outdated,
    /// Manifest names another host. It is never written.
    Foreign { name: String },
    /// Manifest could not be read or parsed.
    Unreadable { reason: String },
}

/// Manifest state for one browser.
#[derive(Debug, Clone)]
pub struct ManifestStatus {
    pub browser: Browser,
    /// Whether the browser has a support directory for this user.
    pub browser_installed: bool,
    pub manifest_path: PathBuf,
    pub state: ManifestState,
}

impl ManifestStatus {
    /// Whether the launch check writes this manifest. A missing manifest is
    /// written if the browser is installed. A manifest we own is rewritten if
    /// it differs from the expected manifest.
    pub fn needs_write(&self) -> bool {
        match self.state {
            ManifestState::NotInstalled => self.browser_installed,
            ManifestState::PointsElsewhere { .. } | ManifestState::Outdated => true,
            ManifestState::Current
            | ManifestState::Foreign { .. }
            | ManifestState::Unreadable { .. } => false,
        }
    }
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("{} is not installed", browser.name())]
    BrowserNotInstalled { browser: Browser },

    #[error("{} names the host {name}, not {NATIVE_HOST_NAME}", path.display())]
    Foreign { path: PathBuf, name: String },

    #[error("Browser host not found at {}", path.display())]
    HostMissing { path: PathBuf },

    #[error("Could not write {}: {source}", path.display())]
    Write { path: PathBuf, source: io::Error },
}

/// Manifest contents for one browser.
#[derive(Serialize)]
struct HostManifest<'a> {
    name: &'a str,
    description: &'a str,
    path: &'a Path,
    #[serde(rename = "type")]
    kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed_origins: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed_extensions: Option<Vec<String>>,
}

/// Key of the allowed extension list and its expected entries.
fn allowed(browser: Browser) -> (&'static str, Vec<String>) {
    match browser {
        Browser::Chrome => (
            "allowed_origins",
            vec![format!("chrome-extension://{CHROME_EXTENSION_ID}/")],
        ),
        Browser::Firefox => ("allowed_extensions", vec![FIREFOX_EXTENSION_ID.to_string()]),
    }
}

/// Manifest JSON for `browser` naming `host`.
pub fn manifest_json(browser: Browser, host: &Path) -> String {
    let (_, entries) = allowed(browser);
    let (allowed_origins, allowed_extensions) = match browser {
        Browser::Chrome => (Some(entries), None),
        Browser::Firefox => (None, Some(entries)),
    };
    let manifest = HostManifest {
        name: NATIVE_HOST_NAME,
        description: DESCRIPTION,
        path: host,
        kind: "stdio",
        allowed_origins,
        allowed_extensions,
    };
    let mut json = serde_json::to_string_pretty(&manifest).expect("manifest serializes");
    json.push('\n');
    json
}

/// The host executable beside the running executable. In the app bundle this
/// is `Contents/MacOS/AxoPassBrowserHost`. Beside a development `ap`, it is the
/// host built into the same target directory.
pub fn sibling_host_path() -> Option<PathBuf> {
    let exe = std::env::current_exe()
        .inspect_err(|e| log::debug!("Failed to get exe path: {e}"))
        .ok()?;
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    Some(exe.parent()?.join(BROWSER_HOST_EXECUTABLE_NAME))
}

/// Reads and writes the manifests under one home directory for one host.
pub struct BrowserManifests {
    home: PathBuf,
    host: PathBuf,
}

impl BrowserManifests {
    pub fn new(home: PathBuf, host: PathBuf) -> Self {
        BrowserManifests { home, host }
    }

    /// Manifests of the current user, naming the host beside the running
    /// executable.
    pub fn for_current_user() -> Option<Self> {
        Some(Self::new(dirs::home_dir()?, sibling_host_path()?))
    }

    /// Host executable the manifests are written to name.
    pub fn host(&self) -> &Path {
        &self.host
    }

    pub fn statuses(&self) -> Vec<ManifestStatus> {
        Browser::ALL.into_iter().map(|b| self.status(b)).collect()
    }

    pub fn status(&self, browser: Browser) -> ManifestStatus {
        let manifest_path = browser.manifest_path_in(&self.home);
        ManifestStatus {
            browser,
            browser_installed: browser.is_installed_in(&self.home),
            state: self.read_state(browser, &manifest_path),
            manifest_path,
        }
    }

    fn read_state(&self, browser: Browser, manifest_path: &Path) -> ManifestState {
        let text = match std::fs::read_to_string(manifest_path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return ManifestState::NotInstalled,
            Err(e) => {
                return ManifestState::Unreadable {
                    reason: e.to_string(),
                };
            },
        };
        let value: serde_json::Value = match serde_json::from_str(&text) {
            Ok(value) => value,
            Err(e) => {
                return ManifestState::Unreadable {
                    reason: e.to_string(),
                };
            },
        };
        let Some(name) = value["name"].as_str() else {
            return ManifestState::Unreadable {
                reason: "The manifest has no name".to_string(),
            };
        };
        if name != NATIVE_HOST_NAME {
            return ManifestState::Foreign {
                name: name.to_string(),
            };
        }

        let path = value["path"].as_str().map(PathBuf::from);
        if !path
            .as_deref()
            .is_some_and(|path| same_file(path, &self.host))
        {
            return ManifestState::PointsElsewhere { path };
        }

        let (key, expected) = allowed(browser);
        let entries: Option<Vec<&str>> = value[key]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect());
        if value["type"] != "stdio"
            || entries != Some(expected.iter().map(String::as_str).collect())
        {
            return ManifestState::Outdated;
        }
        ManifestState::Current
    }

    /// Write the manifest for `browser`. Creates the manifest directory if the
    /// browser is installed. Refuses a manifest that names another host.
    pub fn install(&self, browser: Browser) -> Result<ManifestStatus, ManifestError> {
        if !self.host.is_file() {
            return Err(ManifestError::HostMissing {
                path: self.host.clone(),
            });
        }
        let status = self.status(browser);
        if let ManifestState::Foreign { name } = status.state {
            return Err(ManifestError::Foreign {
                path: status.manifest_path,
                name,
            });
        }
        if !status.browser_installed {
            return Err(ManifestError::BrowserNotInstalled { browser });
        }
        self.write(browser, &status.manifest_path)?;
        Ok(self.status(browser))
    }

    fn write(&self, browser: Browser, manifest_path: &Path) -> Result<(), ManifestError> {
        let write_error = |source| ManifestError::Write {
            path: manifest_path.to_path_buf(),
            source,
        };
        let dir = browser.manifest_dir_in(&self.home);
        std::fs::create_dir_all(&dir).map_err(write_error)?;
        write_atomic(manifest_path, manifest_json(browser, &self.host).as_bytes())
            .map_err(write_error)
    }

    /// Install a missing manifest for each installed browser, and rewrite
    /// every manifest we own that names another host or differs from the
    /// expected manifest. Foreign and unreadable manifests are left alone.
    /// Returns the browsers whose manifest was written.
    pub fn ensure(&self) -> Vec<Browser> {
        if !self.host.is_file() {
            log::warn!(
                "Browser host not found at {}, manifests not checked",
                self.host.display()
            );
            return Vec::new();
        }
        let mut written = Vec::new();
        for status in self.statuses() {
            let browser = status.browser.name();
            match &status.state {
                ManifestState::Foreign { name } => {
                    log::warn!(
                        "{} names the host {name}, left unchanged",
                        status.manifest_path.display()
                    );
                },
                ManifestState::Unreadable { reason } => {
                    log::warn!(
                        "{} is unreadable, left unchanged: {reason}",
                        status.manifest_path.display()
                    );
                },
                state if status.needs_write() => {
                    log::info!("Writing the {browser} manifest ({state:?})");
                    match self.write(status.browser, &status.manifest_path) {
                        Ok(()) => written.push(status.browser),
                        Err(e) => log::warn!("Could not write the {browser} manifest: {e}"),
                    }
                },
                _ => {},
            }
        }
        written
    }
}

#[cfg(test)]
mod tests;
