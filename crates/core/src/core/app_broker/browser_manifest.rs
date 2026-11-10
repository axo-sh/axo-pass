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
mod tests {
    use super::*;

    struct Fixture {
        _dir: tempfile::TempDir,
        home: PathBuf,
        host: PathBuf,
        manifests: BrowserManifests,
    }

    /// Temp home with both browsers installed and a host executable.
    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        for dir in [
            "Library/Application Support/Google/Chrome",
            "Library/Application Support/Mozilla",
        ] {
            std::fs::create_dir_all(home.join(dir)).unwrap();
        }
        let host = dir.path().join(BROWSER_HOST_EXECUTABLE_NAME);
        std::fs::write(&host, "").unwrap();
        let manifests = BrowserManifests::new(home.clone(), host.clone());
        Fixture {
            _dir: dir,
            home,
            host,
            manifests,
        }
    }

    fn write_manifest(f: &Fixture, browser: Browser, value: serde_json::Value) -> PathBuf {
        let path = browser.manifest_path_in(&f.home);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, value.to_string()).unwrap();
        path
    }

    fn read_json(path: &Path) -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn chrome_manifest_lists_allowed_origins() {
        let json: serde_json::Value =
            serde_json::from_str(&manifest_json(Browser::Chrome, Path::new("/h"))).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "name": "com.breakfastlabs.axo_pass",
                "description": "Axo Pass",
                "path": "/h",
                "type": "stdio",
                "allowed_origins": [format!("chrome-extension://{CHROME_EXTENSION_ID}/")],
            })
        );
    }

    #[test]
    fn firefox_manifest_lists_allowed_extensions() {
        let json: serde_json::Value =
            serde_json::from_str(&manifest_json(Browser::Firefox, Path::new("/h"))).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "name": "com.breakfastlabs.axo_pass",
                "description": "Axo Pass",
                "path": "/h",
                "type": "stdio",
                "allowed_extensions": ["axo-pass@breakfastlabs.com"],
            })
        );
    }

    #[test]
    fn install_writes_into_temp_home() {
        let f = fixture();
        for browser in Browser::ALL {
            assert_eq!(
                f.manifests.status(browser).state,
                ManifestState::NotInstalled
            );
            let status = f.manifests.install(browser).unwrap();
            assert_eq!(status.state, ManifestState::Current);
            assert!(status.manifest_path.starts_with(&f.home));
            assert_eq!(
                std::fs::read_to_string(&status.manifest_path).unwrap(),
                manifest_json(browser, &f.host)
            );
        }
    }

    #[test]
    fn install_needs_browser_support_dir() {
        let f = fixture();
        std::fs::remove_dir_all(f.home.join("Library/Application Support/Google")).unwrap();
        let status = f.manifests.status(Browser::Chrome);
        assert!(!status.browser_installed);
        assert!(matches!(
            f.manifests.install(Browser::Chrome),
            Err(ManifestError::BrowserNotInstalled { .. })
        ));
        assert!(!Browser::Chrome.manifest_dir_in(&f.home).exists());
    }

    #[test]
    fn firefox_support_dir_alone_counts_as_installed() {
        let f = fixture();
        std::fs::remove_dir_all(f.home.join("Library/Application Support/Mozilla")).unwrap();
        assert!(!Browser::Firefox.is_installed_in(&f.home));
        std::fs::create_dir_all(f.home.join("Library/Application Support/Firefox")).unwrap();
        let status = f.manifests.install(Browser::Firefox).unwrap();
        assert_eq!(status.state, ManifestState::Current);
        assert!(status.manifest_path.ends_with(
            "Library/Application Support/Mozilla/NativeMessagingHosts/com.breakfastlabs.axo_pass.json"
        ));
    }

    #[test]
    fn install_refuses_missing_host() {
        let f = fixture();
        std::fs::remove_file(&f.host).unwrap();
        assert!(matches!(
            f.manifests.install(Browser::Firefox),
            Err(ManifestError::HostMissing { .. })
        ));
    }

    #[test]
    fn detects_each_state() {
        let f = fixture();
        let browser = Browser::Firefox;
        let state = |value: serde_json::Value| {
            write_manifest(&f, browser, value);
            f.manifests.status(browser).state
        };
        let ours = |path: &str, allowed: &[&str]| {
            serde_json::json!({
                "name": NATIVE_HOST_NAME,
                "path": path,
                "type": "stdio",
                "allowed_extensions": allowed,
            })
        };
        let host = f.host.to_str().unwrap();

        assert_eq!(
            state(ours(host, &[FIREFOX_EXTENSION_ID])),
            ManifestState::Current
        );

        let link = f.host.with_file_name("link");
        std::os::unix::fs::symlink(&f.host, &link).unwrap();
        assert_eq!(
            state(ours(link.to_str().unwrap(), &[FIREFOX_EXTENSION_ID])),
            ManifestState::Current
        );

        assert_eq!(
            state(ours("/usr/bin/true", &[FIREFOX_EXTENSION_ID])),
            ManifestState::PointsElsewhere {
                path: Some(PathBuf::from("/usr/bin/true"))
            }
        );
        assert_eq!(
            state(serde_json::json!({"name": NATIVE_HOST_NAME})),
            ManifestState::PointsElsewhere { path: None }
        );
        assert_eq!(
            state(ours(host, &["evil@example.com"])),
            ManifestState::Outdated
        );
        assert_eq!(
            state(serde_json::json!({"name": "com.example.other", "path": host})),
            ManifestState::Foreign {
                name: "com.example.other".to_string()
            }
        );
        assert!(matches!(
            state(serde_json::json!({"path": host})),
            ManifestState::Unreadable { .. }
        ));

        let path = browser.manifest_path_in(&f.home);
        std::fs::write(&path, "{not json").unwrap();
        assert!(matches!(
            f.manifests.status(browser).state,
            ManifestState::Unreadable { .. }
        ));
    }

    #[test]
    fn chrome_state_checks_allowed_origins() {
        let f = fixture();
        let host = f.host.to_str().unwrap();
        // A Firefox-style manifest in the Chrome directory lacks allowed_origins.
        write_manifest(
            &f,
            Browser::Chrome,
            serde_json::json!({
                "name": NATIVE_HOST_NAME,
                "path": host,
                "type": "stdio",
                "allowed_extensions": [FIREFOX_EXTENSION_ID],
            }),
        );
        assert_eq!(
            f.manifests.status(Browser::Chrome).state,
            ManifestState::Outdated
        );
        f.manifests.install(Browser::Chrome).unwrap();
        assert_eq!(
            f.manifests.status(Browser::Chrome).state,
            ManifestState::Current
        );
    }

    #[test]
    fn ensure_rewrites_only_a_differing_path() {
        let f = fixture();
        f.manifests.install(Browser::Chrome).unwrap();
        let firefox = write_manifest(
            &f,
            Browser::Firefox,
            serde_json::json!({
                "name": NATIVE_HOST_NAME,
                "path": "/usr/bin/true",
                "type": "stdio",
                "allowed_extensions": [FIREFOX_EXTENSION_ID],
            }),
        );
        // Mark the current manifest so a rewrite would be visible.
        let chrome = Browser::Chrome.manifest_path_in(&f.home);
        let mut marked = read_json(&chrome);
        marked["description"] = "kept".into();
        std::fs::write(&chrome, marked.to_string()).unwrap();

        assert_eq!(f.manifests.ensure(), vec![Browser::Firefox]);
        assert_eq!(read_json(&chrome)["description"], "kept");
        assert_eq!(read_json(&firefox)["path"], f.host.to_str().unwrap());
        assert_eq!(
            f.manifests.status(Browser::Firefox).state,
            ManifestState::Current
        );

        assert_eq!(f.manifests.ensure(), Vec::<Browser>::new());
    }

    #[test]
    fn ensure_installs_missing_manifests_of_installed_browsers() {
        let f = fixture();
        assert_eq!(f.manifests.ensure(), Browser::ALL.to_vec());
        for browser in Browser::ALL {
            assert_eq!(f.manifests.status(browser).state, ManifestState::Current);
        }
        assert_eq!(f.manifests.ensure(), Vec::<Browser>::new());
    }

    #[test]
    fn ensure_skips_browsers_that_are_not_installed() {
        let f = fixture();
        std::fs::remove_dir_all(f.home.join("Library/Application Support/Google")).unwrap();
        assert_eq!(f.manifests.ensure(), vec![Browser::Firefox]);
        assert!(!Browser::Chrome.manifest_dir_in(&f.home).exists());
    }

    #[test]
    fn ensure_writes_nothing_without_host() {
        let f = fixture();
        std::fs::remove_file(&f.host).unwrap();
        assert_eq!(f.manifests.ensure(), Vec::<Browser>::new());
        for browser in Browser::ALL {
            assert!(!browser.manifest_path_in(&f.home).exists());
        }
    }

    #[test]
    fn foreign_and_unreadable_manifests_are_untouched() {
        let f = fixture();
        let foreign = serde_json::json!({"name": "com.example.other", "path": "/usr/bin/true"});
        let chrome = write_manifest(&f, Browser::Chrome, foreign.clone());
        let firefox = Browser::Firefox.manifest_path_in(&f.home);
        std::fs::create_dir_all(firefox.parent().unwrap()).unwrap();
        std::fs::write(&firefox, "{not json").unwrap();

        assert_eq!(f.manifests.ensure(), Vec::<Browser>::new());
        assert_eq!(read_json(&chrome), foreign);
        assert_eq!(std::fs::read_to_string(&firefox).unwrap(), "{not json");

        assert!(matches!(
            f.manifests.install(Browser::Chrome),
            Err(ManifestError::Foreign { .. })
        ));
        assert_eq!(read_json(&chrome), foreign);
    }

    #[test]
    fn install_replaces_unreadable_manifest() {
        let f = fixture();
        let firefox = Browser::Firefox.manifest_path_in(&f.home);
        std::fs::create_dir_all(firefox.parent().unwrap()).unwrap();
        std::fs::write(&firefox, "{not json").unwrap();
        let status = f.manifests.install(Browser::Firefox).unwrap();
        assert_eq!(status.state, ManifestState::Current);
    }

    #[test]
    fn writes_leave_no_temp_files() {
        let f = fixture();
        f.manifests.install(Browser::Firefox).unwrap();
        f.manifests.install(Browser::Firefox).unwrap();
        let names: Vec<_> = std::fs::read_dir(Browser::Firefox.manifest_dir_in(&f.home))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            names,
            vec![std::ffi::OsString::from("com.breakfastlabs.axo_pass.json")]
        );
    }
}
