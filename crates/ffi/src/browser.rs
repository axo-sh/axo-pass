use axo_pass_core::core::app_broker::browser_manifest::{
    BrowserManifests, ManifestError, ManifestState, ManifestStatus,
};
use axo_pass_core::core::app_broker::browsers::Browser;

use crate::*;

/// A browser the native messaging host serves. Mirrors the core `Browser`.
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum BrowserKind {
    Chrome,
    Firefox,
}

impl From<Browser> for BrowserKind {
    fn from(browser: Browser) -> Self {
        match browser {
            Browser::Chrome => BrowserKind::Chrome,
            Browser::Firefox => BrowserKind::Firefox,
        }
    }
}

impl From<BrowserKind> for Browser {
    fn from(kind: BrowserKind) -> Self {
        match kind {
            BrowserKind::Chrome => Browser::Chrome,
            BrowserKind::Firefox => Browser::Firefox,
        }
    }
}

/// State of the installed native messaging manifest. Mirrors the core
/// `ManifestState`.
#[derive(uniffi::Enum, Clone, PartialEq, Eq)]
pub enum BrowserManifestState {
    NotInstalled,
    Current,
    /// Manifest names another host executable, or none.
    PointsElsewhere {
        path: Option<String>,
    },
    /// Manifest names this host with other allowed extensions.
    Outdated,
    /// Manifest names another native messaging host. It is never written.
    Foreign {
        name: String,
    },
    Unreadable {
        reason: String,
    },
}

impl From<ManifestState> for BrowserManifestState {
    fn from(state: ManifestState) -> Self {
        match state {
            ManifestState::NotInstalled => BrowserManifestState::NotInstalled,
            ManifestState::Current => BrowserManifestState::Current,
            ManifestState::PointsElsewhere { path } => BrowserManifestState::PointsElsewhere {
                path: path.map(|p| p.to_string_lossy().into_owned()),
            },
            ManifestState::Outdated => BrowserManifestState::Outdated,
            ManifestState::Foreign { name } => BrowserManifestState::Foreign { name },
            ManifestState::Unreadable { reason } => BrowserManifestState::Unreadable { reason },
        }
    }
}

#[derive(uniffi::Record)]
pub struct BrowserManifestStatus {
    pub browser: BrowserKind,
    /// Display name, such as "Google Chrome".
    pub name: String,
    /// Whether the browser has a support directory for this user.
    pub browser_installed: bool,
    pub manifest_path: String,
    pub state: BrowserManifestState,
}

impl From<ManifestStatus> for BrowserManifestStatus {
    fn from(status: ManifestStatus) -> Self {
        BrowserManifestStatus {
            browser: status.browser.into(),
            name: status.browser.name().to_string(),
            browser_installed: status.browser_installed,
            manifest_path: status.manifest_path.to_string_lossy().into_owned(),
            state: status.state.into(),
        }
    }
}

impl From<ManifestError> for FfiError {
    fn from(e: ManifestError) -> Self {
        match e {
            ManifestError::BrowserNotInstalled { .. } | ManifestError::Foreign { .. } => {
                FfiError::InvalidInput(e.to_string())
            },
            ManifestError::HostMissing { .. } => FfiError::NotFound(e.to_string()),
            ManifestError::Write { .. } => FfiError::Internal(e.to_string()),
        }
    }
}

fn manifests() -> Result<BrowserManifests, FfiError> {
    BrowserManifests::for_current_user()
        .ok_or_else(|| FfiError::Internal("No home directory or executable path".to_string()))
}

/// Native messaging manifest state for each browser, naming the host bundled
/// beside the app executable.
#[uniffi::export]
pub fn browser_manifest_statuses() -> Vec<BrowserManifestStatus> {
    manifests()
        .map(|m| m.statuses().into_iter().map(Into::into).collect())
        .unwrap_or_default()
}

/// Write the native messaging manifest for `browser`, naming the bundled host.
/// Refuses a manifest that names another host, and a browser with no support
/// directory.
#[uniffi::export(async_runtime = "tokio")]
pub async fn install_browser_manifest(
    browser: BrowserKind,
) -> Result<BrowserManifestStatus, FfiError> {
    tokio::task::spawn_blocking(move || {
        Ok(manifests()?
            .install(browser.into())
            .map_err(FfiError::from)?
            .into())
    })
    .await
    .map_err(|e| FfiError::Internal(e.to_string()))?
}

/// Install a missing manifest for each installed browser, and rewrite each
/// manifest we own that names another host or lists other extensions. Called
/// on launch. Foreign and unreadable manifests are left alone.
#[uniffi::export(async_runtime = "tokio")]
pub async fn ensure_browser_manifests() {
    let result = tokio::task::spawn_blocking(|| match manifests() {
        Ok(manifests) => {
            manifests.ensure();
        },
        Err(e) => log::warn!("Browser manifests not checked: {e}"),
    })
    .await;
    if let Err(e) = result {
        log::warn!("Browser manifest check failed: {e}");
    }
}
