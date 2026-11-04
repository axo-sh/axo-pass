//! Dismissed pairing requests, `sync/pairing.json` of the app data directory
//! (D12).
//!
//! The file holds the request ids that the user dismissed, by transport root,
//! so a dismissed request does not prompt again. It is unsigned and holds no
//! secret. A process that changes it can only make a request prompt again or
//! not prompt, and the code check covers every request whatever the file
//! holds. A file that fails to read or to parse is read as empty, which only
//! prompts again. It is not a vault file, so it alone does not make vault
//! files present.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::core::files::write_atomic;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::sync::local_state::SYNC_DIR;
use crate::secrets::vaults::sync::transport::{RequestId, TransportRoot};

/// Name of the file under `sync/`.
const FILE_NAME: &str = "pairing.json";

/// Dismissed request ids of each transport root.
///
/// The JSON form is a list with one entry per root, since a root is an
/// object and not a map key: `{"roots":[{"root":{"kind":"Folder","path":
/// "/Users/me/Dropbox/Vaults"},"requests":["0b5e…"]}]}`. The root has the
/// serde form of the sidecar `transport` field. Each id is a lowercase
/// hyphenated UUID.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DismissedRequests {
    roots: Vec<DismissedRoot>,
}

/// Dismissed request ids of one transport root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DismissedRoot {
    root: TransportRoot,
    requests: BTreeSet<RequestId>,
}

impl DismissedRequests {
    /// Path of the file under the app data directory `root`.
    pub fn path(root: &Path) -> PathBuf {
        root.join(SYNC_DIR).join(FILE_NAME)
    }

    /// Dismissed requests under the app data directory `root`. A file that
    /// is missing, cannot be read, or fails to parse is read as empty.
    pub fn load(root: &Path) -> Self {
        let path = Self::path(root);
        let contents = match fs::read(&path) {
            Ok(contents) => contents,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Self::default(),
            Err(e) => {
                log::warn!("Failed to read {}, read as empty: {e}", path.display());
                return Self::default();
            },
        };
        serde_json::from_slice(&contents).unwrap_or_else(|e| {
            log::warn!("Failed to parse {}, read as empty: {e}", path.display());
            Self::default()
        })
    }

    /// Write the file under the app data directory `root`, replacing it in
    /// one rename.
    pub fn save(&self, root: &Path) -> Result<(), Error> {
        let contents = serde_json::to_string_pretty(self)
            .map_err(|e| Error::SyncStateEncodeError(e.to_string()))?;
        fs::create_dir_all(root.join(SYNC_DIR)).map_err(Error::SyncStateWriteError)?;
        write_atomic(&Self::path(root), contents.as_bytes()).map_err(Error::SyncStateWriteError)
    }

    /// Dismissed request ids of `root`. Empty if the root has none.
    pub fn of(&self, root: &TransportRoot) -> BTreeSet<RequestId> {
        self.roots
            .iter()
            .find(|entry| entry.root == *root)
            .map(|entry| entry.requests.clone())
            .unwrap_or_default()
    }

    /// Replace the dismissed request ids of `root` with `requests`. A root
    /// with no id is removed.
    pub fn set(&mut self, root: &TransportRoot, requests: BTreeSet<RequestId>) {
        self.roots.retain(|entry| entry.root != *root);
        if !requests.is_empty() {
            self.roots.push(DismissedRoot {
                root: root.clone(),
                requests,
            });
        }
    }
}
