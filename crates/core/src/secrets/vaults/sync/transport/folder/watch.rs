//! Watch of the folder transport.
//!
//! A watch has several signals that call one callback: file events of the
//! root, the metadata query on macOS, and the end of a download that the
//! transport requested. [`SharedNotify`] joins them. Each call is recorded in
//! the sync log with its signal, so a log shows which signal reported a
//! change.

#[cfg(macos)]
pub mod metadata;

#[cfg(linux)]
mod linux;
#[cfg(macos)]
mod macos;

use std::fmt;
use std::sync::{Arc, Mutex};

#[cfg(linux)]
pub use linux::FolderWatch;
#[cfg(macos)]
pub use macos::FolderWatch;
use uuid::Uuid;

use crate::secrets::vaults::sync::sync_log::{self, Level};

/// Signal that reported a change under a watched directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// FSEvents on macOS, inotify on Linux.
    Files,
    /// Metadata query of the root, on macOS.
    #[cfg(macos)]
    MetadataQuery,
    /// A download that the transport requested ended.
    Download,
}

impl Source {
    /// Fixed text of the sync log entry of a call from this signal.
    fn message(self) -> &'static str {
        match self {
            Self::Files => "Watch event from file events",
            #[cfg(macos)]
            Self::MetadataQuery => "Watch event from the metadata query",
            Self::Download => "Watch event from a finished download",
        }
    }
}

/// Callback of one watch, called by every signal of the watch. Calls never
/// overlap.
pub struct SharedNotify {
    /// Vault of the watch, or `None` for the pairing watch.
    vault_id: Option<Uuid>,
    /// `None` once closed.
    notify: Mutex<Option<Box<dyn Fn() + Send>>>,
}

impl SharedNotify {
    pub fn new(vault_id: Option<Uuid>, notify: Box<dyn Fn() + Send>) -> Arc<Self> {
        Arc::new(Self {
            vault_id,
            notify: Mutex::new(Some(notify)),
        })
    }

    /// Record the call and call the callback, unless it is closed.
    pub fn call(&self, source: Source) {
        let notify = self.notify.lock().unwrap_or_else(|e| e.into_inner());
        let Some(notify) = notify.as_ref() else {
            return;
        };
        sync_log::record(Level::Info, self.vault_id, source.message(), None);
        notify();
    }

    /// Drop the callback, after a call in flight. No call follows.
    pub fn close(&self) {
        let mut notify = self.notify.lock().unwrap_or_else(|e| e.into_inner());
        *notify = None;
    }
}

impl fmt::Debug for SharedNotify {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedNotify")
            .field("vault_id", &self.vault_id)
            .finish_non_exhaustive()
    }
}
