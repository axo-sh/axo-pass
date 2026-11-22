//! Watch of the folder transport.
//!
//! A [`RootWatch`] watches the root of one transport with one instance of
//! each signal: file events of the root, and the metadata query on macOS.
//! Each report of a signal holds the changed paths. Every watch of a
//! directory under the root is called if a path is under its directory, and
//! every watch is called for changes whose paths are not known, such as
//! dropped events. The end of a download that the transport requested calls
//! the watches of its [`Scope`]. The signals start with the first watch and
//! stop after the last watch ends.
//!
//! [`SharedNotify`] is the callback of one watch. Each call is recorded in
//! the sync log with its signal, so a log shows which signal reported a
//! change.

#[cfg(macos)]
pub mod metadata;

#[cfg(linux)]
mod linux;
#[cfg(macos)]
mod macos;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::{fmt, fs};

#[cfg(linux)]
pub use linux::FolderWatch;
#[cfg(macos)]
pub use macos::FolderWatch;
use uuid::Uuid;

#[cfg(macos)]
use self::metadata::MetadataWatch;
use crate::secrets::vaults::sync::sync_log::{self, Level};
use crate::secrets::vaults::sync::transport::WatchHandle;

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

/// Changes that a watch reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Files under the directory of a vault.
    Vault(Uuid),
    /// Files under `pairing/`.
    Pairings,
}

impl Scope {
    /// Vault of the sync log entries of this scope.
    pub fn vault_id(self) -> Option<Uuid> {
        match self {
            Self::Vault(vault_id) => Some(vault_id),
            Self::Pairings => None,
        }
    }
}

/// Changes of one report of a signal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Changes {
    /// Real paths that changed.
    Paths(Vec<PathBuf>),
    /// Changes whose paths are not known, such as dropped events. Every
    /// watch is called.
    Unknown,
}

/// Whether a change at `path` is a change under `dir`: the path is `dir`, a
/// path under it, or an ancestor of it.
pub fn matches(dir: &Path, path: &Path) -> bool {
    path.starts_with(dir) || dir.starts_with(path)
}

/// Callback of one watch, called by every signal of the watch. Calls never
/// overlap. The lock is held during the call, so the callback must not drop
/// the handle of its own watch.
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

/// Watch of one directory under the root.
struct Entry {
    id: u64,
    scope: Scope,
    /// Real path of the watched directory.
    dir: PathBuf,
    notify: Arc<SharedNotify>,
}

/// Running signals of a root. Drop stops them and waits for a call in
/// flight.
struct Signals {
    _files: FolderWatch,
    #[cfg(macos)]
    _query: Option<MetadataWatch>,
}

#[derive(Default)]
struct State {
    entries: Vec<Entry>,
    next_id: u64,
    /// `None` while no watch is live.
    signals: Option<Signals>,
}

/// Watches of the root of one transport, served by one instance of each
/// signal.
pub struct RootWatch {
    root: PathBuf,
    state: Mutex<State>,
}

impl RootWatch {
    pub fn new(root: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            root,
            state: Mutex::default(),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Watch the directory `dir` of the root and call `notify` for each
    /// report of a change under it. `vault_id` is the vault of the sync log
    /// entries. Starts the signals if no watch is live. `None` if the root is
    /// missing or is not a folder, or the file events cannot start. A
    /// metadata query that cannot start is logged and left out.
    ///
    /// The handle must not drop inside `notify`, since the drop of the last
    /// handle waits for the signals.
    pub fn add(
        self: &Arc<Self>,
        scope: Scope,
        vault_id: Option<Uuid>,
        dir: &Path,
        notify: Box<dyn Fn() + Send>,
    ) -> Option<WatchHandle> {
        let root = fs::canonicalize(&self.root).ok()?;
        if !root.is_dir() {
            return None;
        }
        let shared = SharedNotify::new(vault_id, notify);
        let id = {
            let mut state = self.state();
            if state.signals.is_none() {
                state.signals = Some(self.start_signals(&root)?);
            }
            let id = state.next_id;
            state.next_id += 1;
            state.entries.push(Entry {
                id,
                scope,
                dir: root.join(dir),
                notify: shared.clone(),
            });
            id
        };
        // The handle holds the watch, so the signals run while the handle
        // lives, even if the transport is dropped.
        let watch = self.clone();
        Some(WatchHandle::new(move || {
            shared.close();
            watch.remove(id);
        }))
    }

    /// Start each signal of the real root `root`. The signals hold a weak
    /// reference, so they do not keep the watch alive.
    fn start_signals(self: &Arc<Self>, root: &Path) -> Option<Signals> {
        let files = {
            let watch = Arc::downgrade(self);
            FolderWatch::start(
                root,
                Box::new(move |changes| Self::dispatch(&watch, &changes, Source::Files)),
            )?
        };
        #[cfg(macos)]
        let query = {
            let watch = Arc::downgrade(self);
            MetadataWatch::start(
                root,
                Box::new(move |changes| Self::dispatch(&watch, &changes, Source::MetadataQuery)),
            )
        };
        Some(Signals {
            _files: files,
            #[cfg(macos)]
            _query: query,
        })
    }

    /// End the watch `id`. The signals stop after the last watch ends. They
    /// are dropped outside the lock, so a call in flight can finish.
    fn remove(&self, id: u64) {
        let signals = {
            let mut state = self.state();
            state.entries.retain(|entry| entry.id != id);
            if state.entries.is_empty() {
                state.signals.take()
            } else {
                None
            }
        };
        drop(signals);
    }

    /// Call each watch of `watch` that `changes` reports, with `source`.
    fn dispatch(watch: &Weak<Self>, changes: &Changes, source: Source) {
        let Some(watch) = watch.upgrade() else {
            return;
        };
        watch.call_matching(source, |entry| match changes {
            Changes::Paths(paths) => paths.iter().any(|path| matches(&entry.dir, path)),
            Changes::Unknown => true,
        });
    }

    /// Call each watch of `scope` with `source`.
    pub fn call_scope(&self, scope: Scope, source: Source) {
        self.call_matching(source, |entry| entry.scope == scope);
    }

    /// Call each watch that `matched` selects with `source`, outside the
    /// lock.
    fn call_matching(&self, source: Source, matched: impl Fn(&Entry) -> bool) {
        let notify: Vec<Arc<SharedNotify>> = self
            .state()
            .entries
            .iter()
            .filter(|entry| matched(entry))
            .map(|entry| entry.notify.clone())
            .collect();
        for notify in notify {
            notify.call(source);
        }
    }

    /// Whether the signals run.
    #[cfg(test)]
    pub fn running(&self) -> bool {
        self.state().signals.is_some()
    }
}

impl fmt::Debug for RootWatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RootWatch")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}
