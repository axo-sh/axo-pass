//! Stub of the folder watch on Linux. The inotify watch through the `notify`
//! crate replaces it. A transport without a watch is polled by the sync
//! manager.

use std::path::Path;

use crate::secrets::vaults::sync::transport::WatchHandle;

/// Watch of the folder transport. No value of this type exists on Linux yet.
pub struct FolderWatch;

impl FolderWatch {
    /// Always `None`, which reports a transport with no watch.
    pub fn start(_root: &Path, _dir: &Path, _notify: Box<dyn Fn() + Send>) -> Option<WatchHandle> {
        None
    }
}
