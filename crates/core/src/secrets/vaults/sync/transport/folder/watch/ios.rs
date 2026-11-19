//! Folder watch for iOS, which does nothing.
//!
//! The S3 transport polls, and the folder transport is not used on iOS.

use std::path::Path;

use super::Changes;

/// Watch of a folder root. No watch exists on iOS.
pub struct FolderWatch;

impl FolderWatch {
    /// No watch starts, so this returns `None` and the caller polls.
    pub fn start(_root: &Path, _notify: Box<dyn Fn(Changes) + Send>) -> Option<Self> {
        None
    }
}
