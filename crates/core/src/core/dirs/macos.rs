use std::path::PathBuf;

use super::{DirsError, Missing};

/// `~/Library/Application Support/Axo Pass`. `Err` holds the missing variable.
pub(super) fn data_dir() -> Result<PathBuf, Missing> {
    dirs::data_dir()
        .map(|dir| dir.join("Axo Pass"))
        .ok_or(Missing::Var("HOME"))
}

/// `~/Library/Logs/Axo Pass`.
pub(super) fn log_dir() -> Result<PathBuf, Missing> {
    dirs::home_dir()
        .map(|dir| dir.join("Library/Logs/Axo Pass"))
        .ok_or(Missing::Var("HOME"))
}

/// `~/Library/Caches/Axo Pass`.
pub(super) fn cache_dir() -> Result<PathBuf, Missing> {
    dirs::cache_dir()
        .map(|dir| dir.join("Axo Pass"))
        .ok_or(Missing::Var("HOME"))
}

/// Same as the data directory. `data` returns it.
pub(super) fn socket_dir(
    data: impl FnOnce() -> Result<PathBuf, DirsError>,
) -> Result<PathBuf, DirsError> {
    data()
}
