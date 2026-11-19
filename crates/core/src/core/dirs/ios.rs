use std::path::PathBuf;

use super::{DirsError, Missing};

/// iOS has no default data directory. `dirs::init` sets it.
pub(super) fn data_dir() -> Result<PathBuf, Missing> {
    Err(Missing::NoDefault)
}

/// iOS has no default log directory. `dirs::init` sets it.
pub(super) fn log_dir() -> Result<PathBuf, Missing> {
    Err(Missing::NoDefault)
}

/// iOS has no default cache directory. `dirs::init` sets it.
pub(super) fn cache_dir() -> Result<PathBuf, Missing> {
    Err(Missing::NoDefault)
}

/// Same as the data directory. `data` returns it.
pub(super) fn socket_dir(
    data: impl FnOnce() -> Result<PathBuf, DirsError>,
) -> Result<PathBuf, DirsError> {
    data()
}
