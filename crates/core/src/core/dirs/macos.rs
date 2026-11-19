use std::path::PathBuf;

/// `~/Library/Application Support/Axo Pass`. `Err` holds the missing variable.
pub(super) fn data_dir() -> Result<PathBuf, &'static str> {
    dirs::data_dir()
        .map(|dir| dir.join("Axo Pass"))
        .ok_or("HOME")
}

/// `~/Library/Logs/Axo Pass`.
pub(super) fn log_dir() -> Result<PathBuf, &'static str> {
    dirs::home_dir()
        .map(|dir| dir.join("Library/Logs/Axo Pass"))
        .ok_or("HOME")
}

/// `~/Library/Caches/Axo Pass`.
pub(super) fn cache_dir() -> Result<PathBuf, &'static str> {
    dirs::cache_dir()
        .map(|dir| dir.join("Axo Pass"))
        .ok_or("HOME")
}

/// Same as the data directory. `data` returns it.
pub(super) fn socket_dir(data: impl FnOnce() -> PathBuf) -> PathBuf {
    data()
}
