use std::path::PathBuf;

/// `$XDG_DATA_HOME/axo-pass`, typically `~/.local/share/axo-pass`. `Err` holds
/// the missing variable.
pub(super) fn data_dir() -> Result<PathBuf, &'static str> {
    dirs::data_dir()
        .map(|dir| dir.join("axo-pass"))
        .ok_or("XDG_DATA_HOME")
}

/// `$XDG_STATE_HOME/axo-pass`, typically `~/.local/state/axo-pass`.
pub(super) fn log_dir() -> Result<PathBuf, &'static str> {
    dirs::state_dir()
        .map(|dir| dir.join("axo-pass"))
        .ok_or("XDG_STATE_HOME")
}

/// `$XDG_CACHE_HOME/axo-pass`, typically `~/.cache/axo-pass`.
pub(super) fn cache_dir() -> Result<PathBuf, &'static str> {
    dirs::cache_dir()
        .map(|dir| dir.join("axo-pass"))
        .ok_or("XDG_CACHE_HOME")
}

/// `$XDG_RUNTIME_DIR/axo-pass`, or `/run/user/<uid>/axo-pass` if the variable
/// is unset. Ignores the data directory override.
pub(super) fn socket_dir(_data: impl FnOnce() -> PathBuf) -> PathBuf {
    let runtime = dirs::runtime_dir()
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", unsafe { libc::geteuid() })));
    runtime.join("axo-pass")
}
