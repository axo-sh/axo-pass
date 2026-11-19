use std::path::PathBuf;

use crate::core::provenance::team_identifier;

/// The App Group shared by the app and its AutoFill credential provider
/// extension, minus the team identifier prefix macOS requires.
pub const APP_GROUP_SUFFIX: &str = "com.breakfastlabs.frittata.shared";

#[cfg(macos)]
pub fn app_data_dir() -> PathBuf {
    // ~/Library/Application Support/Axo Pass
    dirs::data_dir().unwrap().join("Axo Pass")
}

#[cfg(macos)]
pub fn log_data_dir() -> PathBuf {
    // ~/Library/Logs/Axo Pass
    dirs::home_dir().unwrap().join("Library/Logs/Axo Pass")
}

/// Directory of the broker socket.
#[cfg(macos)]
pub fn socket_dir() -> PathBuf {
    app_data_dir()
}

#[cfg(linux)]
pub fn app_data_dir() -> PathBuf {
    // $XDG_DATA_HOME/axo-pass, typically ~/.local/share/axo-pass
    dirs::data_dir().unwrap().join("axo-pass")
}

#[cfg(linux)]
pub fn log_data_dir() -> PathBuf {
    // $XDG_STATE_HOME/axo-pass, typically ~/.local/state/axo-pass
    dirs::state_dir().unwrap().join("axo-pass")
}

#[cfg(linux)]
pub fn cache_dir() -> PathBuf {
    // $XDG_CACHE_HOME/axo-pass, typically ~/.cache/axo-pass
    dirs::cache_dir().unwrap().join("axo-pass")
}

/// Directory of the broker socket. `$XDG_RUNTIME_DIR/axo-pass`, or
/// `/run/user/<uid>/axo-pass` if the variable is unset.
#[cfg(linux)]
pub fn socket_dir() -> PathBuf {
    let runtime = dirs::runtime_dir()
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", unsafe { libc::geteuid() })));
    runtime.join("axo-pass")
}

pub fn vaults_dir() -> PathBuf {
    app_data_dir().join("vaults")
}

/// The App Group identifier: `<team>.com.breakfastlabs.frittata.shared`.
///
/// The team identifier comes from our own code signature. An unsigned or ad-hoc
/// local build has none, and the extension cannot run under one either, so this
/// returns `None` rather than guessing an identifier nothing will use.
///
/// The app never touches the group's container directory. An unsandboxed app
/// doing so raises the "access data from other apps" consent prompt.
pub fn app_group_identifier() -> Option<String> {
    let team = team_identifier()?;
    Some(format!("{team}.{APP_GROUP_SUFFIX}"))
}
