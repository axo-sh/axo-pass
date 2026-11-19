#[cfg(linux)]
mod linux;
#[cfg(macos)]
mod macos;

use std::path::PathBuf;
use std::sync::OnceLock;

#[cfg(linux)]
use linux as imp;
#[cfg(macos)]
use macos as imp;
use thiserror::Error;

use crate::core::provenance::team_identifier;

/// The App Group shared by the app and its AutoFill credential provider
/// extension, minus the team identifier prefix macOS requires.
pub const APP_GROUP_SUFFIX: &str = "com.breakfastlabs.frittata.shared";

#[derive(Debug, Error)]
pub enum DirsError {
    #[error("directories are already initialized")]
    AlreadyInitialized,
}

/// Directories set by [`init`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct Overrides {
    data: PathBuf,
    logs: PathBuf,
    cache: PathBuf,
}

static OVERRIDES: OnceLock<Overrides> = OnceLock::new();

/// Override the data, log, and cache directories.
///
/// Call once at startup, before any directory is read. A second call fails
/// and leaves the first paths in place. The socket directory is not
/// overridden on Linux.
pub fn init(data: PathBuf, logs: PathBuf, cache: PathBuf) -> Result<(), DirsError> {
    init_in(&OVERRIDES, Overrides { data, logs, cache })
}

/// Directory of app data, including vaults.
///
/// # Panics
///
/// Panics if there is no override and the platform default cannot be found.
pub fn app_data_dir() -> PathBuf {
    data_in(&OVERRIDES)
}

/// Directory of log files.
///
/// # Panics
///
/// Panics if there is no override and the platform default cannot be found.
pub fn log_data_dir() -> PathBuf {
    logs_in(&OVERRIDES)
}

/// Directory of cache files.
///
/// # Panics
///
/// Panics if there is no override and the platform default cannot be found.
pub fn cache_dir() -> PathBuf {
    cache_in(&OVERRIDES)
}

/// Directory of the broker socket.
///
/// # Panics
///
/// Panics on macOS if this follows the data directory and that cannot be
/// found.
pub fn socket_dir() -> PathBuf {
    socket_in(&OVERRIDES)
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

fn init_in(cell: &OnceLock<Overrides>, overrides: Overrides) -> Result<(), DirsError> {
    cell.set(overrides)
        .map_err(|_| DirsError::AlreadyInitialized)
}

fn data_in(cell: &OnceLock<Overrides>) -> PathBuf {
    match cell.get() {
        Some(overrides) => overrides.data.clone(),
        None => resolve("data", imp::data_dir()),
    }
}

fn logs_in(cell: &OnceLock<Overrides>) -> PathBuf {
    match cell.get() {
        Some(overrides) => overrides.logs.clone(),
        None => resolve("log", imp::log_dir()),
    }
}

fn cache_in(cell: &OnceLock<Overrides>) -> PathBuf {
    match cell.get() {
        Some(overrides) => overrides.cache.clone(),
        None => resolve("cache", imp::cache_dir()),
    }
}

fn socket_in(cell: &OnceLock<Overrides>) -> PathBuf {
    imp::socket_dir(|| data_in(cell))
}

/// Platform default, or a panic that names the missing directory. `Err`
/// holds the variable that locates it.
fn resolve(name: &str, default: Result<PathBuf, &'static str>) -> PathBuf {
    default.unwrap_or_else(|var| {
        panic!(
            "cannot determine the {name} directory. No home directory is available and {var} \
             is not set. Call `dirs::init` or set {var}."
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overrides() -> Overrides {
        Overrides {
            data: PathBuf::from("/tmp/axo-test/data"),
            logs: PathBuf::from("/tmp/axo-test/logs"),
            cache: PathBuf::from("/tmp/axo-test/cache"),
        }
    }

    #[test]
    fn override_used() {
        let cell = OnceLock::new();
        init_in(&cell, overrides()).unwrap();
        assert_eq!(data_in(&cell), PathBuf::from("/tmp/axo-test/data"));
        assert_eq!(logs_in(&cell), PathBuf::from("/tmp/axo-test/logs"));
        assert_eq!(cache_in(&cell), PathBuf::from("/tmp/axo-test/cache"));
    }

    #[test]
    fn default_used_without_override() {
        let cell = OnceLock::new();
        assert_eq!(data_in(&cell), imp::data_dir().unwrap());
        assert_eq!(logs_in(&cell), imp::log_dir().unwrap());
        assert_eq!(cache_in(&cell), imp::cache_dir().unwrap());
    }

    #[test]
    fn second_init_fails_keeps_first() {
        let cell = OnceLock::new();
        init_in(&cell, overrides()).unwrap();
        let second = Overrides {
            data: PathBuf::from("/tmp/axo-other/data"),
            logs: PathBuf::from("/tmp/axo-other/logs"),
            cache: PathBuf::from("/tmp/axo-other/cache"),
        };
        assert!(matches!(
            init_in(&cell, second),
            Err(DirsError::AlreadyInitialized)
        ));
        assert_eq!(cell.get(), Some(&overrides()));
    }

    #[cfg(macos)]
    #[test]
    fn socket_follows_data_override() {
        let cell = OnceLock::new();
        init_in(&cell, overrides()).unwrap();
        assert_eq!(socket_in(&cell), PathBuf::from("/tmp/axo-test/data"));
    }

    #[cfg(macos)]
    #[test]
    fn socket_is_data_default_without_override() {
        let cell = OnceLock::new();
        assert_eq!(socket_in(&cell), data_in(&cell));
    }

    #[cfg(linux)]
    #[test]
    fn socket_ignores_data_override() {
        let plain = OnceLock::new();
        let overridden = OnceLock::new();
        init_in(&overridden, overrides()).unwrap();
        assert_eq!(socket_in(&overridden), socket_in(&plain));
    }

    #[test]
    #[should_panic(expected = "cannot determine the cache directory")]
    fn missing_default_panics_naming_directory() {
        resolve("cache", Err("SOME_VAR"));
    }

    #[test]
    #[should_panic(expected = "Call `dirs::init` or set SOME_VAR")]
    fn missing_default_panic_gives_remedy() {
        resolve("data", Err("SOME_VAR"));
    }
}
