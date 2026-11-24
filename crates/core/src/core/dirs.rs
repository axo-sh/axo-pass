#[cfg(ios)]
mod ios;
#[cfg(linux)]
mod linux;
#[cfg(macos)]
mod macos;

use std::path::PathBuf;
use std::sync::OnceLock;

#[cfg(ios)]
use ios as imp;
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
    #[error(
        "cannot determine the {name} directory. No home directory is available and {var} is \
         not set. Call `dirs::init` or set {var}."
    )]
    MissingVar {
        name: &'static str,
        var: &'static str,
    },
    #[error("the {name} directory has no default on this platform. Call `dirs::init` first.")]
    NotInitialized { name: &'static str },
}

/// Reason a platform has no default directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Missing {
    /// The variable that locates the directory is not set. iOS builds never
    /// construct it.
    #[allow(dead_code)]
    Var(&'static str),
    /// The platform has no default. Only iOS builds construct it.
    #[allow(dead_code)]
    NoDefault,
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

/// Directory of app data, including vaults. Fails if there is no override and
/// the platform has no default.
pub fn try_app_data_dir() -> Result<PathBuf, DirsError> {
    data_in(&OVERRIDES)
}

/// Directory of log files. Fails if there is no override and the platform has
/// no default.
pub fn try_log_data_dir() -> Result<PathBuf, DirsError> {
    logs_in(&OVERRIDES)
}

/// Directory of cache files. Fails if there is no override and the platform
/// has no default.
pub fn try_cache_dir() -> Result<PathBuf, DirsError> {
    cache_in(&OVERRIDES)
}

/// Directory of the broker socket. Fails if this follows the data directory
/// and that cannot be found.
pub fn try_socket_dir() -> Result<PathBuf, DirsError> {
    socket_in(&OVERRIDES)
}

/// Directory of app data, including vaults.
///
/// # Panics
///
/// Panics if there is no override and the platform default cannot be found.
/// See [`try_app_data_dir`].
pub fn app_data_dir() -> PathBuf {
    or_panic(try_app_data_dir())
}

/// Directory of log files.
///
/// # Panics
///
/// Panics if there is no override and the platform default cannot be found.
/// See [`try_log_data_dir`].
pub fn log_data_dir() -> PathBuf {
    or_panic(try_log_data_dir())
}

/// Directory of cache files.
///
/// # Panics
///
/// Panics if there is no override and the platform default cannot be found.
/// See [`try_cache_dir`].
pub fn cache_dir() -> PathBuf {
    or_panic(try_cache_dir())
}

/// Directory of the broker socket.
///
/// # Panics
///
/// Panics if this follows the data directory and that cannot be found. See
/// [`try_socket_dir`].
pub fn socket_dir() -> PathBuf {
    or_panic(try_socket_dir())
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

fn data_in(cell: &OnceLock<Overrides>) -> Result<PathBuf, DirsError> {
    match cell.get() {
        Some(overrides) => Ok(overrides.data.clone()),
        None => resolve("data", imp::data_dir()),
    }
}

fn logs_in(cell: &OnceLock<Overrides>) -> Result<PathBuf, DirsError> {
    match cell.get() {
        Some(overrides) => Ok(overrides.logs.clone()),
        None => resolve("log", imp::log_dir()),
    }
}

fn cache_in(cell: &OnceLock<Overrides>) -> Result<PathBuf, DirsError> {
    match cell.get() {
        Some(overrides) => Ok(overrides.cache.clone()),
        None => resolve("cache", imp::cache_dir()),
    }
}

fn socket_in(cell: &OnceLock<Overrides>) -> Result<PathBuf, DirsError> {
    imp::socket_dir(|| data_in(cell))
}

/// Platform default, or an error that names the missing directory.
fn resolve(name: &'static str, default: Result<PathBuf, Missing>) -> Result<PathBuf, DirsError> {
    default.map_err(|missing| match missing {
        Missing::Var(var) => DirsError::MissingVar { name, var },
        Missing::NoDefault => DirsError::NotInitialized { name },
    })
}

/// `dir`, or a panic with the error message.
fn or_panic(dir: Result<PathBuf, DirsError>) -> PathBuf {
    dir.unwrap_or_else(|e| panic!("{e}"))
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
        assert_eq!(data_in(&cell).unwrap(), PathBuf::from("/tmp/axo-test/data"));
        assert_eq!(logs_in(&cell).unwrap(), PathBuf::from("/tmp/axo-test/logs"));
        assert_eq!(
            cache_in(&cell).unwrap(),
            PathBuf::from("/tmp/axo-test/cache")
        );
    }

    #[test]
    fn default_used_without_override() {
        let cell = OnceLock::new();
        assert_eq!(data_in(&cell).ok(), imp::data_dir().ok(),);
        assert_eq!(logs_in(&cell).ok(), imp::log_dir().ok());
        assert_eq!(cache_in(&cell).ok(), imp::cache_dir().ok());
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
        assert_eq!(
            socket_in(&cell).unwrap(),
            PathBuf::from("/tmp/axo-test/data")
        );
    }

    #[cfg(macos)]
    #[test]
    fn socket_is_data_default_without_override() {
        let cell = OnceLock::new();
        assert_eq!(socket_in(&cell).unwrap(), data_in(&cell).unwrap());
    }

    #[cfg(linux)]
    #[test]
    fn socket_ignores_data_override() {
        let plain = OnceLock::new();
        let overridden = OnceLock::new();
        init_in(&overridden, overrides()).unwrap();
        assert_eq!(socket_in(&overridden).unwrap(), socket_in(&plain).unwrap());
    }

    #[test]
    fn missing_var_error_names_directory() {
        let err = resolve("cache", Err(Missing::Var("SOME_VAR"))).unwrap_err();
        assert!(
            err.to_string()
                .contains("cannot determine the cache directory")
        );
    }

    #[test]
    fn missing_var_error_gives_remedy() {
        let err = resolve("data", Err(Missing::Var("SOME_VAR"))).unwrap_err();
        assert!(
            err.to_string()
                .contains("Call `dirs::init` or set SOME_VAR")
        );
    }

    #[test]
    fn no_default_error_gives_remedy() {
        let err = resolve("data", Err(Missing::NoDefault)).unwrap_err();
        assert!(matches!(err, DirsError::NotInitialized { name: "data" }));
        assert!(err.to_string().contains("Call `dirs::init` first"));
    }

    #[test]
    #[should_panic(expected = "cannot determine the cache directory")]
    fn infallible_lookup_panics_with_error() {
        or_panic(resolve("cache", Err(Missing::Var("SOME_VAR"))));
    }
}
