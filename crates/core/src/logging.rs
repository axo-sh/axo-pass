use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Once;

use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, fmt};

use crate::core::dirs::log_data_dir;

static INIT: Once = Once::new();

/// At startup, roll the log file if it has already passed this size.
/// tracing-appender has no size-based rotation, so this is the only check.
const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;

/// Install a process-wide subscriber that captures `log`/`tracing` events
/// from the Rust core and its dependencies, writing them to an un-rotated
/// file in `~/Library/Logs/Axo Pass/` plus a stderr mirror. `filename_prefix`
/// names the log file, e.g. `"app.log"`.
///
/// This is for the Rust side only. It is called from the FFI constructor so
/// that core logs are captured when the code runs inside the Swift GUI app,
/// which otherwise installs no subscriber. Swift's own logging goes through
/// Apple's unified logging and is unaffected.
///
/// The file keeps its exact name so `axo logs` can tail a predictable path.
/// It is rolled to `<name>.old` (one backup) at startup if it has grown past
/// `MAX_LOG_BYTES`.
///
/// The level defaults to `debug` in debug builds or when `FRITTATA_DEBUG` is
/// set, `info` otherwise, and is overridable with `FRITTATA_LOG` (an
/// `EnvFilter` directive). Safe to call more than once; only the first call
/// takes effect, and it never panics if another subscriber is already set.
pub fn init(filename_prefix: &str) {
    INIT.call_once(|| {
        let default_level = if std::env::var("FRITTATA_DEBUG").is_ok() || cfg!(debug_assertions) {
            "debug,ssh_agent_lib=error"
        } else {
            "info"
        };
        let filter = match std::env::var("FRITTATA_LOG") {
            Ok(directive) => EnvFilter::try_new(&directive).unwrap_or_else(|e| {
                eprintln!("axo-pass: ignoring invalid FRITTATA_LOG ({directive:?}): {e}");
                EnvFilter::new(default_level)
            }),
            Err(_) => EnvFilter::new(default_level),
        };

        let dir = log_data_dir();
        roll_if_oversized(&dir.join(filename_prefix));

        let file_layer = match RollingFileAppender::builder()
            .rotation(Rotation::NEVER)
            .filename_prefix(filename_prefix)
            .build(&dir)
        {
            Ok(appender) => Some(fmt::layer().with_ansi(false).with_writer(appender)),
            Err(e) => {
                eprintln!(
                    "axo-pass: could not open log file in {}: {e}",
                    dir.display()
                );
                None
            },
        };

        let stderr_layer = fmt::layer()
            .with_ansi(std::io::stderr().is_terminal())
            .with_writer(std::io::stderr);

        if let Err(e) = tracing_subscriber::registry()
            .with(filter)
            .with(file_layer.map(|l| l.boxed()))
            .with(stderr_layer)
            .try_init()
        {
            eprintln!("axo-pass: logging already initialized elsewhere: {e}");
        }
    });
}

/// If `path` exists and exceeds `MAX_LOG_BYTES`, rename it to `<path>.old`,
/// replacing any previous backup. Best effort: any error is ignored, the
/// appender will just keep writing to the existing file.
fn roll_if_oversized(path: &Path) {
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    if meta.len() <= MAX_LOG_BYTES {
        return;
    }
    let mut backup = path.as_os_str().to_owned();
    backup.push(".old");
    let _ = std::fs::rename(path, PathBuf::from(backup));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rolls_only_when_oversized() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("app.log");
        let backup = dir.path().join("app.log.old");

        // Missing file: no-op.
        roll_if_oversized(&log);
        assert!(!backup.exists());

        // Small file: left in place.
        std::fs::write(&log, b"small").unwrap();
        roll_if_oversized(&log);
        assert!(log.exists());
        assert!(!backup.exists());

        // Oversized file: rolled to .old.
        std::fs::write(&log, vec![b'x'; (MAX_LOG_BYTES + 1) as usize]).unwrap();
        roll_if_oversized(&log);
        assert!(!log.exists());
        assert!(backup.exists());
    }
}
