//! Broker parts for macOS: the AutoFill Mach service, the app launch through
//! LaunchServices, and the browser support directories.

use std::fs;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};

use objc2::rc::Retained;
use objc2_app_kit::NSRunningApplication;
use objc2_foundation::{NSBundle, NSString, NSURL};

use crate::core::app_broker::access::{Client, RequestScope, agent_policy, browser_host_policy};
use crate::core::app_broker::browsers::Browser;
use crate::core::app_broker::server::serve_on;
use crate::core::app_broker::{
    AUTOFILL_EXTENSION_NAME, Authorizers, BrokerError, LAUNCH_FLAG, autofill_service_name,
    broker_socket_path, mach,
};
use crate::core::dirs::app_data_dir;
use crate::core::provenance::PeerPolicy;

/// Serve requests until `shutdown` resolves, then remove the socket and the
/// Mach service.
///
/// `ap` connects to the socket in the app data directory. When this build is
/// signed, the AutoFill extension reaches the broker through a Mach service
/// named under the App Group (see [`mach`]). The extension is sandboxed, and a
/// Mach service lookup is the one path to the app it has that touches no
/// files.
pub async fn serve(
    authorizers: Authorizers,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) -> std::io::Result<()> {
    let autofill = match autofill_service_name() {
        Some(name) => match mach::MachService::start(
            &name,
            extension_policy(),
            RequestScope::AutofillExtension,
            authorizers.clone(),
        ) {
            Ok(service) => Some(service),
            Err(e) => {
                log::warn!("AutoFill broker failed to start on {name}: {e}");
                None
            },
        },
        None => {
            log::debug!("No team identifier: not serving the AutoFill broker");
            None
        },
    };

    let result = serve_on(
        broker_socket_path(),
        vec![
            Client {
                policy: agent_policy(),
                scope: RequestScope::Agent,
            },
            Client {
                policy: browser_host_policy(),
                scope: RequestScope::BrowserHost,
            },
        ],
        authorizers,
        shutdown,
    )
    .await;

    if let Some(autofill) = autofill {
        autofill.stop();
    }
    result
}

/// Who the AutoFill broker takes requests from: only the credential provider
/// extension staged in our own bundle, signed by the same team.
fn extension_policy() -> PeerPolicy {
    let policy = PeerPolicy::bundled_executable(&format!(
        "PlugIns/{AUTOFILL_EXTENSION_NAME}.appex/Contents/MacOS/{AUTOFILL_EXTENSION_NAME}"
    ));
    match policy.executable.as_ref() {
        Some(path) => log::debug!("AutoFill broker accepts {}", path.display()),
        None => log::warn!("AutoFill broker could not resolve the extension's executable"),
    }
    policy
}

/// Make writes to a closed peer fail with EPIPE, not raise SIGPIPE, which
/// would terminate the host process.
pub(in crate::core::app_broker) fn disable_sigpipe(stream: &impl AsFd) {
    if let Err(e) = socket2::SockRef::from(stream).set_nosigpipe(true) {
        log::debug!("App broker could not set SO_NOSIGPIPE: {e}");
    }
}

/// Support directories the browser creates for the user, relative to the
/// home directory. The browser counts as installed if any of them exists.
/// The first entry holds the manifest directory.
pub(in crate::core::app_broker) fn support_dirs(browser: Browser) -> &'static [&'static str] {
    match browser {
        Browser::Chrome => &["Library/Application Support/Google/Chrome"],
        Browser::Firefox => &[
            "Library/Application Support/Mozilla",
            "Library/Application Support/Firefox",
        ],
    }
}

/// The bundle holding this executable, i.e. `.../Axo Pass.app` for the `ap`
/// staged at `Contents/MacOS/ap`.
///
/// Walks up from the executable looking for a `.app` component rather than
/// assuming a fixed depth: `current_exe` is not always canonical (a wrapper
/// that execs `.../Contents/Resources/../MacOS/ap` leaves the `..` in place),
/// so a fixed number of `parent()` calls can land in the wrong directory.
pub(crate) fn app_bundle_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    log::debug!("Resolving the app bundle from {}", exe.display());
    exe.ancestors()
        .find(|path| path.extension().is_some_and(|ext| ext == "app"))
        .map(Path::to_path_buf)
}

/// Whether the app is already running.
///
/// Asks LaunchServices, which is the same authority `open` consults: if it
/// reports an instance, `open` will reopen that one rather than launch a new
/// one. `ap` itself is not a registered application, so it never counts.
fn app_is_running(bundle: &Path) -> bool {
    let Some(id) = bundle_identifier(bundle) else {
        log::debug!("No bundle identifier for {}", bundle.display());
        return false;
    };
    !NSRunningApplication::runningApplicationsWithBundleIdentifier(&id).is_empty()
}

/// The `CFBundleIdentifier` of the bundle at `path`.
fn bundle_identifier(path: &Path) -> Option<Retained<NSString>> {
    let url = NSURL::fileURLWithPath(&NSString::from_str(path.to_str()?));
    NSBundle::bundleWithURL(&url)?.bundleIdentifier()
}

/// Serializes `launch_app` across processes, so two requests arriving together
/// issue one `open` between them.
fn launch_lock_path() -> PathBuf {
    app_data_dir().join("app-broker.launch.lock")
}

/// Take the launch lock, waiting for whoever holds it.
///
/// Waits rather than giving up, so the second caller runs its checks only after
/// the first has finished starting the app and LaunchServices knows about it.
///
/// The lock is an `flock` the kernel releases when the file closes or the
/// process dies, so it cannot go stale and needs no timeout. Nothing reads the
/// file's contents.
fn lock_launch() -> Option<fs::File> {
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(launch_lock_path())
        .map_err(|e| log::debug!("Could not open the launch lock: {e}"))
        .ok()?;
    file.lock()
        .map_err(|e| log::debug!("Could not take the launch lock: {e}"))
        .ok()?;
    Some(file)
}

/// Start the app in the background, so a signature request does not pull focus
/// away from whatever asked for it.
pub(in crate::core::app_broker) fn launch_app() -> Result<(), BrokerError> {
    let Some(bundle) = app_bundle_path() else {
        log::debug!("Not running from an app bundle; cannot start the broker");
        return Err(BrokerError::Unavailable);
    };

    // Held until this function returns, so two requests arriving together issue
    // one `open` between them: the second waits here, then finds the app
    // running below. A second `open` would reach the app as a reopen, which
    // puts a window on screen.
    let _lock = lock_launch();

    // `open` on a running app only delivers a reopen event, which puts a window
    // on screen and takes focus, and drops `--args` on the way. So do not issue
    // one: the app is up and binding the socket, and the caller waits for it.
    if app_is_running(&bundle) {
        log::info!("The app is already running; waiting for it to serve");
        return Ok(());
    }

    log::info!("Starting {} for the app broker", bundle.display());
    let status = std::process::Command::new("/usr/bin/open")
        .arg("-g")
        .arg(&bundle)
        .arg("--args")
        .arg(LAUNCH_FLAG)
        .status()
        .map_err(|e| BrokerError::Failed(format!("Failed to start the app: {e}")))?;
    if !status.success() {
        return Err(BrokerError::Failed(format!(
            "Failed to start {}: open exited with {status}",
            bundle.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_paths_are_per_browser() {
        let chrome = Browser::Chrome.manifest_path().unwrap();
        let firefox = Browser::Firefox.manifest_path().unwrap();
        assert!(
            chrome.ends_with("Google/Chrome/NativeMessagingHosts/com.breakfastlabs.axo_pass.json")
        );
        assert!(firefox.ends_with("Mozilla/NativeMessagingHosts/com.breakfastlabs.axo_pass.json"));
    }
}
