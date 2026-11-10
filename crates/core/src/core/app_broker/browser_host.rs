//! `AxoPassBrowserHost`, the native messaging host Chrome and Firefox start for
//! the Axo Pass extension.
//!
//! Any local process can start the host and write to its stdin, so nothing the
//! extension sends is trusted to say who is asking. The host parses each
//! message into [`ExtensionRequest`], which can represent only the browser host
//! requests, and builds the broker request itself. `client` and `caller` come
//! from its own check of the parent process.
//!
//! One request per process. The host first writes a hello with the protocol
//! version and a nonce. The extension sends one request with both, and
//! disconnects after the reply. The host exits on stdin EOF, which closes the
//! broker connection and ends any prompt on screen. See [`session`].
//!
//! Replies are broker responses, plus statuses of the host's own: the app
//! could not be reached, a locked listing was refused because the browser is
//! not verified, and the request was for another protocol version. See
//! [`HostStatus`].
//!
//! Stdout carries native messaging frames only. Logs go to stderr and to
//! `~/Library/Logs/Axo Pass/browser-host.log`. Request bodies are never logged.

mod framing;
mod parent;
mod request;
mod session;

use std::ffi::OsString;
use std::io;
use std::os::fd::AsFd;
use std::path::Path;
use std::process::ExitCode;

use serde::Serialize;

use self::framing::{FrameError, write_message};
use self::parent::verify_parent;
use self::request::ExtensionRequest;
use self::session::{greet, read_request};
use super::BrokerError;
use super::browsers::{Browser, same_file};
use super::client::send_request;
use super::wire::{BrowserClient, VerifiedBrowser, WireResponse};

/// Run the host until it has answered one request or stdin closes.
pub fn run() -> ExitCode {
    crate::logging::init("browser-host.log");

    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let client = identify_client(&args);

    let stdin = io::stdin();
    let greeting = greet(stdin.as_fd(), &mut io::stdout().lock());
    let nonce = match greeting {
        Ok(nonce) => nonce,
        Err(refusal) => {
            reply(&refusal);
            return ExitCode::FAILURE;
        },
    };
    let request = match read_request(&mut stdin.lock(), &nonce) {
        Ok(Some(request)) => request,
        Ok(None) => return ExitCode::SUCCESS,
        Err(refusal) => {
            // Input past a refused message is not read. Report and stop.
            reply(&refusal);
            return ExitCode::FAILURE;
        },
    };
    log::info!(
        "Browser host request: {} ({})",
        request.kind(),
        client
            .browser
            .as_ref()
            .map_or("unverified browser", |b| b.name.as_str())
    );

    // The broker refuses a locked listing for an unverified browser. The host
    // says so itself, so the extension can tell this from other failures.
    if client.browser.is_none() && matches!(request, ExtensionRequest::ListLoginsLocked { .. }) {
        return exit_code(reply(&HostStatus::BrowserNotVerified));
    }

    exit_on_stdin_eof();

    let sent = match send_request(&request.into_wire(client)) {
        Ok(response) => reply(&response),
        Err(BrokerError::Cancelled) => reply(&WireResponse::Cancelled),
        Err(e @ BrokerError::Unavailable) => {
            log::warn!("Browser host could not reach the app: {e}");
            reply(&HostStatus::AppUnavailable {
                message: e.to_string(),
            })
        },
        Err(e) => {
            log::warn!("Browser host request failed: {e}");
            reply(&failed(e.to_string()))
        },
    };
    exit_code(sent)
}

/// Replies the host makes without an answer from the broker. They share the
/// `status` tag of [`WireResponse`] and use names it does not.
#[derive(Debug, Serialize)]
#[cfg_attr(test, derive(serde::Deserialize, PartialEq))]
#[serde(tag = "status", rename_all = "snake_case")]
enum HostStatus {
    /// No app is listening and none could be started.
    AppUnavailable { message: String },
    /// The host could not verify the browser that started it, so it refused a
    /// request that needs a verified browser.
    BrowserNotVerified,
    /// The request was for another protocol version. `version` is the version
    /// the host speaks.
    VersionMismatch { version: u32 },
}

fn exit_code(sent: bool) -> ExitCode {
    if sent {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn failed(message: String) -> WireResponse {
    WireResponse::Failed { message }
}

/// Write `response` to stdout. False if it could not be written.
fn reply(response: &impl Serialize) -> bool {
    let body = match serde_json::to_vec(response) {
        Ok(body) => body,
        Err(e) => {
            log::error!("Browser host could not encode a response: {e}");
            return false;
        },
    };
    let mut stdout = io::stdout().lock();
    let result = match write_message(&mut stdout, &body) {
        Err(FrameError::TooLarge(len)) => {
            log::warn!("Browser host response of {len} bytes is too large to send");
            let body = serde_json::to_vec(&failed("The response is too large".to_string()))
                .unwrap_or_default();
            write_message(&mut stdout, &body)
        },
        result => result,
    };
    result
        .inspect_err(|e| log::warn!("Browser host could not write a response: {e}"))
        .is_ok()
}

/// Exit the process when stdin closes. The browser closes it when the
/// extension disconnects, and exiting closes the broker connection, which
/// ends the prompt. Messages after the first are read and dropped.
fn exit_on_stdin_eof() {
    std::thread::spawn(|| {
        let _ = io::copy(&mut io::stdin().lock(), &mut io::sink());
        log::info!("Browser host stdin closed, exiting");
        std::process::exit(0);
    });
}

/// Who the host reports to the broker. The browser is set only when the parent
/// check passes and, in a release build, the extension and manifest checks
/// pass too. The extension identity from the arguments is reported either way,
/// for audit only.
fn identify_client(args: &[OsString]) -> BrowserClient {
    let extension = reported_extension(args);
    let browser = match verify_parent() {
        Ok(parent) => {
            log::debug!("Browser host parent: {:#?}", parent.peer);
            match check_release(parent.browser, args) {
                Ok(()) => Some(VerifiedBrowser {
                    name: parent.browser.name().to_string(),
                    team_id: parent.browser.team_id().to_string(),
                }),
                Err(message) => {
                    log::warn!(
                        "Browser host could not verify {}: {message}",
                        parent.browser.name()
                    );
                    None
                },
            }
        },
        Err(message) => {
            log::warn!("Browser host could not verify its parent: {message}");
            None
        },
    };
    BrowserClient { browser, extension }
}

/// The extension and manifest checks. Debug builds skip them, since a
/// development extension and manifest do not match the release values.
fn check_release(browser: Browser, args: &[OsString]) -> Result<(), String> {
    if cfg!(debug_assertions) {
        return Ok(());
    }
    let manifest = browser
        .manifest_path()
        .ok_or("No home directory for the manifest")?;
    check_extension(browser, args, &manifest)?;
    let exe = std::env::current_exe().map_err(|e| format!("No executable path: {e}"))?;
    check_manifest(&manifest, &exe)
}

/// The extension identity a browser passes in the arguments: the caller origin
/// for Chrome, the extension id after the manifest path for Firefox.
fn reported_extension(args: &[OsString]) -> Option<String> {
    let first = args.first()?.to_str()?;
    if first.starts_with("chrome-extension://") {
        return Some(first.to_string());
    }
    args.get(1)?.to_str().map(String::from)
}

/// Check that the arguments name our extension. Chrome passes its origin as
/// the first argument. Firefox passes the manifest path, then the extension id.
fn check_extension(browser: Browser, args: &[OsString], manifest: &Path) -> Result<(), String> {
    let expected = browser.expected_extension();
    match browser {
        Browser::Chrome => {
            let origin = args.first().and_then(|a| a.to_str());
            if origin != Some(expected.as_str()) {
                return Err(format!("Caller origin {origin:?} is not {expected}"));
            }
        },
        Browser::Firefox => {
            let path = args.first().map(Path::new);
            if !path.is_some_and(|path| same_file(path, manifest)) {
                return Err(format!(
                    "Manifest path {path:?} is not {}",
                    manifest.display()
                ));
            }
            let id = args.get(1).and_then(|a| a.to_str());
            if id != Some(expected.as_str()) {
                return Err(format!("Extension id {id:?} is not {expected}"));
            }
        },
    }
    Ok(())
}

/// Check that the installed manifest names this executable as the host.
fn check_manifest(manifest: &Path, exe: &Path) -> Result<(), String> {
    let text = std::fs::read_to_string(manifest)
        .map_err(|e| format!("Could not read {}: {e}", manifest.display()))?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| format!("Could not parse {}: {e}", manifest.display()))?;
    let path = value["path"]
        .as_str()
        .ok_or_else(|| format!("{} has no path", manifest.display()))?;
    if !same_file(Path::new(path), exe) {
        return Err(format!(
            "{} names {path}, not {}",
            manifest.display(),
            exe.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::app_broker::browsers::{CHROME_EXTENSION_ID, FIREFOX_EXTENSION_ID};

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn reports_extension_from_either_browser() {
        assert_eq!(
            reported_extension(&args(&["chrome-extension://abc/"])).as_deref(),
            Some("chrome-extension://abc/")
        );
        assert_eq!(
            reported_extension(&args(&["/tmp/m.json", "axo-pass@breakfastlabs.com"])).as_deref(),
            Some("axo-pass@breakfastlabs.com")
        );
        assert_eq!(reported_extension(&args(&[])), None);
    }

    #[test]
    fn chrome_extension_must_be_pinned_origin() {
        let manifest = Path::new("/nonexistent");
        let pinned = format!("chrome-extension://{CHROME_EXTENSION_ID}/");
        assert!(check_extension(Browser::Chrome, &args(&[&pinned]), manifest).is_ok());
        for other in [
            vec!["chrome-extension://other/"],
            vec![pinned.trim_end_matches('/')],
            vec![],
        ] {
            assert!(
                check_extension(Browser::Chrome, &args(&other), manifest).is_err(),
                "{other:?}"
            );
        }
    }

    #[test]
    fn firefox_needs_installed_manifest_and_extension_id() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("com.breakfastlabs.axo_pass.json");
        std::fs::write(&manifest, "{}").unwrap();
        let other = dir.path().join("other.json");
        std::fs::write(&other, "{}").unwrap();
        let manifest_arg = manifest.to_str().unwrap();

        assert!(
            check_extension(
                Browser::Firefox,
                &args(&[manifest_arg, FIREFOX_EXTENSION_ID]),
                &manifest
            )
            .is_ok()
        );
        assert!(
            check_extension(
                Browser::Firefox,
                &args(&[other.to_str().unwrap(), FIREFOX_EXTENSION_ID]),
                &manifest
            )
            .is_err()
        );
        assert!(
            check_extension(
                Browser::Firefox,
                &args(&[manifest_arg, "evil@example.com"]),
                &manifest
            )
            .is_err()
        );
        assert!(check_extension(Browser::Firefox, &args(&[manifest_arg]), &manifest).is_err());
    }

    #[test]
    fn manifest_must_name_running_executable() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("AxoPassBrowserHost");
        std::fs::write(&exe, "").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&exe, &link).unwrap();
        let manifest = dir.path().join("manifest.json");

        let write = |path: &Path| {
            let value = serde_json::json!({"name": "com.breakfastlabs.axo_pass", "path": path});
            std::fs::write(&manifest, value.to_string()).unwrap();
        };

        write(&exe);
        assert!(check_manifest(&manifest, &exe).is_ok());
        write(&link);
        assert!(check_manifest(&manifest, &exe).is_ok());
        write(Path::new("/usr/bin/true"));
        assert!(check_manifest(&manifest, &exe).is_err());

        std::fs::write(&manifest, r#"{"name":"x"}"#).unwrap();
        assert!(check_manifest(&manifest, &exe).is_err());
        assert!(check_manifest(&dir.path().join("missing.json"), &exe).is_err());
    }

    /// Response fixtures shared with the extension tests, one file per status
    /// the extension handles. Each parses as a broker response or a host
    /// status, never both, and serializes back to the same JSON.
    #[test]
    fn response_fixtures_round_trip() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/native-messaging/responses");
        let mut names = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_stem().unwrap().to_string_lossy().into_owned();
            let text = std::fs::read_to_string(&path).unwrap();
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(value["status"], name.as_str(), "{name}");

            let broker = serde_json::from_value::<WireResponse>(value.clone());
            let host = serde_json::from_value::<HostStatus>(value.clone());
            let round_trip = match (broker, host) {
                (Ok(response), Err(_)) => serde_json::to_value(&response).unwrap(),
                (Err(_), Ok(status)) => serde_json::to_value(&status).unwrap(),
                (broker, host) => panic!("{name}: broker {:?}, host {host:?}", broker.is_ok()),
            };
            assert_eq!(round_trip, value, "{name}");
            names.push(name);
        }
        names.sort();
        assert_eq!(
            names,
            [
                "acknowledged",
                "app_unavailable",
                "browser_not_verified",
                "cancelled",
                "failed",
                "generated_password",
                "locked_logins",
                "login_fill",
                "login_saved",
                "logins",
                "totp_code",
                "version_mismatch",
            ]
        );
    }

    #[test]
    fn host_statuses_serialize_with_status_tag() {
        assert_eq!(
            serde_json::to_value(HostStatus::BrowserNotVerified).unwrap(),
            serde_json::json!({"status": "browser_not_verified"})
        );
        assert_eq!(
            serde_json::to_value(HostStatus::VersionMismatch { version: 1 }).unwrap(),
            serde_json::json!({"status": "version_mismatch", "version": 1})
        );
        assert_eq!(
            serde_json::to_value(HostStatus::AppUnavailable {
                message: BrokerError::Unavailable.to_string()
            })
            .unwrap(),
            serde_json::json!({"status": "app_unavailable", "message": "App broker unavailable"})
        );
    }

    /// The test runner has no browser parent, so the host reports no browser
    /// and keeps the extension for audit.
    #[test]
    fn unverified_parent_reports_no_browser() {
        let client = identify_client(&args(&["chrome-extension://abc/"]));
        assert!(client.browser.is_none());
        assert_eq!(client.extension.as_deref(), Some("chrome-extension://abc/"));
    }
}
