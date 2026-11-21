// Tests that need an installed browser are in `macos`: the Linux browser
// paths come in 0.8, so no browser counts as installed.
#[cfg(macos)]
mod macos;

use super::*;

struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    host: PathBuf,
    manifests: BrowserManifests,
}

/// Temp home with both browsers installed and a host executable.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    for dir in [
        "Library/Application Support/Google/Chrome",
        "Library/Application Support/Mozilla",
    ] {
        std::fs::create_dir_all(home.join(dir)).unwrap();
    }
    let host = dir.path().join(BROWSER_HOST_EXECUTABLE_NAME);
    std::fs::write(&host, "").unwrap();
    let manifests = BrowserManifests::new(home.clone(), host.clone());
    Fixture {
        _dir: dir,
        home,
        host,
        manifests,
    }
}

fn write_manifest(f: &Fixture, browser: Browser, value: serde_json::Value) -> PathBuf {
    let path = browser.manifest_path_in(&f.home);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, value.to_string()).unwrap();
    path
}

#[test]
fn chrome_manifest_lists_allowed_origins() {
    let json: serde_json::Value =
        serde_json::from_str(&manifest_json(Browser::Chrome, Path::new("/h"))).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "name": "com.breakfastlabs.axo_pass",
            "description": "Axo Pass",
            "path": "/h",
            "type": "stdio",
            "allowed_origins": [format!("chrome-extension://{CHROME_EXTENSION_ID}/")],
        })
    );
}

#[test]
fn firefox_manifest_lists_allowed_extensions() {
    let json: serde_json::Value =
        serde_json::from_str(&manifest_json(Browser::Firefox, Path::new("/h"))).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "name": "com.breakfastlabs.axo_pass",
            "description": "Axo Pass",
            "path": "/h",
            "type": "stdio",
            "allowed_extensions": ["pass@axo.sh"],
        })
    );
}

#[test]
fn install_needs_browser_support_dir() {
    let f = fixture();
    std::fs::remove_dir_all(f.home.join("Library/Application Support/Google")).unwrap();
    let status = f.manifests.status(Browser::Chrome);
    assert!(!status.browser_installed);
    assert!(matches!(
        f.manifests.install(Browser::Chrome),
        Err(ManifestError::BrowserNotInstalled { .. })
    ));
    assert!(!Browser::Chrome.manifest_dir_in(&f.home).exists());
}

#[test]
fn install_refuses_missing_host() {
    let f = fixture();
    std::fs::remove_file(&f.host).unwrap();
    assert!(matches!(
        f.manifests.install(Browser::Firefox),
        Err(ManifestError::HostMissing { .. })
    ));
}

#[test]
fn detects_each_state() {
    let f = fixture();
    let browser = Browser::Firefox;
    let state = |value: serde_json::Value| {
        write_manifest(&f, browser, value);
        f.manifests.status(browser).state
    };
    let ours = |path: &str, allowed: &[&str]| {
        serde_json::json!({
            "name": NATIVE_HOST_NAME,
            "path": path,
            "type": "stdio",
            "allowed_extensions": allowed,
        })
    };
    let host = f.host.to_str().unwrap();

    assert_eq!(
        state(ours(host, &[FIREFOX_EXTENSION_ID])),
        ManifestState::Current
    );

    let link = f.host.with_file_name("link");
    std::os::unix::fs::symlink(&f.host, &link).unwrap();
    assert_eq!(
        state(ours(link.to_str().unwrap(), &[FIREFOX_EXTENSION_ID])),
        ManifestState::Current
    );

    assert_eq!(
        state(ours("/usr/bin/true", &[FIREFOX_EXTENSION_ID])),
        ManifestState::PointsElsewhere {
            path: Some(PathBuf::from("/usr/bin/true"))
        }
    );
    assert_eq!(
        state(serde_json::json!({"name": NATIVE_HOST_NAME})),
        ManifestState::PointsElsewhere { path: None }
    );
    assert_eq!(
        state(ours(host, &["evil@example.com"])),
        ManifestState::Outdated
    );
    assert_eq!(
        state(serde_json::json!({"name": "com.example.other", "path": host})),
        ManifestState::Foreign {
            name: "com.example.other".to_string()
        }
    );
    assert!(matches!(
        state(serde_json::json!({"path": host})),
        ManifestState::Unreadable { .. }
    ));

    let path = browser.manifest_path_in(&f.home);
    std::fs::write(&path, "{not json").unwrap();
    assert!(matches!(
        f.manifests.status(browser).state,
        ManifestState::Unreadable { .. }
    ));
}

#[test]
fn ensure_writes_nothing_without_host() {
    let f = fixture();
    std::fs::remove_file(&f.host).unwrap();
    assert_eq!(f.manifests.ensure(), Vec::<Browser>::new());
    for browser in Browser::ALL {
        assert!(!browser.manifest_path_in(&f.home).exists());
    }
}
