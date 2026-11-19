use super::*;

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn install_writes_into_temp_home() {
    let f = fixture();
    for browser in Browser::ALL {
        assert_eq!(
            f.manifests.status(browser).state,
            ManifestState::NotInstalled
        );
        let status = f.manifests.install(browser).unwrap();
        assert_eq!(status.state, ManifestState::Current);
        assert!(status.manifest_path.starts_with(&f.home));
        assert_eq!(
            std::fs::read_to_string(&status.manifest_path).unwrap(),
            manifest_json(browser, &f.host)
        );
    }
}

#[test]
fn firefox_support_dir_alone_counts_as_installed() {
    let f = fixture();
    std::fs::remove_dir_all(f.home.join("Library/Application Support/Mozilla")).unwrap();
    assert!(!Browser::Firefox.is_installed_in(&f.home));
    std::fs::create_dir_all(f.home.join("Library/Application Support/Firefox")).unwrap();
    let status = f.manifests.install(Browser::Firefox).unwrap();
    assert_eq!(status.state, ManifestState::Current);
    assert!(status.manifest_path.ends_with(
        "Library/Application Support/Mozilla/NativeMessagingHosts/com.breakfastlabs.axo_pass.json"
    ));
}

#[test]
fn chrome_state_checks_allowed_origins() {
    let f = fixture();
    let host = f.host.to_str().unwrap();
    // A Firefox-style manifest in the Chrome directory lacks allowed_origins.
    write_manifest(
        &f,
        Browser::Chrome,
        serde_json::json!({
            "name": NATIVE_HOST_NAME,
            "path": host,
            "type": "stdio",
            "allowed_extensions": [FIREFOX_EXTENSION_ID],
        }),
    );
    assert_eq!(
        f.manifests.status(Browser::Chrome).state,
        ManifestState::Outdated
    );
    f.manifests.install(Browser::Chrome).unwrap();
    assert_eq!(
        f.manifests.status(Browser::Chrome).state,
        ManifestState::Current
    );
}

#[test]
fn ensure_rewrites_only_differing_path() {
    let f = fixture();
    f.manifests.install(Browser::Chrome).unwrap();
    let firefox = write_manifest(
        &f,
        Browser::Firefox,
        serde_json::json!({
            "name": NATIVE_HOST_NAME,
            "path": "/usr/bin/true",
            "type": "stdio",
            "allowed_extensions": [FIREFOX_EXTENSION_ID],
        }),
    );
    // Mark the current manifest so a rewrite would be visible.
    let chrome = Browser::Chrome.manifest_path_in(&f.home);
    let mut marked = read_json(&chrome);
    marked["description"] = "kept".into();
    std::fs::write(&chrome, marked.to_string()).unwrap();

    assert_eq!(f.manifests.ensure(), vec![Browser::Firefox]);
    assert_eq!(read_json(&chrome)["description"], "kept");
    assert_eq!(read_json(&firefox)["path"], f.host.to_str().unwrap());
    assert_eq!(
        f.manifests.status(Browser::Firefox).state,
        ManifestState::Current
    );

    assert_eq!(f.manifests.ensure(), Vec::<Browser>::new());
}

#[test]
fn ensure_installs_missing_manifests() {
    let f = fixture();
    assert_eq!(f.manifests.ensure(), Browser::ALL.to_vec());
    for browser in Browser::ALL {
        assert_eq!(f.manifests.status(browser).state, ManifestState::Current);
    }
    assert_eq!(f.manifests.ensure(), Vec::<Browser>::new());
}

#[test]
fn ensure_skips_browsers_that_are_not_installed() {
    let f = fixture();
    std::fs::remove_dir_all(f.home.join("Library/Application Support/Google")).unwrap();
    assert_eq!(f.manifests.ensure(), vec![Browser::Firefox]);
    assert!(!Browser::Chrome.manifest_dir_in(&f.home).exists());
}

#[test]
fn foreign_and_unreadable_manifests_are_untouched() {
    let f = fixture();
    let foreign = serde_json::json!({"name": "com.example.other", "path": "/usr/bin/true"});
    let chrome = write_manifest(&f, Browser::Chrome, foreign.clone());
    let firefox = Browser::Firefox.manifest_path_in(&f.home);
    std::fs::create_dir_all(firefox.parent().unwrap()).unwrap();
    std::fs::write(&firefox, "{not json").unwrap();

    assert_eq!(f.manifests.ensure(), Vec::<Browser>::new());
    assert_eq!(read_json(&chrome), foreign);
    assert_eq!(std::fs::read_to_string(&firefox).unwrap(), "{not json");

    assert!(matches!(
        f.manifests.install(Browser::Chrome),
        Err(ManifestError::Foreign { .. })
    ));
    assert_eq!(read_json(&chrome), foreign);
}

#[test]
fn install_replaces_unreadable_manifest() {
    let f = fixture();
    let firefox = Browser::Firefox.manifest_path_in(&f.home);
    std::fs::create_dir_all(firefox.parent().unwrap()).unwrap();
    std::fs::write(&firefox, "{not json").unwrap();
    let status = f.manifests.install(Browser::Firefox).unwrap();
    assert_eq!(status.state, ManifestState::Current);
}

#[test]
fn writes_leave_no_temp_files() {
    let f = fixture();
    f.manifests.install(Browser::Firefox).unwrap();
    f.manifests.install(Browser::Firefox).unwrap();
    let names: Vec<_> = std::fs::read_dir(Browser::Firefox.manifest_dir_in(&f.home))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(
        names,
        vec![std::ffi::OsString::from("com.breakfastlabs.axo_pass.json")]
    );
}
