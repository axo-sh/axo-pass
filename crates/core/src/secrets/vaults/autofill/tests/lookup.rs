use super::super::{
    Error, FieldKind, SecretString, ShortId, Site, Uuid, VaultHandle, check_rp_id, collect_items,
    find_login, find_login_record, is_stored_for, login_totp, parse_record_id, read_login,
    write_login,
};
use super::{github_login, key_of, login, overview};

#[test]
fn find_login_record_ignores_page_but_not_id() {
    let mut vw = VaultHandle::new_for_test("personal");
    let websites = vec!["github.com".to_string()];
    write_login(&mut vw, login(&websites, Some("tp"))).unwrap();
    let item = collect_items(&vw, None).unwrap().remove(0);

    let found = find_login_record(&vw, &item.record_id).unwrap().unwrap();
    assert_eq!(found.record_id, item.record_id);

    let (vault, item_id, _) = parse_record_id(&item.record_id).unwrap();
    let wrong_credential = format!("{vault}/{item_id}/{}", Uuid::new_v4());
    assert!(find_login_record(&vw, &wrong_credential).unwrap().is_none());
    assert!(find_login_record(&vw, "not-a-record").unwrap().is_none());
}

#[test]
fn record_id_with_hyphenated_ids_finds_its_login() {
    let mut vw = VaultHandle::new_for_test("personal");
    let websites = vec!["github.com".to_string()];
    write_login(&mut vw, login(&websites, Some("tp"))).unwrap();
    let item = collect_items(&vw, None).unwrap().remove(0);
    let (vault, item_id, credential) = parse_record_id(&item.record_id).unwrap();
    assert_eq!(
        item.record_id,
        format!(
            "{}/{}/{}",
            ShortId::new(vault),
            ShortId::new(item_id),
            ShortId::new(credential)
        )
    );

    // Identifier registered in the AutoFill index before ids were short.
    let hyphenated = format!("{vault}/{item_id}/{credential}");
    let found = find_login_record(&vw, &hyphenated).unwrap().unwrap();
    assert_eq!(found.record_id, item.record_id);
    let found = find_login(&vw, &hyphenated, "https://github.com/login").unwrap();
    assert_eq!(found.unwrap().record_id, item.record_id);
}

#[test]
fn login_stored_for_page_only_through_listed_website() {
    let mut vw = VaultHandle::new_for_test("personal");
    let websites = vec!["github.com".to_string()];
    write_login(&mut vw, login(&websites, Some("tp"))).unwrap();
    let item = find_login_record(&vw, &collect_items(&vw, None).unwrap()[0].record_id)
        .unwrap()
        .unwrap();

    assert!(is_stored_for(&item, "https://gist.github.com/new"));
    assert!(!is_stored_for(&item, "https://evil.com"));
}

/// Point the github test item's totp slot at the credential `cred_key`.
fn set_totp_slot(vw: &mut VaultHandle, cred_key: &str) {
    let overview = vw.get_item_overview("github").unwrap().unwrap();
    let mut autofill = overview.autofill.clone();
    autofill.totp = Some(key_of(overview, cred_key));
    vw.set_item_autofill("github", autofill).unwrap();
}

#[test]
fn totp_credential_with_no_slot_gives_no_code() {
    let item = overview(&[
        ("password", FieldKind::default()),
        ("code", FieldKind::Totp),
    ]);
    assert!(item.autofill.totp_credential(&item).is_none());
}

#[test]
fn totp_slot_decides_which_credential_makes_code() {
    let mut item = overview(&[("first", FieldKind::Totp), ("second", FieldKind::Totp)]);
    item.autofill.totp = Some(key_of(&item, "second"));
    assert_eq!(item.autofill.totp_credential(&item).unwrap().key, "second");
}

#[test]
fn totp_slot_that_points_at_nothing_usable_means_no_code() {
    let mut item = overview(&[
        ("password", FieldKind::default()),
        ("code", FieldKind::Totp),
    ]);

    // A missing credential does not fall back to the `Totp` one.
    item.autofill.totp = Some(uuid::Uuid::new_v4());
    assert!(item.autofill.totp_credential(&item).is_none());

    // A credential that is not a one-time code is not used either.
    item.autofill.totp = Some(key_of(&item, "password"));
    assert!(item.autofill.totp_credential(&item).is_none());
}

#[test]
fn has_totp_follows_totp_slot() {
    let mut vw = VaultHandle::new_for_test("personal");
    let record_id = github_login(&mut vw);
    let has_totp = |vw: &VaultHandle| collect_items(vw, None).unwrap()[0].has_totp;
    assert!(!has_totp(&vw));

    vw.add_secret(
        "github",
        "code",
        "Code",
        FieldKind::Totp,
        SecretString::from("JBSWY3DPEHPK3PXP"),
    )
    .unwrap();
    // The credential alone does not make a code. The slot does.
    assert!(!has_totp(&vw));

    set_totp_slot(&mut vw, "code");
    assert!(has_totp(&vw));

    // Deleting the credential clears the slot.
    vw.delete_item_credential("github", "code").unwrap();
    assert!(!has_totp(&vw));
    let item = find_login_record(&vw, &record_id).unwrap().unwrap();
    assert!(login_totp(&vw, &item).unwrap().is_none());
    assert!(
        vw.get_item_overview("github")
            .unwrap()
            .unwrap()
            .autofill
            .totp
            .is_none()
    );
}

#[test]
fn find_login_requires_website_that_matches_frame() {
    let mut vw = VaultHandle::new_for_test("personal");
    let record_id = github_login(&mut vw);

    let found = find_login(&vw, &record_id, "https://gist.github.com/new")
        .unwrap()
        .unwrap();
    assert_eq!(found.record_id, record_id);
    assert_eq!(found.username.as_deref(), Some("tp"));

    assert!(
        find_login(&vw, &record_id, "https://github.io")
            .unwrap()
            .is_none()
    );
    assert!(
        find_login(&vw, &record_id, "https://evil.com")
            .unwrap()
            .is_none()
    );
    assert!(find_login(&vw, &record_id, "").unwrap().is_none());
    assert!(
        find_login(&vw, &record_id, "ftp://github.com")
            .unwrap()
            .is_none()
    );
}

#[test]
fn find_login_refuses_ids_that_do_not_name_this_login() {
    let mut vw = VaultHandle::new_for_test("personal");
    let record_id = github_login(&mut vw);
    let (vault, item, credential) = parse_record_id(&record_id).unwrap();
    let new = Uuid::new_v4;

    for wrong in [
        format!("{}/{item}/{credential}", new()),
        format!("{vault}/{}/{credential}", new()),
        format!("{vault}/{item}/{}", new()),
        format!("{vault}/{item}"),
        format!("{record_id}/extra"),
        "github/github/password".to_string(),
        String::new(),
    ] {
        assert!(
            find_login(&vw, &wrong, "https://github.com")
                .unwrap()
                .is_none(),
            "{wrong}"
        );
    }
}

#[test]
fn read_login_returns_only_role_credentials() {
    use secrecy::ExposeSecret;

    let mut vw = VaultHandle::new_for_test("personal");
    let record_id = github_login(&mut vw);
    vw.add_secret(
        "github",
        "recovery",
        "Recovery code",
        FieldKind::default(),
        SecretString::from("do-not-return"),
    )
    .unwrap();

    let item = find_login(&vw, &record_id, "github.com").unwrap().unwrap();
    let secrets = read_login(&vw, &item).unwrap().unwrap();
    assert_eq!(secrets.username.as_deref(), Some("tp"));
    assert_eq!(secrets.password.expose_secret(), "hunter2");
}

#[test]
fn login_listing_summary_carries_no_secret_or_key() {
    let mut vw = VaultHandle::new_for_test("personal");
    github_login(&mut vw);
    let found = collect_items(&vw, Some("github.com")).unwrap();
    let summary = found[0].summary(false).unwrap();
    assert_eq!(summary.title, "GitHub");
    assert_eq!(summary.username.as_deref(), Some("tp"));
    assert_eq!(summary.matched.host, "github.com");
    let json = serde_json::to_string(&summary).unwrap();
    assert!(!json.contains("hunter2"));
    assert!(!json.contains("password"));
    assert!(
        collect_items(&vw, None).unwrap()[0]
            .summary(false)
            .is_none()
    );
}

#[test]
fn login_totp_uses_credential_in_totp_slot() {
    let mut vw = VaultHandle::new_for_test("personal");
    let record_id = github_login(&mut vw);
    let item = find_login(&vw, &record_id, "github.com").unwrap().unwrap();
    assert!(login_totp(&vw, &item).unwrap().is_none());

    vw.add_secret(
        "github",
        "otp",
        "Code",
        FieldKind::Totp,
        SecretString::from("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
    )
    .unwrap();
    vw.add_secret(
        "github",
        "broken",
        "Broken",
        FieldKind::Totp,
        SecretString::from("!!"),
    )
    .unwrap();

    // Without a slot there is no code, whatever credentials exist.
    assert!(login_totp(&vw, &item).unwrap().is_none());

    set_totp_slot(&mut vw, "otp");
    let code = login_totp(&vw, &item).unwrap().unwrap();
    assert_eq!(code.code.len(), 6);

    set_totp_slot(&mut vw, "broken");
    assert!(matches!(
        login_totp(&vw, &item),
        Err(Error::InvalidOneTimeCode(_))
    ));
}

#[test]
fn site_reports_host_domain_and_scheme() {
    let site = Site::parse("http://www.accounts.example.co.uk:8080/x").unwrap();
    assert_eq!(site.host, "accounts.example.co.uk");
    assert_eq!(site.domain, "example.co.uk");
    assert!(!site.secure);
    assert!(Site::parse("https://example.com").unwrap().secure);
    assert!(Site::parse("example.com").unwrap().secure);
    assert!(!Site::parse("HTTP://example.com").unwrap().secure);
    assert!(!Site::parse(" http://example.com").unwrap().secure);
    assert!(Site::parse("ftp://example.com").is_none());
}

#[test]
fn rp_ids_must_be_valid_for_origin() {
    let ok = |rp: &str, origin: &str| check_rp_id(rp, Some(origin)).is_ok();
    assert!(ok("example.com", "https://login.example.com"));
    assert!(ok("example.com", "https://example.com"));
    assert!(ok("login.example.com", "https://login.example.com"));
    assert!(ok("example.com", "https://a.b.example.com:8443/path"));

    assert!(!ok("login.example.com", "https://example.com"));
    assert!(!ok("github.io", "https://example.github.io"));
    assert!(!ok("github.io", "https://github.io"));
    assert!(!ok("evil.com", "https://example.com"));
    assert!(!ok("example.com", "https://notexample.com"));
    assert!(!ok("example.com", "https://example.com.evil.com"));
    assert!(!ok("com", "https://example.com"));
    assert!(!ok("co.uk", "https://example.co.uk"));
    assert!(!ok("example.com", "https://192.168.0.1"));
}

#[test]
fn rp_ids_checked_without_origin() {
    assert!(check_rp_id("example.com", None).is_ok());
    assert!(check_rp_id("login.example.co.uk", None).is_ok());
    for invalid in [
        "",
        "github.io",
        "co.uk",
        "localhost",
        "192.168.0.1",
        "Example.com",
        "https://example.com",
        "example.com:8080",
        "example.com/path",
        ".example.com",
        "example.com.",
    ] {
        assert!(check_rp_id(invalid, None).is_err(), "{invalid:?}");
    }
}
