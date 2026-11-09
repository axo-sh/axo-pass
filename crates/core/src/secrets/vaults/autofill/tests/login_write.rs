use super::super::{
    CATEGORY_LOGIN, FieldKind, MatchKind, SecretString, VaultHandle, Website, collect_items,
    create_login, find_login, save_login, set_websites, update_login_password, write_login,
};
use super::{github_login, login, names};

#[test]
fn write_login_creates_item_credentials_roles_and_websites() {
    use secrecy::ExposeSecret;

    let mut vw = VaultHandle::new_for_test("personal");
    let websites = vec!["github.com".to_string()];
    write_login(&mut vw, login(&websites, Some("tp"))).unwrap();

    let item = vw.get_item_overview("github").unwrap().unwrap();
    assert_eq!(item.title, "GitHub");
    assert_eq!(item.category.as_deref(), Some(CATEGORY_LOGIN));
    assert_eq!(
        item.autofill.websites,
        vec![Website::new("github.com", MatchKind::Domain)]
    );
    assert_eq!(
        item.autofill.password_credential(item).unwrap().key,
        "password"
    );
    let username = item.autofill.username_credential(item).unwrap();
    assert_eq!(username.key, "username");
    assert!(matches!(username.kind, FieldKind::Text(_)));

    let password = vw.get_secret("github", "password").unwrap().unwrap();
    assert_eq!(password.expose_secret(), "hunter2");
    let username = vw.get_secret("github", "username").unwrap().unwrap();
    assert_eq!(username.expose_secret(), "tp");

    let found = collect_items(&vw, Some("gist.github.com")).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].username.as_deref(), Some("tp"));
    assert_eq!(found[0].matched.as_ref().unwrap().host, "github.com");
    assert!(collect_items(&vw, Some("github.io")).unwrap().is_empty());
}

#[test]
fn write_login_stores_email_username_as_email() {
    let mut vw = VaultHandle::new_for_test("personal");
    write_login(&mut vw, login(&[], Some("tp@example.com"))).unwrap();
    let cred = vw
        .get_secret_overview("github", "username")
        .unwrap()
        .unwrap();
    assert_eq!(cred.kind, FieldKind::Email);
}

#[test]
fn write_login_does_not_duplicate_websites_on_update() {
    let mut vw = VaultHandle::new_for_test("personal");
    let websites = vec!["github.com".to_string()];
    write_login(&mut vw, login(&websites, None)).unwrap();
    write_login(&mut vw, login(&websites, None)).unwrap();
    let item = vw.get_item_overview("github").unwrap().unwrap();
    assert_eq!(item.autofill.websites.len(), 1);
    assert!(item.autofill.username.is_none());
}

#[test]
fn names_come_from_registrable_domain() {
    let pair = |key: &str, title: &str| (key.to_string(), title.to_string());
    assert_eq!(
        names("https://accounts.github.com/login"),
        pair("github", "Github.com")
    );
    assert_eq!(
        names("https://www.example.co.uk"),
        pair("example", "Example.co.uk")
    );
}

#[test]
fn names_fall_back_when_first_label_not_key() {
    let pair = |key: &str, title: &str| (key.to_string(), title.to_string());
    // Keys start with a letter and have at least three characters.
    assert_eq!(names("https://x.com"), pair("x-com", "X.com"));
    assert_eq!(names("https://t.co"), pair("t-co", "T.co"));
    assert_eq!(names("https://123.com"), pair("login", "123.com"));
}

#[test]
fn save_login_stores_host_website_and_conventional_keys() {
    use secrecy::ExposeSecret;

    let mut vw = VaultHandle::new_for_test("personal");
    let item = save_login(
        &mut vw,
        "https://login.example.com",
        Some("tp"),
        SecretString::from("pw"),
    )
    .unwrap();

    assert_eq!(item.item_key, "example");
    assert_eq!(item.title, "Example.com");
    assert_eq!(item.username.as_deref(), Some("tp"));
    assert_eq!(item.password_key, "password");

    let overview = vw.get_item_overview("example").unwrap().unwrap();
    assert_eq!(overview.category.as_deref(), Some(CATEGORY_LOGIN));
    assert_eq!(
        overview.autofill.websites,
        vec![Website::new("https://login.example.com", MatchKind::Host)]
    );
    let password = vw.get_secret("example", "password").unwrap().unwrap();
    assert_eq!(password.expose_secret(), "pw");

    // `host` matching offers the login on its own host and nowhere else
    // under the registrable domain.
    let id = &item.record_id;
    assert!(
        find_login(&vw, id, "https://login.example.com/x")
            .unwrap()
            .is_some()
    );
    assert!(
        find_login(&vw, id, "https://www.example.com")
            .unwrap()
            .is_none()
    );
}

#[test]
fn save_login_leaves_existing_item_alone() {
    use secrecy::ExposeSecret;

    let mut vw = VaultHandle::new_for_test("personal");
    let save = |vw: &mut VaultHandle, password: &str| {
        save_login(
            vw,
            "https://example.com",
            Some("tp"),
            SecretString::from(password),
        )
        .unwrap()
    };
    let first = save(&mut vw, "one");
    let second = save(&mut vw, "two");

    assert_eq!(first.item_key, "example");
    assert_eq!(second.item_key, "example-2");
    assert_ne!(first.record_id, second.record_id);
    let password = vw.get_secret("example", "password").unwrap().unwrap();
    assert_eq!(password.expose_secret(), "one");
}

#[test]
fn save_login_without_username_has_no_username_role() {
    let mut vw = VaultHandle::new_for_test("personal");
    let item = save_login(
        &mut vw,
        "https://example.com",
        Some("  "),
        SecretString::from("pw"),
    )
    .unwrap();
    assert!(item.username.is_none());
    let overview = vw.get_item_overview("example").unwrap().unwrap();
    assert!(overview.autofill.username.is_none());
}

#[test]
fn save_login_refuses_page_not_http() {
    let mut vw = VaultHandle::new_for_test("personal");
    assert!(save_login(&mut vw, "ftp://example.com", None, SecretString::from("pw")).is_err());
}

#[test]
fn update_login_password_changes_only_value() {
    use secrecy::ExposeSecret;

    let mut vw = VaultHandle::new_for_test("personal");
    let websites = vec!["github.com".to_string()];
    write_login(&mut vw, login(&websites, Some("tp"))).unwrap();
    let before = vw
        .get_secret_overview("github", "password")
        .unwrap()
        .unwrap()
        .clone();
    let item = collect_items(&vw, None).unwrap().remove(0);

    update_login_password(&mut vw, &item, SecretString::from("new")).unwrap();

    let password = vw.get_secret("github", "password").unwrap().unwrap();
    assert_eq!(password.expose_secret(), "new");
    let after = vw
        .get_secret_overview("github", "password")
        .unwrap()
        .unwrap();
    assert_eq!(after.id, before.id);
    assert_eq!(after.title, before.title);
    assert_eq!(after.kind, before.kind);
}

#[test]
fn create_login_derives_key_and_title_from_website() {
    let mut vw = VaultHandle::new_for_test("personal");
    let key = create_login(
        &mut vw,
        " github.com ",
        Some("tp"),
        SecretString::from("pw"),
        None,
        None,
    )
    .unwrap();
    assert_eq!(key, "github");
    let item = vw.get_item_overview("github").unwrap().unwrap();
    assert_eq!(item.title, "Github.com");
    assert_eq!(item.category.as_deref(), Some(CATEGORY_LOGIN));
    assert_eq!(
        item.autofill.websites,
        vec![Website::new("github.com", MatchKind::Domain)]
    );

    // A second login for the same site gets a numbered key.
    let key = create_login(
        &mut vw,
        "https://github.com/login",
        None,
        SecretString::from("pw2"),
        None,
        Some("Work GitHub"),
    )
    .unwrap();
    assert_eq!(key, "github-2");
    let item = vw.get_item_overview("github-2").unwrap().unwrap();
    assert_eq!(item.title, "Work GitHub");
    assert!(item.autofill.username.is_none());
}

#[test]
fn create_login_rejects_bad_website_or_key() {
    let mut vw = VaultHandle::new_for_test("personal");
    let create = |vw: &mut VaultHandle, website: &str, key: Option<&str>| {
        create_login(vw, website, None, SecretString::from("pw"), key, None)
    };
    assert!(create(&mut vw, "ftp://example.com", None).is_err());
    assert!(create(&mut vw, "", None).is_err());
    assert!(create(&mut vw, "example.com", Some("Not A Key")).is_err());
    assert!(vw.list_items().unwrap().is_empty());
}

#[test]
fn set_websites_replaces_list_and_checks_each_url() {
    let mut vw = VaultHandle::new_for_test("personal");
    github_login(&mut vw);
    set_websites(
        &mut vw,
        "github",
        vec![
            Website::new(" gist.github.com ", MatchKind::Host),
            Website::new("github.com", MatchKind::Never),
        ],
    )
    .unwrap();
    let item = vw.get_item_overview("github").unwrap().unwrap();
    assert_eq!(
        item.autofill.websites,
        vec![
            Website::new("gist.github.com", MatchKind::Host),
            Website::new("github.com", MatchKind::Never),
        ]
    );
    assert!(
        set_websites(
            &mut vw,
            "github",
            vec![Website::new("ftp://x.com", MatchKind::Domain)]
        )
        .is_err()
    );
    let item = vw.get_item_overview("github").unwrap().unwrap();
    assert_eq!(item.autofill.websites.len(), 2);
}
