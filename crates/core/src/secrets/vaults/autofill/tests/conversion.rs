use super::super::{
    CATEGORY_LOGIN, FieldKind, MatchKind, Role, SecretString, VaultHandle, Website, collect_items,
    collect_places, convert_to_login, pick_password, pick_username, set_role, sorted_credentials,
    suggest_conversion,
};
use super::{github_login, key_of, legacy_item, overview};

#[test]
fn item_without_autofill_data_not_offered() {
    let mut vw = VaultHandle::new_for_test("personal");
    legacy_item(
        &mut vw,
        "blog",
        &[
            ("password", FieldKind::default(), "pw"),
            ("site", FieldKind::Url, "https://blog.example.com/login"),
        ],
    );
    assert!(collect_items(&vw, None).unwrap().is_empty());
    assert!(collect_items(&vw, Some("example.com")).unwrap().is_empty());
    assert!(collect_places(&vw).unwrap().is_empty());
}

#[test]
fn conversion_assigns_roles_and_websites_from_credentials() {
    let mut vw = VaultHandle::new_for_test("personal");
    legacy_item(
        &mut vw,
        "blog",
        &[
            ("api-token", FieldKind::default(), "token"),
            ("password", FieldKind::default(), "pw"),
            ("email", FieldKind::Email, "tp@example.com"),
            ("code", FieldKind::Totp, "JBSWY3DPEHPK3PXP"),
            ("site", FieldKind::Url, "https://blog.example.com/login"),
        ],
    );
    let overview = vw.get_item_overview("blog").unwrap().unwrap();
    let conversion = suggest_conversion(&vw, overview).unwrap().unwrap();
    assert_eq!(conversion.password, key_of(overview, "password"));
    assert_eq!(conversion.username, Some(key_of(overview, "email")));
    assert_eq!(conversion.totp, Some(key_of(overview, "code")));

    assert!(convert_to_login(&mut vw, "blog").unwrap());
    let item = vw.get_item_overview("blog").unwrap().unwrap();
    assert_eq!(item.category.as_deref(), Some(CATEGORY_LOGIN));
    assert_eq!(
        item.autofill.websites,
        vec![Website::new(
            "https://blog.example.com/login",
            MatchKind::Domain
        )]
    );
    let found = collect_items(&vw, Some("example.com")).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].username.as_deref(), Some("tp@example.com"));
    assert!(found[0].has_totp);
    // Keys are not renamed.
    assert!(vw.get_secret("blog", "email").unwrap().is_some());

    // A converted item has nothing left to convert.
    assert!(!convert_to_login(&mut vw, "blog").unwrap());
}

#[test]
fn conversion_limited_to_http_sites() {
    let mut vw = VaultHandle::new_for_test("personal");
    legacy_item(
        &mut vw,
        "database",
        &[
            ("password", FieldKind::default(), "pw"),
            ("url", FieldKind::Url, "postgres://example.com/db"),
        ],
    );
    let overview = vw.get_item_overview("database").unwrap().unwrap();
    assert!(suggest_conversion(&vw, overview).unwrap().is_none());
    assert!(!convert_to_login(&mut vw, "database").unwrap());
}

#[test]
fn conversion_needs_confidential_credential() {
    let mut vw = VaultHandle::new_for_test("personal");
    legacy_item(
        &mut vw,
        "notes",
        &[("site", FieldKind::Url, "https://example.com")],
    );
    assert!(!convert_to_login(&mut vw, "notes").unwrap());
}

#[test]
fn conversion_leaves_item_with_roles_alone() {
    let mut vw = VaultHandle::new_for_test("personal");
    github_login(&mut vw);
    vw.add_secret(
        "github",
        "site",
        "Site",
        FieldKind::Url,
        SecretString::from("https://other.example.com"),
    )
    .unwrap();
    assert!(!convert_to_login(&mut vw, "github").unwrap());
    let item = vw.get_item_overview("github").unwrap().unwrap();
    assert_eq!(item.autofill.websites.len(), 1);
}

#[test]
fn roles_decide_credentials_to_fill() {
    let mut item = overview(&[
        ("password", FieldKind::default()),
        ("pin", FieldKind::default()),
        ("handle", FieldKind::Text(Default::default())),
    ]);
    item.autofill.password = Some(key_of(&item, "pin"));
    item.autofill.username = Some(key_of(&item, "handle"));
    assert_eq!(item.autofill.password_credential(&item).unwrap().key, "pin");
    assert_eq!(
        item.autofill.username_credential(&item).unwrap().key,
        "handle"
    );
}

#[test]
fn dangling_password_role_not_login() {
    let mut item = overview(&[("password", FieldKind::default())]);
    item.autofill.password = Some(uuid::Uuid::new_v4());
    assert!(item.autofill.password_credential(&item).is_none());
}

#[test]
fn set_role_moves_credential_between_roles() {
    let mut vw = VaultHandle::new_for_test("personal");
    github_login(&mut vw);
    set_role(&mut vw, "github", Role::Password, Some("username")).unwrap();
    let item = vw.get_item_overview("github").unwrap().unwrap();
    assert_eq!(
        item.autofill.password_credential(item).unwrap().key,
        "username"
    );
    // The credential left the username role.
    assert!(item.autofill.username.is_none());

    set_role(&mut vw, "github", Role::Password, None).unwrap();
    let item = vw.get_item_overview("github").unwrap().unwrap();
    assert!(item.autofill.password.is_none());
}

#[test]
fn set_role_rejects_credential_of_wrong_kind() {
    let mut vw = VaultHandle::new_for_test("personal");
    github_login(&mut vw);
    vw.add_secret(
        "github",
        "code",
        "Code",
        FieldKind::Totp,
        SecretString::from("JBSWY3DPEHPK3PXP"),
    )
    .unwrap();
    assert!(set_role(&mut vw, "github", Role::Password, Some("code")).is_err());
    assert!(set_role(&mut vw, "github", Role::Totp, Some("password")).is_err());
    assert!(set_role(&mut vw, "github", Role::Totp, Some("missing")).is_err());
    set_role(&mut vw, "github", Role::Totp, Some("code")).unwrap();
    assert!(collect_items(&vw, None).unwrap()[0].has_totp);
}

#[test]
fn set_role_makes_uncategorized_item_login() {
    let mut vw = VaultHandle::new_for_test("personal");
    legacy_item(&mut vw, "blog", &[("secret", FieldKind::default(), "pw")]);
    set_role(&mut vw, "blog", Role::Password, Some("secret")).unwrap();
    let item = vw.get_item_overview("blog").unwrap().unwrap();
    assert_eq!(item.category.as_deref(), Some(CATEGORY_LOGIN));
}

#[test]
fn conversion_prefers_credential_named_password_and_email_username() {
    let item = overview(&[
        ("api-token", FieldKind::default()),
        ("password", FieldKind::default()),
        ("login", FieldKind::Text(Default::default())),
        ("email", FieldKind::Email),
    ]);
    let credentials = sorted_credentials(&item);
    assert_eq!(pick_password(&credentials).unwrap().key, "password");
    assert_eq!(pick_username(&credentials).unwrap().key, "email");
}

#[test]
fn conversion_falls_back_to_conventional_username_key() {
    let item = overview(&[
        ("pass", FieldKind::default()),
        ("account", FieldKind::Text(Default::default())),
    ]);
    let credentials = sorted_credentials(&item);
    assert_eq!(pick_password(&credentials).unwrap().key, "pass");
    assert_eq!(pick_username(&credentials).unwrap().key, "account");
}
