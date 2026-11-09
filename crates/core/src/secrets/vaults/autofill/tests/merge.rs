use super::super::{
    CATEGORY_LOGIN, FieldKind, MatchKind, Role, SecretString, VaultHandle,
    VaultItemCredentialOverview, Website, add_passkey_login, merge_items, set_role, set_websites,
};
use super::{github_login, legacy_item};

#[test]
fn merge_moves_credentials_and_deletes_source() {
    use secrecy::ExposeSecret;

    let mut vw = VaultHandle::new_for_test("personal");
    github_login(&mut vw);
    add_passkey_login(&mut vw, "github.com", Some("GitHub"), Some("tp")).unwrap();
    let source = vw
        .list_items()
        .unwrap()
        .into_iter()
        .find(|item| item.key != "github")
        .unwrap()
        .key
        .clone();
    vw.add_secret(
        &source,
        "passkey-aa",
        "tp",
        FieldKind::Passkey,
        SecretString::from("{}"),
    )
    .unwrap();
    set_websites(
        &mut vw,
        &source,
        vec![
            Website::new("github.com", MatchKind::Domain),
            Website::new("gist.github.com", MatchKind::Host),
        ],
    )
    .unwrap();

    merge_items(&mut vw, &source, "github").unwrap();

    assert!(vw.get_item_overview(&source).unwrap().is_none());
    let item = vw.get_item_overview("github").unwrap().unwrap();
    let mut keys: Vec<_> = item.credentials.values().map(|c| c.key.as_str()).collect();
    keys.sort();
    // The equal username is dropped rather than copied as `username-2`.
    assert_eq!(keys, ["passkey-aa", "password", "username"]);
    assert_eq!(
        item.autofill.username_credential(item).unwrap().key,
        "username"
    );
    assert_eq!(
        item.autofill.password_credential(item).unwrap().key,
        "password"
    );
    assert_eq!(
        item.autofill.websites,
        vec![
            Website::new("github.com", MatchKind::Domain),
            Website::new("gist.github.com", MatchKind::Host),
        ]
    );
    let passkey = vw.get_secret("github", "passkey-aa").unwrap().unwrap();
    assert_eq!(passkey.expose_secret(), "{}");

    // The deleted source keeps no copy of the passkey.
    let deleted = vw.list_deleted_items().unwrap();
    assert_eq!(deleted.len(), 1);
    let is_passkey = |c: &&VaultItemCredentialOverview| matches!(c.kind, FieldKind::Passkey);
    assert!(!deleted[0].item.credentials.values().any(|c| is_passkey(&c)));
    assert!(!deleted[0].deleted_credentials.iter().any(is_passkey));
    assert!(vw.list_all_deleted().unwrap().is_empty());
}

#[test]
fn merge_renames_differing_credential_and_fills_missing_roles() {
    let mut vw = VaultHandle::new_for_test("personal");
    legacy_item(
        &mut vw,
        "alpha",
        &[("username", FieldKind::Email, "x@y.com")],
    );
    legacy_item(
        &mut vw,
        "bravo",
        &[
            ("username", FieldKind::Email, "other@y.com"),
            ("password", FieldKind::default(), "pw"),
        ],
    );
    set_role(&mut vw, "bravo", Role::Password, Some("password")).unwrap();
    set_role(&mut vw, "bravo", Role::Username, Some("username")).unwrap();

    merge_items(&mut vw, "bravo", "alpha").unwrap();

    let item = vw.get_item_overview("alpha").unwrap().unwrap();
    let mut keys: Vec<_> = item.credentials.values().map(|c| c.key.as_str()).collect();
    keys.sort();
    assert_eq!(keys, ["password", "username", "username-2"]);
    assert_eq!(
        item.autofill.username_credential(item).unwrap().key,
        "username-2"
    );
    assert_eq!(
        item.autofill.password_credential(item).unwrap().key,
        "password"
    );
    assert_eq!(item.category.as_deref(), Some(CATEGORY_LOGIN));
}

#[test]
fn merge_keeps_history_and_sections_and_purges_emptied_source() {
    use secrecy::ExposeSecret;

    let mut vw = VaultHandle::new_for_test("personal");
    legacy_item(&mut vw, "alpha", &[]);
    legacy_item(
        &mut vw,
        "bravo",
        &[("password", FieldKind::default(), "old")],
    );
    vw.add_secret(
        "bravo",
        "password",
        "password",
        FieldKind::default(),
        SecretString::from("new"),
    )
    .unwrap();
    let section = vw.create_item_section("bravo", "Recovery").unwrap().id;
    vw.move_credential("bravo", "password", Some(section))
        .unwrap();
    let existing = vw.create_item_section("alpha", "Recovery").unwrap().id;
    let bravo_id = vw.get_item_overview("bravo").unwrap().unwrap().id;

    merge_items(&mut vw, "bravo", "alpha").unwrap();

    let item = vw.get_item_overview("alpha").unwrap().unwrap();
    // The source section maps onto the destination section with its title.
    assert_eq!(item.sections.len(), 1);
    let moved = &item.credentials.values().next().unwrap();
    assert_eq!(moved.section, Some(existing));
    let history = vw.list_history("alpha", "password").unwrap();
    assert_eq!(history.len(), 1);
    let previous = vw
        .get_history_value("alpha", "password", history[0].id)
        .unwrap();
    assert_eq!(previous.expose_secret(), "old");
    // Nothing stayed in the source, so it is not kept as a deleted item.
    assert!(vw.get_item_overview("bravo").unwrap().is_none());
    assert!(
        !vw.list_deleted_items()
            .unwrap()
            .iter()
            .any(|d| d.item.id == bravo_id)
    );
}

#[test]
fn merge_into_itself_is_error() {
    let mut vw = VaultHandle::new_for_test("personal");
    github_login(&mut vw);
    assert!(merge_items(&mut vw, "github", "github").is_err());
    assert!(vw.get_item_overview("github").unwrap().is_some());
}
