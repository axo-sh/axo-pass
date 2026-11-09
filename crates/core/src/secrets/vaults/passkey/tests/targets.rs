use super::*;
use crate::secrets::vaults::MatchKind;

#[tokio::test]
async fn new_login_target_creates_login_item() {
    let mut vw = VaultHandle::new_for_test("personal");
    register(&mut vw, PasskeyTarget::NewLogin, "ada@example.com").await;

    let passkeys = list(&vw).unwrap();
    assert_eq!(passkeys.len(), 1);
    let item = vw
        .get_item_overview(&passkeys[0].item_key)
        .unwrap()
        .unwrap();
    assert_eq!(item.title, "Example");
    assert_eq!(item.category.as_deref(), Some("login"));
    assert_eq!(item.autofill.websites.len(), 1);
    assert_eq!(item.autofill.websites[0].url, "example.com");
    assert!(item.autofill.password.is_none());
    let username = item.autofill.username_credential(item).unwrap();
    assert_eq!(username.key, "username");
    assert_eq!(passkeys[0].record_id().split('/').count(), 3);
}

#[tokio::test]
async fn item_target_stores_passkey_beside_login() {
    let mut vw = VaultHandle::new_for_test("personal");
    autofill::write_login(
        &mut vw,
        autofill::LoginWrite {
            item_key: "example",
            title: "Example",
            password_key: "password",
            password: SecretString::from("pw"),
            username: Some("ada"),
            websites: &["example.com".to_string()],
            match_kind: MatchKind::Domain,
        },
    )
    .unwrap();
    register(&mut vw, PasskeyTarget::Item("example".into()), "ada").await;

    let passkeys = list(&vw).unwrap();
    assert_eq!(passkeys.len(), 1);
    assert_eq!(passkeys[0].item_key, "example");
    assert_eq!(vw.list_items().unwrap().len(), 1);
}

#[test]
fn only_passkeys_can_be_removed_after_move() {
    let mut vw = VaultHandle::new_for_test("personal");
    vw.add_item("site", "Site").unwrap();
    vw.add_secret(
        "site",
        "password",
        "Password",
        FieldKind::default(),
        SecretString::from("pw"),
    )
    .unwrap();
    assert!(remove_record(&mut vw, "site", "password").is_err());
    assert!(vw.get_secret("site", "password").unwrap().is_some());
}

#[test]
fn only_passkeys_can_be_read_for_move() {
    let mut vw = VaultHandle::new_for_test("personal");
    vw.add_item("site", "Site").unwrap();
    vw.add_secret(
        "site",
        "password",
        "Password",
        FieldKind::default(),
        SecretString::from("pw"),
    )
    .unwrap();
    assert!(read_record(&vw, "site", "password").is_err());
}

#[tokio::test]
async fn missing_item_target_is_error() {
    let mut vw = VaultHandle::new_for_test("personal");
    let mut authenticator = Authenticator::new(
        AAGUID,
        PasskeyCredentialStore::new(&mut vw, PasskeyTarget::Item("gone".into())),
        PromptedUser,
    );
    assert!(
        authenticator
            .make_credential(registration("example.com", "ada"))
            .await
            .is_err()
    );
}
