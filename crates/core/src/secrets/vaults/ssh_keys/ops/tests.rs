use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as b64;
use ssh_key::{HashAlg, LineEnding};

use super::*;
use crate::secrets::keychain::managed_key::KeyPolicy;

fn fixture(data: &str) -> PrivateKey {
    PrivateKey::from_bytes(&b64.decode(data.trim()).unwrap()).unwrap()
}

fn ed25519_key() -> PrivateKey {
    fixture(include_str!(
        "../../../../../../cli/src/cli/commands/ssh_agent/fixtures/b64_ed25519"
    ))
}

fn rsa_key() -> PrivateKey {
    fixture(include_str!(
        "../../../../../../cli/src/cli/commands/ssh_agent/fixtures/b64_rsa"
    ))
}

fn openssh(key: &PrivateKey) -> String {
    key.to_openssh(LineEnding::LF).unwrap().to_string()
}

fn encrypted_openssh(key: &PrivateKey, passphrase: &str) -> String {
    let encrypted = key.encrypt(&mut OsRng, passphrase).unwrap();
    assert!(encrypted.is_encrypted());
    openssh(&encrypted)
}

fn fingerprint_of(key: &PrivateKey) -> String {
    key.public_key().fingerprint(HashAlg::Sha256).to_string()
}

fn new_item(title: &str) -> KeyTarget<'_> {
    KeyTarget::NewItem { title }
}

fn secret(text: &str) -> SecretString {
    SecretString::from(text.to_string())
}

fn record_of(vw: &VaultHandle, added: &AddedKey) -> SshKeyRecord {
    let value = vw
        .get_secret(&added.item_key, &added.credential_key)
        .unwrap()
        .unwrap();
    SshKeyRecord::from_value(value.expose_secret()).unwrap()
}

fn item_count(vw: &VaultHandle) -> usize {
    vw.list_items().unwrap().len()
}

#[test]
fn generate_creates_ed25519_key_in_new_item() {
    let mut vw = VaultHandle::new_for_test("personal");

    let added = generate(&mut vw, new_item("Deploy key"), "deploy@laptop").unwrap();

    assert_eq!(added.item_key, "deploy-key");
    assert_eq!(added.credential_key, "ssh-key");
    let item = vw.get_item_overview("deploy-key").unwrap().unwrap();
    assert_eq!(item.title, "Deploy key");
    assert_eq!(item.category.as_deref(), Some(CATEGORY_SSH_KEY));
    let credential = vw
        .get_secret_overview("deploy-key", "ssh-key")
        .unwrap()
        .unwrap();
    assert_eq!(credential.kind, FieldKind::SshKey);
    assert_eq!(credential.id, added.credential_id);

    let record = record_of(&vw, &added);
    assert_eq!(record.policy, KeyPolicy::Default);
    assert_eq!(record.comment, "deploy@laptop");
    assert!(record.public_key.starts_with("ssh-ed25519 "));
    assert!(record.public_key.ends_with(" deploy@laptop"));
    assert_eq!(record.public_key, added.public_key);
    assert_eq!(record.fingerprint().unwrap(), added.fingerprint);
    assert_eq!(
        record.private_key().unwrap().algorithm(),
        Algorithm::Ed25519
    );
}

#[test]
fn generate_makes_distinct_keys() {
    let mut vw = VaultHandle::new_for_test("personal");

    let first = generate(&mut vw, new_item("One"), "").unwrap();
    let second = generate(&mut vw, new_item("Two"), "").unwrap();

    assert_ne!(first.fingerprint, second.fingerprint);
}

#[test]
fn generate_into_existing_item_leaves_item_alone() {
    let mut vw = VaultHandle::new_for_test("personal");
    vw.add_item("server", "Server").unwrap();
    vw.add_secret(
        "server",
        "password",
        "Password",
        FieldKind::default(),
        secret("hunter2"),
    )
    .unwrap();

    let first = generate(&mut vw, KeyTarget::ExistingItem { item_key: "server" }, "a").unwrap();
    let second = generate(&mut vw, KeyTarget::ExistingItem { item_key: "server" }, "b").unwrap();

    assert_eq!(first.credential_key, "ssh-key");
    assert_eq!(second.credential_key, "ssh-key-2");
    assert_eq!(item_count(&vw), 1);
    let item = vw.get_item_overview("server").unwrap().unwrap();
    assert_eq!(item.title, "Server");
    assert_eq!(item.category, None);
    let password = vw.get_secret("server", "password").unwrap().unwrap();
    assert_eq!(password.expose_secret(), "hunter2");
}

#[test]
fn generate_into_missing_item_refused() {
    let mut vw = VaultHandle::new_for_test("personal");

    let err = generate(&mut vw, KeyTarget::ExistingItem { item_key: "nope" }, "").unwrap_err();

    assert!(
        matches!(err, SshKeyError::Vault(VaultError::InvalidItemKey(_))),
        "{err}"
    );
    assert_eq!(item_count(&vw), 0);
}

#[test]
fn new_item_key_from_title_with_suffix_if_taken() {
    let mut vw = VaultHandle::new_for_test("personal");

    let first = generate(&mut vw, new_item("Build server"), "").unwrap();
    let second = generate(&mut vw, new_item("Build server"), "").unwrap();
    let untitled = generate(&mut vw, new_item("  "), "").unwrap();
    let odd = generate(&mut vw, new_item("!!"), "").unwrap();

    assert_eq!(first.item_key, "build-server");
    assert_eq!(second.item_key, "build-server-2");
    assert_eq!(untitled.item_key, "ssh-key");
    assert_eq!(odd.item_key, "ssh-key-2");
    let untitled_item = vw.get_item_overview("ssh-key").unwrap().unwrap();
    assert_eq!(untitled_item.title, "SSH key");
}

#[test]
fn import_plain_keys_of_each_type() {
    for key in [ed25519_key(), rsa_key()] {
        let mut vw = VaultHandle::new_for_test("personal");

        let added = import(&mut vw, new_item("Imported"), &openssh(&key), None, None).unwrap();

        assert_eq!(added.fingerprint, fingerprint_of(&key));
        let record = record_of(&vw, &added);
        assert_eq!(record.policy, KeyPolicy::Default);
        assert_eq!(
            record.private_key().unwrap().public_key().key_data(),
            key.public_key().key_data()
        );
    }
}

#[test]
fn import_comment_from_caller_or_key() {
    let mut key = ed25519_key();
    key.set_comment("from-key");
    let mut vw = VaultHandle::new_for_test("personal");

    let kept = import(&mut vw, new_item("A"), &openssh(&key), None, None).unwrap();
    let mut other = rsa_key();
    other.set_comment("from-key");
    let replaced = import(
        &mut vw,
        new_item("B"),
        &openssh(&other),
        None,
        Some("given"),
    )
    .unwrap();

    assert_eq!(record_of(&vw, &kept).comment, "from-key");
    assert!(kept.public_key.ends_with(" from-key"));
    assert_eq!(record_of(&vw, &replaced).comment, "given");
    assert!(replaced.public_key.ends_with(" given"));
}

#[test]
fn import_encrypted_key_stored_unencrypted() {
    let key = ed25519_key();
    let text = encrypted_openssh(&key, "correct horse");
    let mut vw = VaultHandle::new_for_test("personal");

    let added = import(
        &mut vw,
        new_item("Encrypted"),
        &text,
        Some(&secret("correct horse")),
        None,
    )
    .unwrap();

    assert_eq!(added.fingerprint, fingerprint_of(&key));
    let record = record_of(&vw, &added);
    let stored = PrivateKey::from_openssh(&record.private_key).unwrap();
    assert!(!stored.is_encrypted());
    assert_eq!(stored.key_data(), key.key_data());
}

#[test]
fn import_encrypted_key_with_wrong_passphrase_refused() {
    let text = encrypted_openssh(&ed25519_key(), "correct horse");
    let mut vw = VaultHandle::new_for_test("personal");

    let err = import(
        &mut vw,
        new_item("Encrypted"),
        &text,
        Some(&secret("battery staple")),
        None,
    )
    .unwrap_err();

    assert!(matches!(err, SshKeyError::WrongPassphrase), "{err}");
    assert_eq!(item_count(&vw), 0);
}

#[test]
fn import_encrypted_key_without_passphrase_refused() {
    let text = encrypted_openssh(&ed25519_key(), "correct horse");
    let mut vw = VaultHandle::new_for_test("personal");

    let missing = import(&mut vw, new_item("Encrypted"), &text, None, None).unwrap_err();
    let empty = import(
        &mut vw,
        new_item("Encrypted"),
        &text,
        Some(&secret("")),
        None,
    )
    .unwrap_err();

    assert!(
        matches!(missing, SshKeyError::PassphraseRequired),
        "{missing}"
    );
    assert!(matches!(empty, SshKeyError::PassphraseRequired), "{empty}");
    assert_eq!(item_count(&vw), 0);
}

#[test]
fn import_malformed_text_refused() {
    let valid = openssh(&ed25519_key());
    let truncated = &valid[..valid.len() / 2];
    let legacy = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END RSA PRIVATE KEY-----\n";
    let public_only = ed25519_key().public_key().to_openssh().unwrap();

    for text in ["", "not a key", truncated, legacy, public_only.as_str()] {
        let mut vw = VaultHandle::new_for_test("personal");

        let err = import(&mut vw, new_item("Bad"), text, None, None).unwrap_err();

        assert!(
            matches!(err, SshKeyError::InvalidPrivateKey(_)),
            "{text}: {err}"
        );
        assert_eq!(item_count(&vw), 0, "{text}");
    }
}

#[test]
fn duplicate_fingerprint_in_vault_refused() {
    let key = ed25519_key();
    let mut vw = VaultHandle::new_for_test("personal");
    let first = import(&mut vw, new_item("First"), &openssh(&key), None, None).unwrap();
    vw.add_item("other", "Other").unwrap();

    let same_item = import(
        &mut vw,
        KeyTarget::ExistingItem {
            item_key: &first.item_key,
        },
        &openssh(&key),
        None,
        None,
    )
    .unwrap_err();
    let other_item = import(
        &mut vw,
        KeyTarget::ExistingItem { item_key: "other" },
        &openssh(&key),
        None,
        None,
    )
    .unwrap_err();
    let new_item_err = import(&mut vw, new_item("Third"), &openssh(&key), None, None).unwrap_err();

    for err in [same_item, other_item, new_item_err] {
        assert!(
            matches!(&err, SshKeyError::Duplicate { fingerprint } if *fingerprint == first.fingerprint),
            "{err}"
        );
    }
    assert_eq!(item_count(&vw), 2);
    let other = vw.get_item_overview("other").unwrap().unwrap();
    assert!(other.credentials.is_empty());
}

#[test]
fn duplicate_refused_for_encrypted_import_of_stored_key() {
    let key = ed25519_key();
    let mut vw = VaultHandle::new_for_test("personal");
    import(&mut vw, new_item("First"), &openssh(&key), None, None).unwrap();

    let err = import(
        &mut vw,
        new_item("Second"),
        &encrypted_openssh(&key, "pw"),
        Some(&secret("pw")),
        None,
    )
    .unwrap_err();

    assert!(matches!(err, SshKeyError::Duplicate { .. }), "{err}");
}

#[test]
fn same_key_allowed_in_another_vault() {
    let key = ed25519_key();
    let mut personal = VaultHandle::new_for_test("personal");
    let mut work = VaultHandle::new_for_test("work");

    import(&mut personal, new_item("Key"), &openssh(&key), None, None).unwrap();
    let added = import(&mut work, new_item("Key"), &openssh(&key), None, None).unwrap();

    assert_eq!(added.fingerprint, fingerprint_of(&key));
}

#[test]
fn generated_key_reimport_refused_as_duplicate() {
    let mut vw = VaultHandle::new_for_test("personal");
    let added = generate(&mut vw, new_item("Key"), "c").unwrap();
    let text = record_of(&vw, &added).private_key.clone();

    let err = import(&mut vw, new_item("Again"), &text, None, None).unwrap_err();

    assert!(matches!(err, SshKeyError::Duplicate { .. }), "{err}");
}

#[test]
fn set_comment_updates_record_and_public_key() {
    let mut vw = VaultHandle::new_for_test("personal");
    let added = generate(&mut vw, new_item("Key"), "old").unwrap();

    let line = set_comment(&mut vw, &added.item_key, &added.credential_key, "new").unwrap();

    assert!(line.ends_with(" new"));
    let record = record_of(&vw, &added);
    assert_eq!(record.comment, "new");
    assert_eq!(record.public_key, line);
    assert_eq!(record.fingerprint().unwrap(), added.fingerprint);
    record.private_key().unwrap();
    assert_eq!(
        public_key_line(&vw, &added.item_key, &added.credential_key).unwrap(),
        line
    );
}

#[test]
fn set_comment_refused_for_other_credential() {
    let mut vw = VaultHandle::new_for_test("personal");
    vw.add_item("login", "Login").unwrap();
    vw.add_secret(
        "login",
        "password",
        "Password",
        FieldKind::default(),
        secret("hunter2"),
    )
    .unwrap();

    let err = set_comment(&mut vw, "login", "password", "x").unwrap_err();
    let missing = public_key_line(&vw, "login", "none").unwrap_err();

    assert!(matches!(err, SshKeyError::NotSshKey(_)), "{err}");
    assert!(
        matches!(
            missing,
            SshKeyError::Vault(VaultError::InvalidCredentialKey(_))
        ),
        "{missing}"
    );
}

#[test]
fn export_returns_plain_key_with_record_comment() {
    let mut key = ed25519_key();
    key.set_comment("from-key");
    let mut vw = VaultHandle::new_for_test("personal");
    let added = import(&mut vw, new_item("Key"), &openssh(&key), None, None).unwrap();
    set_comment(&mut vw, &added.item_key, &added.credential_key, "renamed").unwrap();

    let text = export_private_key(&vw, &added.item_key, &added.credential_key, None).unwrap();

    let exported = PrivateKey::from_openssh(text.as_str()).unwrap();
    assert!(!exported.is_encrypted());
    assert_eq!(exported.key_data(), key.key_data());
    assert_eq!(exported.comment(), "renamed");
}

#[test]
fn export_with_passphrase_encrypts_key() {
    let key = ed25519_key();
    let mut vw = VaultHandle::new_for_test("personal");
    let added = import(&mut vw, new_item("Key"), &openssh(&key), None, None).unwrap();

    let text = export_private_key(
        &vw,
        &added.item_key,
        &added.credential_key,
        Some(&secret("pw")),
    )
    .unwrap();
    let empty = export_private_key(
        &vw,
        &added.item_key,
        &added.credential_key,
        Some(&secret("")),
    )
    .unwrap();

    let exported = PrivateKey::from_openssh(text.as_str()).unwrap();
    assert!(exported.is_encrypted());
    assert_eq!(exported.decrypt("pw").unwrap().key_data(), key.key_data());
    assert!(
        !PrivateKey::from_openssh(empty.as_str())
            .unwrap()
            .is_encrypted()
    );
}

#[test]
fn export_refused_for_other_credential() {
    let mut vw = VaultHandle::new_for_test("personal");
    vw.add_item("login", "Login").unwrap();
    vw.add_secret(
        "login",
        "password",
        "Password",
        FieldKind::default(),
        secret("hunter2"),
    )
    .unwrap();

    let err = export_private_key(&vw, "login", "password", None).unwrap_err();

    assert!(matches!(err, SshKeyError::NotSshKey(_)), "{err}");
}
