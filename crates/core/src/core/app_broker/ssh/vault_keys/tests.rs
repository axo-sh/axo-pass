use std::os::unix::fs::PermissionsExt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as b64;
use secrecy::SecretString;
use ssh_key::PrivateKey;

use super::*;

fn ed25519_key() -> PrivateKey {
    let data =
        include_str!("../../../../../../cli/src/cli/commands/ssh_agent/fixtures/b64_ed25519");
    PrivateKey::from_bytes(&b64.decode(data.trim()).unwrap()).unwrap()
}

fn rsa_key() -> PrivateKey {
    let data = include_str!("../../../../../../cli/src/cli/commands/ssh_agent/fixtures/b64_rsa");
    PrivateKey::from_bytes(&b64.decode(data.trim()).unwrap()).unwrap()
}

fn entry(key: &PrivateKey, comment: &str, credential_key: &str) -> VaultKeyEntry {
    let record = SshKeyRecord::new(key, comment).unwrap();
    VaultKeyEntry::from_record(&record, "personal", "github", credential_key).unwrap()
}

fn cache_path(dir: &tempfile::TempDir) -> std::path::PathBuf {
    dir.path().join("ssh-vault-keys.json")
}

#[test]
fn entries_roundtrip_through_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = cache_path(&dir);
    let entries = vec![
        entry(&ed25519_key(), "laptop", "ed"),
        entry(&rsa_key(), "", "rsa"),
    ];

    store(&path, &entries).unwrap();

    let mut expected = entries;
    expected.sort_by(|a, b| a.credential_key.cmp(&b.credential_key));
    assert_eq!(load(&path), expected);
}

#[test]
fn store_writes_owner_only_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = cache_path(&dir);
    fs::write(&path, "{}").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

    store(&path, &[entry(&ed25519_key(), "", "ed")]).unwrap();

    let mode = fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn store_creates_missing_directory() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested").join("ssh-vault-keys.json");

    store(&path, &[]).unwrap();

    assert!(load(&path).is_empty());
    assert!(path.exists());
}

#[test]
fn store_leaves_no_temp_file() {
    let dir = tempfile::tempdir().unwrap();
    store(&cache_path(&dir), &[entry(&ed25519_key(), "", "ed")]).unwrap();

    let names: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, vec![std::ffi::OsString::from("ssh-vault-keys.json")]);
}

#[test]
fn store_skips_write_of_same_entries() {
    let dir = tempfile::tempdir().unwrap();
    let path = cache_path(&dir);
    let entries = [entry(&ed25519_key(), "", "ed")];
    store(&path, &entries).unwrap();
    // A write replaces the file and sets mode 0600, so a changed mode shows
    // a write.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();

    store(&path, &entries).unwrap();

    let mode = fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o640);
}

#[test]
fn store_replaces_changed_entries() {
    let dir = tempfile::tempdir().unwrap();
    let path = cache_path(&dir);
    store(&path, &[entry(&ed25519_key(), "", "ed")]).unwrap();

    let replacement = entry(&rsa_key(), "", "rsa");
    store(&path, std::slice::from_ref(&replacement)).unwrap();

    assert_eq!(load(&path), vec![replacement]);
}

#[test]
fn refresh_replaces_unlocked_keeps_locked_and_drops_removed() {
    let dir = tempfile::tempdir().unwrap();
    let path = cache_path(&dir);
    let mut work = entry(&rsa_key(), "", "rsa");
    work.vault_key = "work".to_string();
    let mut gone = entry(&rsa_key(), "", "rsa2");
    gone.vault_key = "removed".to_string();
    store(
        &path,
        &[entry(&ed25519_key(), "", "ed"), work.clone(), gone],
    )
    .unwrap();
    let known = [
        "personal".to_string(),
        "work".to_string(),
        "new".to_string(),
    ];
    let added = entry(&ed25519_key(), "new", "ed2");

    // "personal" unlocked and now holds a different key. "work" stayed locked.
    refresh(
        &path,
        &known,
        vec![("personal".to_string(), vec![added.clone()])],
    )
    .unwrap();

    assert_eq!(load(&path), vec![added, work]);
}

#[test]
fn refresh_with_nothing_unlocked_keeps_known_vaults() {
    let dir = tempfile::tempdir().unwrap();
    let path = cache_path(&dir);
    let kept = entry(&ed25519_key(), "", "ed");
    store(&path, std::slice::from_ref(&kept)).unwrap();

    refresh(&path, &["personal".to_string()], Vec::new()).unwrap();

    assert_eq!(load(&path), vec![kept]);
}

#[test]
fn refresh_writes_listing_when_file_missing() {
    let dir = tempfile::tempdir().unwrap();
    let path = cache_path(&dir);
    let added = entry(&ed25519_key(), "", "ed");

    refresh(
        &path,
        &["personal".to_string()],
        vec![("personal".to_string(), vec![added.clone()])],
    )
    .unwrap();

    assert_eq!(load(&path), vec![added]);
}

#[test]
fn replace_vault_keeps_other_vaults() {
    let dir = tempfile::tempdir().unwrap();
    let path = cache_path(&dir);
    let mut other = entry(&rsa_key(), "", "rsa");
    other.vault_key = "work".to_string();
    store(&path, &[entry(&ed25519_key(), "", "ed"), other.clone()]).unwrap();

    replace_vault(&path, "personal", Vec::new()).unwrap();
    assert_eq!(load(&path), vec![other.clone()]);

    let added = entry(&ed25519_key(), "new", "ed2");
    replace_vault(&path, "personal", vec![added.clone()]).unwrap();
    assert_eq!(load(&path), vec![added, other]);
}

#[test]
fn replace_vault_recovers_from_corrupt_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = cache_path(&dir);
    fs::write(&path, "not json").unwrap();
    let added = entry(&ed25519_key(), "", "ed");

    replace_vault(&path, "personal", vec![added.clone()]).unwrap();

    assert_eq!(load(&path), vec![added]);
}

#[test]
fn missing_file_lists_no_keys() {
    let dir = tempfile::tempdir().unwrap();

    assert!(load(&cache_path(&dir)).is_empty());
}

#[test]
fn corrupt_file_lists_no_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = cache_path(&dir);
    for contents in [
        "",
        "not json",
        "[]",
        r#"{"version":1}"#,
        r#"{"version":1,"keys":[{"fingerprint":"x"}]}"#,
    ] {
        fs::write(&path, contents).unwrap();
        assert!(load(&path).is_empty(), "{contents}");
    }
}

#[test]
fn unreadable_file_lists_no_keys() {
    let dir = tempfile::tempdir().unwrap();
    // A directory at the path fails the read with an error other than not found.
    let path = dir.path().join("ssh-vault-keys.json");
    fs::create_dir(&path).unwrap();

    assert!(load(&path).is_empty());
}

#[test]
fn unknown_version_lists_no_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = cache_path(&dir);
    store(&path, &[entry(&ed25519_key(), "", "ed")]).unwrap();
    let text = fs::read_to_string(&path).unwrap().replace(
        &format!(r#""version": {FORMAT_VERSION}"#),
        r#""version": 99"#,
    );
    fs::write(&path, text).unwrap();

    assert!(load(&path).is_empty());
}

#[test]
fn entry_carries_fingerprint_comment_and_location() {
    let key = ed25519_key();
    let found = entry(&key, "laptop", "ed");

    assert_eq!(
        found.fingerprint,
        key.public_key().fingerprint(HashAlg::Sha256).to_string()
    );
    assert!(found.fingerprint.starts_with("SHA256:"));
    assert!(found.public_key.ends_with(" laptop"));
    assert_eq!(found.comment, "laptop");
    assert_eq!(
        (&*found.vault_key, &*found.item_key, &*found.credential_key),
        ("personal", "github", "ed")
    );
    assert_eq!(found.policy, KeyPolicy::Default);
}

#[test]
fn entry_refused_for_invalid_public_key() {
    let mut record = SshKeyRecord::new(&ed25519_key(), "").unwrap();
    record.public_key = "not a key".to_string();

    assert!(VaultKeyEntry::from_record(&record, "v", "i", "c").is_err());
}

#[test]
fn collect_lists_ssh_key_credentials_only() {
    let mut vault = VaultHandle::new_for_test("personal");
    vault.add_item("github", "GitHub").unwrap();
    let record = SshKeyRecord::new(&ed25519_key(), "laptop").unwrap();
    vault
        .add_new_secret(
            "github",
            "key",
            "Key",
            FieldKind::SshKey,
            record.to_value().unwrap(),
        )
        .unwrap();
    vault
        .add_new_secret(
            "github",
            "token",
            "Token",
            FieldKind::default(),
            SecretString::from("hunter2"),
        )
        .unwrap();

    let found = collect("personal", &vault);

    assert_eq!(found, vec![entry(&ed25519_key(), "laptop", "key")]);
}

#[test]
fn collect_skips_unreadable_ssh_key_values() {
    let mut vault = VaultHandle::new_for_test("personal");
    vault.add_item("github", "GitHub").unwrap();
    vault
        .add_new_secret(
            "github",
            "broken",
            "Broken",
            FieldKind::SshKey,
            SecretString::from("not a record"),
        )
        .unwrap();
    let mut mismatched = SshKeyRecord::new(&ed25519_key(), "").unwrap();
    mismatched.public_key = rsa_key().public_key().to_openssh().unwrap();
    vault
        .add_new_secret(
            "github",
            "mismatched",
            "Mismatched",
            FieldKind::SshKey,
            mismatched.to_value().unwrap(),
        )
        .unwrap();

    assert!(collect("personal", &vault).is_empty());
}
