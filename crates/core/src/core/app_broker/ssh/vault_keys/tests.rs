use std::os::unix::fs::PermissionsExt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as b64;
use secrecy::SecretString;
use ssh_key::PrivateKey;

use super::*;
use crate::secrets::vaults::CredentialUpdate;
use crate::secrets::vaults::ssh_keys::ops;

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

    let credential_id = vault
        .get_secret_overview("github", "key")
        .unwrap()
        .map(|credential| credential.id);
    assert!(credential_id.is_some());
    let expected = VaultKeyEntry {
        credential_id,
        ..entry(&ed25519_key(), "laptop", "key")
    };
    assert_eq!(found, vec![expected]);
}

#[test]
fn credential_id_roundtrips_and_is_optional_in_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = cache_path(&dir);
    let with_id = VaultKeyEntry {
        credential_id: Some(Uuid::from_u128(7)),
        ..entry(&ed25519_key(), "a", "ed")
    };
    let without_id = entry(&rsa_key(), "b", "rsa");

    store(&path, &[with_id.clone(), without_id.clone()]).unwrap();

    let text = fs::read_to_string(&path).unwrap();
    assert_eq!(text.matches("credential_id").count(), 1);
    assert_eq!(load(&path), vec![with_id, without_id]);
}

fn added_key(vault: &mut VaultHandle, title: &str) -> ops::AddedKey {
    ops::generate(vault, ops::KeyTarget::NewItem { title }, title).unwrap()
}

#[test]
fn sync_vault_lists_new_key_and_keeps_other_vaults() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path().join("ssh");
    let path = cache_path(&dir);
    let other = VaultKeyEntry {
        vault_key: "work".to_string(),
        ..entry(&rsa_key(), "", "rsa")
    };
    store(&path, std::slice::from_ref(&other)).unwrap();
    let mut vault = VaultHandle::new_for_test("personal");
    let added = added_key(&mut vault, "Deploy");

    let mut written = sync_vault(&path, &ssh_dir, "personal", &vault).unwrap();

    let listed = load(&path);
    written.sort_by(|a, b| a.vault_key.cmp(&b.vault_key));
    assert_eq!(listed, written);
    assert_eq!(listed.len(), 2);
    let mine = listed.iter().find(|e| e.vault_key == "personal").unwrap();
    assert_eq!(mine.fingerprint, added.fingerprint);
    assert_eq!(mine.credential_id, Some(added.credential_id));
    assert!(listed.contains(&other));
}

#[test]
fn sync_vault_drops_removed_key_and_deletes_its_public_file() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path().join("ssh");
    let path = cache_path(&dir);
    let mut vault = VaultHandle::new_for_test("personal");
    let kept = added_key(&mut vault, "Kept");
    let removed = added_key(&mut vault, "Removed");
    sync_vault(&path, &ssh_dir, "personal", &vault).unwrap();
    for added in [&kept, &removed] {
        vault_pubkeys::write(&ssh_dir, added.credential_id, &added.public_key).unwrap();
    }

    vault.delete_item(&removed.item_key).unwrap();
    sync_vault(&path, &ssh_dir, "personal", &vault).unwrap();

    let listed = load(&path);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].credential_id, Some(kept.credential_id));
    assert!(vault_pubkeys::path_for(&ssh_dir, kept.credential_id).exists());
    assert!(!vault_pubkeys::path_for(&ssh_dir, removed.credential_id).exists());
}

#[test]
fn sync_vault_keeps_public_file_across_rename() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path().join("ssh");
    let path = cache_path(&dir);
    let mut vault = VaultHandle::new_for_test("personal");
    let added = added_key(&mut vault, "Deploy");
    sync_vault(&path, &ssh_dir, "personal", &vault).unwrap();
    let file = vault_pubkeys::write(&ssh_dir, added.credential_id, &added.public_key).unwrap();

    vault
        .update_credential(
            &added.item_key,
            &added.credential_key,
            CredentialUpdate {
                key: Some("renamed".to_string()),
                title: None,
                kind: None,
            },
        )
        .unwrap();
    sync_vault(&path, &ssh_dir, "personal", &vault).unwrap();

    let listed = load(&path);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].credential_key, "renamed");
    assert_eq!(listed[0].credential_id, Some(added.credential_id));
    assert!(file.exists());
}

#[test]
fn refresh_returns_written_entries_and_sweep_keeps_locked_vault_files() {
    let dir = tempfile::tempdir().unwrap();
    let ssh_dir = dir.path().join("ssh");
    let path = cache_path(&dir);
    let mut locked = VaultHandle::new_for_test("locked");
    let mut open = VaultHandle::new_for_test("open");
    let locked_key = added_key(&mut locked, "Locked");
    let open_key = added_key(&mut open, "Open");
    let known = ["locked".to_string(), "open".to_string()];
    refresh(
        &path,
        &known,
        vec![
            ("locked".to_string(), collect("locked", &locked)),
            ("open".to_string(), collect("open", &open)),
        ],
    )
    .unwrap();
    for added in [&locked_key, &open_key] {
        vault_pubkeys::write(&ssh_dir, added.credential_id, &added.public_key).unwrap();
    }

    let written = refresh(
        &path,
        &known,
        vec![("open".to_string(), collect("open", &open))],
    )
    .unwrap();
    sweep_pubkey_files(&ssh_dir, &written).unwrap();

    assert_eq!(written.len(), 2);
    assert!(vault_pubkeys::path_for(&ssh_dir, locked_key.credential_id).exists());
    assert!(vault_pubkeys::path_for(&ssh_dir, open_key.credential_id).exists());
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
