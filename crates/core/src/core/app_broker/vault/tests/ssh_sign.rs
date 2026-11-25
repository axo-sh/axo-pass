use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as b64;
use ssh_key::{HashAlg, PrivateKey};

use super::super::super::ssh::{SignPurpose, vault_keys};
use super::super::SignSshKeyPayload;
use super::*;
use crate::secrets::vaults::ssh_keys::SshKeyRecord;

fn ed25519_key() -> PrivateKey {
    let data =
        include_str!("../../../../../../cli/src/cli/commands/ssh_agent/fixtures/b64_ed25519");
    PrivateKey::from_bytes(&b64.decode(data.trim()).unwrap()).unwrap()
}

fn rsa_key() -> PrivateKey {
    let data = include_str!("../../../../../../cli/src/cli/commands/ssh_agent/fixtures/b64_rsa");
    PrivateKey::from_bytes(&b64.decode(data.trim()).unwrap()).unwrap()
}

fn fingerprint_of(key: &PrivateKey) -> String {
    key.public_key().fingerprint(HashAlg::Sha256).to_string()
}

/// Store `key` as credential `key` of item `item` in vault `personal`.
fn add_key(fx: &Fixture, key: &PrivateKey) {
    let record = SshKeyRecord::new(key, "laptop").unwrap();
    fx.app_write("personal", |vw| {
        vw.add_item("item", "Item")?;
        vw.add_secret(
            "item",
            "key",
            "Key",
            FieldKind::SshKey,
            record.to_value().unwrap(),
        )
    });
}

fn sign_action(fingerprint: &str, purpose: Option<SignPurpose>) -> VaultAction {
    VaultAction::SignSshKey {
        item_key: "item".to_string(),
        credential_key: "key".to_string(),
        fingerprint: fingerprint.to_string(),
        comment: Some("laptop".to_string()),
        purpose,
        grant_candidate: None,
    }
}

fn sign_payload(cache_path: &Path) -> VaultPayload {
    VaultPayload::SignSshKey(SignSshKeyPayload {
        data: b"data".to_vec(),
        flags: 0,
        cache_path: cache_path.to_path_buf(),
    })
}

#[test]
fn signature_records_ssh_sign_with_credential_ids() {
    let _audit = test_dir();
    let fx = Fixture::new();
    let key = ed25519_key();
    add_key(&fx, &key);
    let cache = fx._dir.path().join("ssh-vault-keys.json");
    let purpose = SignPurpose::Login {
        user: Some("git".to_string()),
        host: Some("github.com".to_string()),
    };

    let event = fx.serve_recorded(
        true,
        "personal",
        sign_action(&fingerprint_of(&key), Some(purpose)),
        Some(sign_payload(&cache)),
    );

    assert_eq!(event.action, Action::SshSign);
    assert_eq!(event.outcome, Outcome::Succeeded);
    let ids = fx.read("personal").credential_ids("item", "key").unwrap();
    assert!(ids.credential_id.is_some());
    assert_eq!(recorded_ids(&event), ids);
    assert_eq!(event.detail["key_source"], "vault");
    assert_eq!(event.detail["algorithm"], "ssh-ed25519");
    assert_eq!(event.detail["user"], "git");
    assert_eq!(event.detail["host"], "github.com");
    assert_eq!(
        event.subject.as_ref().unwrap().fingerprint.as_deref(),
        Some(fingerprint_of(&key).as_str())
    );
}

#[test]
fn sshsig_signature_records_namespace() {
    let _audit = test_dir();
    let fx = Fixture::new();
    let key = ed25519_key();
    add_key(&fx, &key);
    let cache = fx._dir.path().join("ssh-vault-keys.json");
    let purpose = SignPurpose::Sshsig {
        namespace: "git".to_string(),
    };

    let event = fx.serve_recorded(
        true,
        "personal",
        sign_action(&fingerprint_of(&key), Some(purpose)),
        Some(sign_payload(&cache)),
    );

    assert_eq!(event.detail["namespace"], "git");
    assert!(!event.detail.contains_key("user"));
}

#[test]
fn declined_prompt_records_denied_signature_without_ids() {
    let _audit = test_dir();
    let fx = Fixture::new();
    let key = ed25519_key();
    add_key(&fx, &key);
    let cache = fx._dir.path().join("ssh-vault-keys.json");

    let event = fx.serve_recorded(
        false,
        "personal",
        sign_action(&fingerprint_of(&key), None),
        Some(sign_payload(&cache)),
    );

    assert_eq!(event.action, Action::SshSign);
    assert_eq!(event.outcome, Outcome::Denied);
    assert_eq!(recorded_ids(&event), SubjectIds::default());
}

#[test]
fn stale_cache_entry_refused_and_vault_entries_rewritten() {
    let _audit = test_dir();
    let fx = Fixture::new();
    let stored = ed25519_key();
    add_key(&fx, &stored);
    let cache = fx._dir.path().join("ssh-vault-keys.json");
    // The cache says the credential holds the RSA key.
    let stale_record = SshKeyRecord::new(&rsa_key(), "old").unwrap();
    let stale =
        vault_keys::VaultKeyEntry::from_record(&stale_record, "personal", "item", "key").unwrap();
    vault_keys::store(&cache, std::slice::from_ref(&stale)).unwrap();

    let event = fx.serve_recorded(
        true,
        "personal",
        sign_action(&stale.fingerprint, None),
        Some(sign_payload(&cache)),
    );

    assert_eq!(event.outcome, Outcome::Failed);
    let listed = vault_keys::load(&cache);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].fingerprint, fingerprint_of(&stored));
}

#[test]
fn key_with_ssh_use_off_refused_and_listing_rewritten() {
    let _audit = test_dir();
    let fx = Fixture::new();
    let key = ed25519_key();
    let mut record = SshKeyRecord::new(&key, "laptop").unwrap();
    // The cache still says SSH use is allowed.
    let stale = vault_keys::VaultKeyEntry::from_record(&record, "personal", "item", "key").unwrap();
    record.set_access(true, false);
    fx.app_write("personal", |vw| {
        vw.add_item("item", "Item")?;
        vw.add_secret(
            "item",
            "key",
            "Key",
            FieldKind::SshKey,
            record.to_value().unwrap(),
        )
    });
    let cache = fx._dir.path().join("ssh-vault-keys.json");
    vault_keys::store(&cache, std::slice::from_ref(&stale)).unwrap();

    let event = fx.serve_recorded(
        true,
        "personal",
        sign_action(&stale.fingerprint, None),
        Some(sign_payload(&cache)),
    );

    assert_eq!(event.outcome, Outcome::Failed);
    let listed = vault_keys::load(&cache);
    assert_eq!(listed.len(), 1);
    assert!(!listed[0].ssh_use);
    assert!(!listed[0].auto_load);
}
