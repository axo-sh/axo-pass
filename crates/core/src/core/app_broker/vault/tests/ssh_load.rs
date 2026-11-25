use ssh_key::{HashAlg, PrivateKey};

use super::super::super::ssh::{SignPurpose, vault_keys};
use super::super::LoadSshKeyPayload;
use super::*;
use crate::core::app_broker::wire::b64_decode_raw;
use crate::secrets::vaults::ssh_keys::SshKeyRecord;

fn ed25519_key() -> PrivateKey {
    let data =
        include_str!("../../../../../../cli/src/cli/commands/ssh_agent/fixtures/b64_ed25519");
    PrivateKey::from_bytes(&base64_no_pad(data.trim())).unwrap()
}

fn rsa_key() -> PrivateKey {
    let data = include_str!("../../../../../../cli/src/cli/commands/ssh_agent/fixtures/b64_rsa");
    PrivateKey::from_bytes(&base64_no_pad(data.trim())).unwrap()
}

fn base64_no_pad(text: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(text)
        .unwrap()
}

fn fingerprint_of(key: &PrivateKey) -> String {
    key.public_key().fingerprint(HashAlg::Sha256).to_string()
}

/// Store the key of `record` as credential `key` of item `item` in vault
/// `personal`.
fn add_record(fx: &Fixture, record: &SshKeyRecord) {
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

fn add_key(fx: &Fixture, key: &PrivateKey) {
    add_record(fx, &SshKeyRecord::new(key, "laptop").unwrap());
}

fn cache_path(fx: &Fixture) -> PathBuf {
    fx._dir.path().join("ssh-vault-keys.json")
}

fn load_action(fingerprint: &str, purpose: Option<SignPurpose>) -> VaultAction {
    VaultAction::LoadSshKey {
        item_key: "item".to_string(),
        credential_key: "key".to_string(),
        fingerprint: fingerprint.to_string(),
        comment: Some("laptop".to_string()),
        purpose,
        grant_candidate: None,
    }
}

fn load_payload(cache_path: &Path) -> VaultPayload {
    VaultPayload::LoadSshKey(LoadSshKeyPayload {
        cache_path: cache_path.to_path_buf(),
    })
}

/// Base64 text of the key in a load response.
fn returned_key_text(served: Served) -> String {
    let WireResponse::VaultKey { private_key } = served.response else {
        panic!("expected a key response");
    };
    private_key.to_string()
}

#[test]
fn load_returns_key_with_requested_fingerprint() {
    let fx = Fixture::new();
    let key = ed25519_key();
    add_key(&fx, &key);
    let cache = cache_path(&fx);

    let served = fx
        .serve(
            "personal",
            load_action(&fingerprint_of(&key), None),
            Some(load_payload(&cache)),
        )
        .unwrap();

    let text = b64_decode_raw(returned_key_text(served)).unwrap();
    let returned = PrivateKey::from_openssh(&text).unwrap();
    assert!(!returned.is_encrypted());
    assert_eq!(fingerprint_of(&returned), fingerprint_of(&key));
}

#[test]
fn load_records_credential_read_with_ids() {
    let _audit = test_dir();
    let fx = Fixture::new();
    let key = ed25519_key();
    add_key(&fx, &key);
    let cache = cache_path(&fx);
    let purpose = SignPurpose::Login {
        user: Some("git".to_string()),
        host: Some("github.com".to_string()),
    };

    let event = fx.serve_recorded(
        true,
        "personal",
        load_action(&fingerprint_of(&key), Some(purpose)),
        Some(load_payload(&cache)),
    );

    assert_eq!(event.action, Action::CredentialRead);
    assert_eq!(event.outcome, Outcome::Succeeded);
    let ids = fx.read("personal").credential_ids("item", "key").unwrap();
    assert!(ids.credential_id.is_some());
    assert_eq!(recorded_ids(&event), ids);
    assert_eq!(event.detail["vault"], "personal");
    assert_eq!(event.detail["key_source"], "vault");
    assert_eq!(event.detail["agent_load"], "true");
    assert_eq!(event.detail["host"], "github.com");
    assert_eq!(event.subject.as_ref().unwrap().id, "personal/item/key");
}

#[test]
fn load_event_does_not_hold_key() {
    let _audit = test_dir();
    let fx = Fixture::new();
    let key = ed25519_key();
    add_key(&fx, &key);
    let cache = cache_path(&fx);
    let action = load_action(&fingerprint_of(&key), None);
    let served = fx
        .serve("personal", action.clone(), Some(load_payload(&cache)))
        .unwrap();
    let text = returned_key_text(served);

    let event = fx.serve_recorded(true, "personal", action, Some(load_payload(&cache)));

    let recorded = serde_json::to_string(&event).unwrap();
    assert!(!recorded.contains(&text));
    assert!(!recorded.contains("PRIVATE KEY"));
}

#[test]
fn declined_load_records_denied_read_without_ids() {
    let _audit = test_dir();
    let fx = Fixture::new();
    let key = ed25519_key();
    add_key(&fx, &key);
    let cache = cache_path(&fx);

    let event = fx.serve_recorded(
        false,
        "personal",
        load_action(&fingerprint_of(&key), None),
        Some(load_payload(&cache)),
    );

    assert_eq!(event.action, Action::CredentialRead);
    assert_eq!(event.outcome, Outcome::Denied);
    assert_eq!(recorded_ids(&event), SubjectIds::default());
}

#[test]
fn load_without_payload_refused() {
    let fx = Fixture::new();
    let key = ed25519_key();
    add_key(&fx, &key);

    let result = fx.serve("personal", load_action(&fingerprint_of(&key), None), None);

    assert!(result.is_err());
}

#[test]
fn load_of_other_fingerprint_refused_and_listing_rewritten() {
    let fx = Fixture::new();
    let stored = ed25519_key();
    add_key(&fx, &stored);
    let cache = cache_path(&fx);
    // The cache says the credential holds the RSA key.
    let stale_record = SshKeyRecord::new(&rsa_key(), "old").unwrap();
    let stale =
        vault_keys::VaultKeyEntry::from_record(&stale_record, "personal", "item", "key").unwrap();
    vault_keys::store(&cache, std::slice::from_ref(&stale)).unwrap();

    let result = fx.serve(
        "personal",
        load_action(&stale.fingerprint, None),
        Some(load_payload(&cache)),
    );

    assert!(result.is_err());
    let listed = vault_keys::load(&cache);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].fingerprint, fingerprint_of(&stored));
}

#[test]
fn load_of_non_ssh_credential_refused() {
    let fx = Fixture::new();
    fx.app_add("personal", "key", "not a key");
    let cache = cache_path(&fx);

    let result = fx.serve(
        "personal",
        load_action(&fingerprint_of(&ed25519_key()), None),
        Some(load_payload(&cache)),
    );

    let Err(message) = result else {
        panic!("expected the load to be refused");
    };
    assert!(message.contains("not an SSH key"), "{message}");
}

#[test]
fn load_of_key_with_auto_load_off_refused_and_listing_rewritten() {
    let fx = Fixture::new();
    let key = ed25519_key();
    let mut record = SshKeyRecord::new(&key, "laptop").unwrap();
    // The cache still says auto-load is allowed.
    let stale = vault_keys::VaultKeyEntry::from_record(&record, "personal", "item", "key").unwrap();
    record.set_access(false, true);
    add_record(&fx, &record);
    let cache = cache_path(&fx);
    vault_keys::store(&cache, std::slice::from_ref(&stale)).unwrap();

    let result = fx.serve(
        "personal",
        load_action(&stale.fingerprint, None),
        Some(load_payload(&cache)),
    );

    assert!(result.is_err());
    let listed = vault_keys::load(&cache);
    assert_eq!(listed.len(), 1);
    assert!(listed[0].ssh_use);
    assert!(!listed[0].auto_load);
}

#[test]
fn load_of_key_with_ssh_use_off_refused_and_listing_rewritten() {
    let fx = Fixture::new();
    let key = ed25519_key();
    let mut record = SshKeyRecord::new(&key, "laptop").unwrap();
    // The cache still says SSH use is allowed.
    let stale = vault_keys::VaultKeyEntry::from_record(&record, "personal", "item", "key").unwrap();
    record.set_access(true, false);
    add_record(&fx, &record);
    let cache = cache_path(&fx);
    vault_keys::store(&cache, std::slice::from_ref(&stale)).unwrap();

    let result = fx.serve(
        "personal",
        load_action(&stale.fingerprint, None),
        Some(load_payload(&cache)),
    );

    assert!(result.is_err());
    let listed = vault_keys::load(&cache);
    assert_eq!(listed.len(), 1);
    assert!(!listed[0].ssh_use);
}
