use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as b64;
use secrecy::ExposeSecret;
use serde_json::json;

use super::*;

fn fixture(data: &str) -> PrivateKey {
    PrivateKey::from_bytes(&b64.decode(data.trim()).unwrap()).unwrap()
}

fn ed25519_key() -> PrivateKey {
    fixture(include_str!(
        "../../../../../cli/src/cli/commands/ssh_agent/fixtures/b64_ed25519"
    ))
}

fn rsa_key() -> PrivateKey {
    fixture(include_str!(
        "../../../../../cli/src/cli/commands/ssh_agent/fixtures/b64_rsa"
    ))
}

fn fingerprint_of(key: &PrivateKey) -> String {
    key.public_key().fingerprint(HashAlg::Sha256).to_string()
}

#[test]
fn record_roundtrips_through_value() {
    for key in [ed25519_key(), rsa_key()] {
        let record = SshKeyRecord::new(&key, "work laptop").unwrap();
        let value = record.to_value().unwrap();
        let back = SshKeyRecord::from_value(value.expose_secret()).unwrap();

        assert_eq!(back, record);
        assert_eq!(back.comment, "work laptop");
        assert_eq!(back.policy, KeyPolicy::Default);
        assert_eq!(back.fingerprint().unwrap(), fingerprint_of(&key));
        assert_eq!(
            back.private_key().unwrap().public_key().key_data(),
            key.public_key().key_data()
        );
    }
}

#[test]
fn record_value_has_documented_fields() {
    let record = SshKeyRecord::new(&ed25519_key(), "c").unwrap();
    let value: serde_json::Value =
        serde_json::from_str(record.to_value().unwrap().expose_secret()).unwrap();

    assert!(
        value["private_key"]
            .as_str()
            .unwrap()
            .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
    );
    assert!(
        value["public_key"]
            .as_str()
            .unwrap()
            .starts_with("ssh-ed25519 ")
    );
    assert_eq!(value["comment"], "c");
    assert_eq!(value["policy"], "default");
}

#[test]
fn policy_defaults_to_default_when_absent() {
    let record = SshKeyRecord::new(&ed25519_key(), "").unwrap();
    let mut value = serde_json::to_value(&record).unwrap();
    value.as_object_mut().unwrap().remove("policy");
    value.as_object_mut().unwrap().remove("comment");

    let parsed = SshKeyRecord::from_value(&value.to_string()).unwrap();
    assert_eq!(parsed.policy, KeyPolicy::Default);
    assert_eq!(parsed.comment, "");
}

#[test]
fn always_require_auth_policy_roundtrips() {
    let mut record = SshKeyRecord::new(&ed25519_key(), "").unwrap();
    record.policy = KeyPolicy::AlwaysRequireAuth;

    let value = record.to_value().unwrap();
    assert!(
        value
            .expose_secret()
            .contains(r#""policy":"always_require_auth""#)
    );
    let back = SshKeyRecord::from_value(value.expose_secret()).unwrap();
    assert_eq!(back.policy, KeyPolicy::AlwaysRequireAuth);
}

#[test]
fn malformed_value_refused() {
    for value in ["", "not json", r#"{"public_key":"x"}"#, "[]"] {
        let err = SshKeyRecord::from_value(value).unwrap_err();
        assert!(matches!(err, SshKeyError::Malformed(_)), "{value}: {err}");
    }
}

#[test]
fn private_key_for_matching_fingerprint() {
    let key = ed25519_key();
    let record = SshKeyRecord::new(&key, "").unwrap();

    let found = record.private_key_for(&fingerprint_of(&key)).unwrap();
    assert_eq!(found.public_key().key_data(), key.public_key().key_data());
}

#[test]
fn fingerprint_mismatch_refused() {
    let record = SshKeyRecord::new(&ed25519_key(), "").unwrap();
    let requested = fingerprint_of(&rsa_key());

    let err = record.private_key_for(&requested).unwrap_err();
    assert!(
        matches!(&err, SshKeyError::FingerprintMismatch { requested: r, .. } if *r == requested),
        "{err}"
    );
}

#[test]
fn public_key_of_another_key_refused() {
    let mut record = SshKeyRecord::new(&ed25519_key(), "").unwrap();
    record.public_key = rsa_key().public_key().to_openssh().unwrap();
    let requested = record.fingerprint().unwrap();

    let err = record.private_key_for(&requested).unwrap_err();
    assert!(matches!(err, SshKeyError::PublicKeyMismatch), "{err}");
}

#[test]
fn encrypted_private_key_refused() {
    let key = ed25519_key()
        .encrypt(&mut ssh_key::rand_core::OsRng, "passphrase")
        .unwrap();
    let err = SshKeyRecord::new(&key, "").unwrap_err();
    assert!(matches!(err, SshKeyError::Encrypted), "{err}");

    let mut record = SshKeyRecord::new(&ed25519_key(), "").unwrap();
    record.private_key = key.to_openssh(LineEnding::LF).unwrap().to_string();
    let err = record.private_key().unwrap_err();
    assert!(matches!(err, SshKeyError::Encrypted), "{err}");
}

#[test]
fn debug_omits_private_key() {
    let record = SshKeyRecord::new(&ed25519_key(), "").unwrap();
    let shown = format!("{record:?}");

    assert!(!shown.contains("PRIVATE KEY"));
    assert!(!shown.contains(&record.private_key));
}

#[test]
fn unknown_record_fields_ignored() {
    let record = SshKeyRecord::new(&ed25519_key(), "").unwrap();
    let mut value = serde_json::to_value(&record).unwrap();
    value["added_later"] = json!(1);

    let parsed = SshKeyRecord::from_value(&value.to_string()).unwrap();
    assert_eq!(parsed, record);
}

#[test]
fn access_flags_default_to_true_and_are_omitted() {
    let record = SshKeyRecord::new(&ed25519_key(), "").unwrap();

    let value = serde_json::to_value(&record).unwrap();

    assert!(!value.as_object().unwrap().contains_key("auto_load"));
    assert!(!value.as_object().unwrap().contains_key("ssh_use"));
    let parsed = SshKeyRecord::from_value(&value.to_string()).unwrap();
    assert!(parsed.auto_load);
    assert!(parsed.ssh_use);
}

#[test]
fn access_flags_off_roundtrip() {
    let mut record = SshKeyRecord::new(&ed25519_key(), "").unwrap();
    record.set_access(false, true);

    let back = SshKeyRecord::from_value(record.to_value().unwrap().expose_secret()).unwrap();

    assert!(!back.auto_load);
    assert!(back.ssh_use);
}

#[test]
fn ssh_use_off_turns_auto_load_off() {
    let mut record = SshKeyRecord::new(&ed25519_key(), "").unwrap();

    record.set_access(true, false);

    assert!(!record.ssh_use);
    assert!(!record.auto_load);
}
