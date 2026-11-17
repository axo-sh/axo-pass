use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as b64;
use rsa::signature::Verifier;
use secrecy::SecretString;
use ssh_agent_lib::proto::signature;
use ssh_key::{Algorithm, HashAlg, PrivateKey};

use super::*;

const DATA: &[u8] = b"test data to sign";

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

/// A vault with `key` as credential `key` of item `github` and a text
/// credential `token`.
fn vault_with(key: &PrivateKey) -> VaultHandle {
    let mut vault = VaultHandle::new_for_test("personal");
    vault.add_item("github", "GitHub").unwrap();
    let record = SshKeyRecord::new(key, "laptop").unwrap();
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
    vault
}

#[test]
fn signs_ed25519_key() {
    let key = ed25519_key();
    let vault = vault_with(&key);

    let signature =
        sign_with_stored_key(&vault, "github", "key", &fingerprint_of(&key), DATA, 0).unwrap();

    assert_eq!(signature.algorithm(), Algorithm::Ed25519);
    key.public_key()
        .key_data()
        .verify(DATA, &signature)
        .unwrap();
}

#[test]
fn ed25519_ignores_rsa_flags() {
    let key = ed25519_key();
    let vault = vault_with(&key);

    let signature = sign_with_stored_key(
        &vault,
        "github",
        "key",
        &fingerprint_of(&key),
        DATA,
        signature::RSA_SHA2_512,
    )
    .unwrap();

    assert_eq!(signature.algorithm(), Algorithm::Ed25519);
}

#[test]
fn rsa_signs_with_sha256_by_default() {
    let key = rsa_key();
    let vault = vault_with(&key);

    let signature =
        sign_with_stored_key(&vault, "github", "key", &fingerprint_of(&key), DATA, 0).unwrap();

    assert_eq!(
        signature.algorithm(),
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha256)
        }
    );
    key.public_key()
        .key_data()
        .verify(DATA, &signature)
        .unwrap();
}

#[test]
fn rsa_signs_with_sha256_for_sha256_flag() {
    let key = rsa_key();
    let vault = vault_with(&key);

    let signature = sign_with_stored_key(
        &vault,
        "github",
        "key",
        &fingerprint_of(&key),
        DATA,
        signature::RSA_SHA2_256,
    )
    .unwrap();

    assert_eq!(
        signature.algorithm(),
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha256)
        }
    );
}

#[test]
fn rsa_signs_with_sha512_for_sha512_flag() {
    let key = rsa_key();
    let vault = vault_with(&key);

    let signature = sign_with_stored_key(
        &vault,
        "github",
        "key",
        &fingerprint_of(&key),
        DATA,
        signature::RSA_SHA2_512,
    )
    .unwrap();

    assert_eq!(
        signature.algorithm(),
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha512)
        }
    );
    key.public_key()
        .key_data()
        .verify(DATA, &signature)
        .unwrap();
}

#[test]
fn fingerprint_mismatch_refused() {
    let vault = vault_with(&ed25519_key());
    let requested = fingerprint_of(&rsa_key());

    let err = sign_with_stored_key(&vault, "github", "key", &requested, DATA, 0).unwrap_err();

    assert!(err.contains(&requested), "{err}");
}

#[test]
fn public_key_mismatch_refused() {
    let key = ed25519_key();
    let mut vault = vault_with(&key);
    let mut record = SshKeyRecord::new(&key, "").unwrap();
    record.public_key = rsa_key().public_key().to_openssh().unwrap();
    vault
        .replace_secret(
            "github",
            "key",
            "Key",
            FieldKind::SshKey,
            record.to_value().unwrap(),
        )
        .unwrap();

    let err = sign_with_stored_key(
        &vault,
        "github",
        "key",
        &fingerprint_of(&rsa_key()),
        DATA,
        0,
    )
    .unwrap_err();

    assert!(err.contains("does not belong"), "{err}");
}

#[test]
fn credential_of_other_kind_refused() {
    let key = ed25519_key();
    let vault = vault_with(&key);

    let err = sign_with_stored_key(&vault, "github", "token", &fingerprint_of(&key), DATA, 0)
        .unwrap_err();

    assert!(err.contains("not an SSH key"), "{err}");
}

#[test]
fn missing_credential_refused() {
    let key = ed25519_key();
    let vault = vault_with(&key);

    for (item, credential) in [("github", "nothing"), ("nothing", "key")] {
        let result = sign_with_stored_key(&vault, item, credential, &fingerprint_of(&key), DATA, 0);
        assert!(result.is_err(), "{item}/{credential}");
    }
}

#[test]
fn malformed_value_refused() {
    let key = ed25519_key();
    let mut vault = vault_with(&key);
    vault
        .replace_secret(
            "github",
            "key",
            "Key",
            FieldKind::SshKey,
            SecretString::from("not a record"),
        )
        .unwrap();

    let err =
        sign_with_stored_key(&vault, "github", "key", &fingerprint_of(&key), DATA, 0).unwrap_err();

    assert!(err.contains("Malformed"), "{err}");
}
