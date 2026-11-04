use uuid::Uuid;
use zeroize::ZeroizeOnDrop;

use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::sync::keys::{
    KeyFingerprint, StateKey, SyncKey, SyncKeyWrapper, SyncKeyring, TestKeyWrapper, WrappedSyncKey,
};
use crate::secrets::vaults::sync::model::KeyId;

/// Sync key of the fixed vectors: the bytes 0 to 31.
fn vector_key() -> SyncKey {
    SyncKey::from_bytes(std::array::from_fn(|i| i as u8))
}

/// Vault id of the fixed vectors.
const VECTOR_VAULT: Uuid = Uuid::from_u128(0x6f1c2b9e_5d4a_4c3b_8a29_1e0f2d3c4b5a);

/// Bytes of the hex string `hex`.
fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn keyring(ids: &[u32]) -> SyncKeyring {
    SyncKeyring::new(
        ids.iter()
            .map(|&id| (KeyId(id), SyncKey::generate()))
            .collect(),
    )
    .unwrap()
}

#[test]
fn fingerprint_and_state_key_match_fixed_vectors() {
    // Vectors computed with OpenSSL, not with the code under test:
    //   K=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    //   openssl kdf -keylen 16 -kdfopt digest:SHA256 -kdfopt hexkey:$K \
    //     -kdfopt info:ap-key-fingerprint-v1 HKDF
    //   openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt hexkey:$K \
    //     -kdfopt hexsalt:6f1c2b9e5d4a4c3b8a291e0f2d3c4b5a \
    //     -kdfopt info:ap-state-key-v1 HKDF
    // The second vault id of `two_vault_ids_give_two_state_keys_for_one_sync_key`
    // takes hexsalt 6f1c2b9e5d4a4c3b8a291e0f2d3c4b5b.
    let key = vector_key();
    assert_eq!(
        key.fingerprint().0.to_vec(),
        unhex("7ff6f50dffb4e2dd6f7fe8f45f90e7c5")
    );
    assert_eq!(
        key.state_key(VECTOR_VAULT).as_bytes().to_vec(),
        unhex("b84a08b1ac0e93bbd9ac32363222f81f74755668002324b99e3e974ce0bbd99f")
    );
}

#[test]
fn two_vault_ids_give_two_state_keys_for_one_sync_key() {
    let key = vector_key();
    let other_vault = Uuid::from_u128(VECTOR_VAULT.as_u128() + 1);
    assert_eq!(
        key.state_key(other_vault).as_bytes().to_vec(),
        unhex("89356729b77fef5f0a59639a169af1fc81f51899ff5e3e5ff9273a84ed2fae00")
    );
    assert_ne!(
        key.state_key(VECTOR_VAULT).as_bytes(),
        key.state_key(other_vault).as_bytes()
    );

    let key = SyncKey::generate();
    assert_ne!(
        key.state_key(VECTOR_VAULT).as_bytes(),
        key.state_key(other_vault).as_bytes()
    );
}

#[test]
fn generated_keys_differ() {
    let a = SyncKey::generate();
    let b = SyncKey::generate();
    assert_ne!(a.as_bytes(), b.as_bytes());
    assert_ne!(a.fingerprint(), b.fingerprint());
}

#[test]
fn keyring_round_trips_through_wrapping_and_json() {
    let keyring = keyring(&[1, 2]);
    let wrapped = keyring.wrap(&TestKeyWrapper).unwrap();
    let json = serde_json::to_string(&wrapped).unwrap();
    let read: Vec<WrappedSyncKey> = serde_json::from_str(&json).unwrap();
    let unwrapped = SyncKeyring::unwrap(&read, &TestKeyWrapper).unwrap();

    assert_eq!(unwrapped.keys().len(), 2);
    for (key_id, key) in keyring.keys() {
        assert_eq!(unwrapped.get(*key_id).unwrap().as_bytes(), key.as_bytes());
    }
    let ids: Vec<KeyId> = wrapped.iter().map(|entry| entry.key_id).collect();
    assert_eq!(ids, [KeyId(1), KeyId(2)]);
}

#[test]
fn wrapped_key_json_has_key_id_and_wrapped_string_only() {
    let entry = WrappedSyncKey {
        key_id: KeyId(2),
        wrapped: "d3JhcHBlZA==".to_string(),
    };
    assert_eq!(
        serde_json::to_string(&entry).unwrap(),
        r#"{"key_id":2,"wrapped":"d3JhcHBlZA=="}"#
    );
    let unknown = r#"{"key_id":2,"wrapped":"d3JhcHBlZA==","other":1}"#;
    assert!(serde_json::from_str::<WrappedSyncKey>(unknown).is_err());
}

#[test]
fn key_that_fails_to_unwrap_or_has_wrong_length_fails_keyring() {
    let not_wrapped = WrappedSyncKey {
        key_id: KeyId(1),
        wrapped: "bm90IHdyYXBwZWQ=".to_string(),
    };
    assert!(matches!(
        SyncKeyring::unwrap(&[not_wrapped], &TestKeyWrapper),
        Err(Error::SyncKeyDecryptionError(1))
    ));

    let short = WrappedSyncKey {
        key_id: KeyId(2),
        wrapped: TestKeyWrapper.wrap(&[7u8; 16]).unwrap(),
    };
    assert!(matches!(
        SyncKeyring::unwrap(&[short], &TestKeyWrapper),
        Err(Error::SyncKeyDecryptionError(2))
    ));
}

#[test]
fn two_keys_with_one_key_id_are_refused() {
    let keys = vec![
        (KeyId(1), SyncKey::generate()),
        (KeyId(1), SyncKey::generate()),
    ];
    assert!(matches!(
        SyncKeyring::new(keys),
        Err(Error::DuplicateSyncKeyId(1))
    ));

    let wrapped = keyring(&[3]).wrap(&TestKeyWrapper).unwrap();
    let twice = [wrapped.clone(), wrapped].concat();
    assert!(matches!(
        SyncKeyring::unwrap(&twice, &TestKeyWrapper),
        Err(Error::DuplicateSyncKeyId(3))
    ));
}

#[test]
fn sync_key_debug_shows_no_bytes() {
    fn zeroizes_on_drop<T: ZeroizeOnDrop>() {}
    zeroizes_on_drop::<SyncKey>();
    zeroizes_on_drop::<StateKey>();

    let key = SyncKey::from_bytes([0xab; 32]);
    assert_eq!(format!("{key:?}"), "SyncKey(..)");
    assert_eq!(format!("{:?}", key.state_key(VECTOR_VAULT)), "StateKey(..)");
    let keyring = SyncKeyring::new(vec![(KeyId(1), key)]).unwrap();
    let debug = format!("{keyring:?}");
    assert!(debug.contains("SyncKey(..)"), "{debug}");
    assert!(!debug.contains("171") && !debug.contains("ab"), "{debug}");
}

#[test]
fn fingerprint_that_matches_in_first_8_bytes_only_is_different_key() {
    let keyring = keyring(&[1]);
    let key = keyring.get(KeyId(1)).unwrap();
    let fingerprint = key.fingerprint();
    let mut other = fingerprint;
    other.0[8..].iter_mut().for_each(|b| *b ^= 0xff);

    assert_eq!(fingerprint.0[..8], other.0[..8]);
    assert_ne!(fingerprint, other);
    assert!(keyring.find(KeyId(1), &fingerprint).is_some());
    assert!(keyring.find(KeyId(1), &other).is_none());

    let mut last_byte = fingerprint;
    last_byte.0[15] ^= 1;
    assert_ne!(fingerprint, last_byte);
    assert!(keyring.find(KeyId(1), &last_byte).is_none());
    assert!(keyring.find(KeyId(2), &fingerprint).is_none());
}

#[test]
fn fingerprint_is_cbor_byte_string_and_json_base64() {
    let fingerprint = KeyFingerprint([0x11; 16]);
    let json = serde_json::to_string(&fingerprint).unwrap();
    assert_eq!(json, "\"EREREREREREREREREREREQ==\"");
    assert_eq!(
        serde_json::from_str::<KeyFingerprint>(&json).unwrap(),
        fingerprint
    );
    assert!(serde_json::from_str::<KeyFingerprint>("\"EREREREREREREREREQ==\"").is_err());

    let mut cbor = Vec::new();
    ciborium::into_writer(&fingerprint, &mut cbor).unwrap();
    // Major type 2, byte string, with length 16.
    assert_eq!(cbor[0], 0x50);
    assert_eq!(cbor[1..], [0x11; 16]);
}
