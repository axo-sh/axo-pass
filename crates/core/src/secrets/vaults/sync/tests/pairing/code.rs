use std::collections::BTreeMap;

use uuid::Uuid;

use super::{NAME, sender_keys, vault, vector_code};
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::keys::KeyFingerprint;
use crate::secrets::vaults::sync::model::{KeyId, PublicKey, ReplicaKeys};
use crate::secrets::vaults::sync::pairing::PairingCode;
use crate::secrets::vaults::sync::pairing::request::PairingRequest;
use crate::secrets::vaults::sync::transport::RequestId;
use crate::secrets::vaults::sync::wrapping::DeviceWrapping;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn code_shown_in_four_groups_of_four_crockford_characters() {
    // Bits of 00 01 .. 09 in groups of 5, read by hand with `xxd -b`.
    assert_eq!(vector_code().shown().as_str(), "000G-40R4-0M30-E209");
    let first = PairingCode::generate();
    let second = PairingCode::generate();
    assert_ne!(first.shown(), second.shown());
    for shown in [first.shown(), second.shown()] {
        let groups: Vec<&str> = shown.split('-').collect();
        assert_eq!(groups.len(), 4, "{}", shown.as_str());
        for group in groups {
            assert_eq!(group.len(), 4);
            assert!(
                group
                    .chars()
                    .all(|c| "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(c))
            );
        }
    }
    assert_eq!(format!("{first:?}"), "PairingCode(..)");
    assert_eq!(format!("{:?}", first.pair_key()), "PairKey(..)");
}

#[test]
fn code_parses_from_shown_form() {
    let code = PairingCode::generate();
    let key = code.pair_key();
    let shown = code.shown();
    let lowercase = shown.to_lowercase();
    let confusable = shown.replace('0', "o").replace('1', "l");
    let spaced = shown.replace('-', " ");
    let bare = shown.replace('-', "");
    for text in [
        shown.as_str(),
        lowercase.as_str(),
        confusable.as_str(),
        spaced.as_str(),
        bare.as_str(),
    ] {
        let typed = PairingCode::parse(text).unwrap();
        assert_eq!(typed.pair_key().as_bytes(), key.as_bytes(), "{text}");
    }
    let vector = PairingCode::parse("ooog-4oR4-oM3o-E2o9").unwrap();
    assert_eq!(vector.shown(), vector_code().shown());
    let vector = PairingCode::parse("000g 40r4 0m30 e209").unwrap();
    assert_eq!(vector.shown(), vector_code().shown());
}

#[test]
fn code_of_other_length_or_outside_alphabet_refused() {
    for text in [
        "",
        "000G-40R4-0M30-E20",
        "000G-40R4-0M30-E2099",
        "000G-40R4-0M30-E20U",
        "000G-40R4-0M30-E20!",
        "000G_40R4_0M30_E209",
    ] {
        assert!(PairingCode::parse(text).is_none(), "{text}");
    }
}

#[test]
fn request_and_wrapping_hmacs_match_fixed_vectors() {
    // Vectors computed with OpenSSL, not with the code under test:
    //   openssl kdf -keylen 32 -kdfopt digest:SHA256 \
    //     -kdfopt hexkey:00010203040506070809 -kdfopt info:ap-pairing-v1 HKDF
    //   P=11e59615bf912ee3513439b91d4ecbe65406a123cea68713073cb8acba7648b3
    //   echo -n $REQUEST | xxd -r -p | openssl mac -digest SHA256 \
    //     -macopt hexkey:$P HMAC
    //   echo -n $WRAPPING | xxd -r -p | openssl mac -digest SHA256 \
    //     -macopt hexkey:$P HMAC
    // $REQUEST and $WRAPPING are the hex inputs asserted below. Each field is
    // its 4-byte big-endian length and its bytes. Ids are their 16 UUID
    // bytes, and the key id is 4 big-endian bytes.
    let key = vector_code().pair_key();
    assert_eq!(
        hex(key.as_bytes()),
        "11e59615bf912ee3513439b91d4ecbe65406a123cea68713073cb8acba7648b3"
    );

    let keys = ReplicaKeys {
        encryption: PublicKey(vec![0xe1, 0xe2]),
        signing: PublicKey(vec![0x51, 0x52]),
    };
    let replicas = BTreeMap::from([
        (Uuid::from_u128(0x11), ReplicaId(Uuid::from_u128(0x21))),
        (Uuid::from_u128(0x10), ReplicaId(Uuid::from_u128(0x20))),
    ]);
    let request = PairingRequest::new(
        RequestId(Uuid::from_u128(1)),
        replicas,
        &keys,
        "Mac".to_string(),
        &key,
    );
    let request_input = concat!(
        "00000010",
        "00000000000000000000000000000001",
        "00000002",
        "00000010",
        "00000000000000000000000000000010",
        "00000010",
        "00000000000000000000000000000020",
        "00000010",
        "00000000000000000000000000000011",
        "00000010",
        "00000000000000000000000000000021",
        "00000002e1e2",
        "000000025152",
        "000000034d6163",
    );
    assert_eq!(hex(&request.mac_input()), request_input);
    assert_eq!(
        hex(&request.mac.0),
        "872619dd18a6b24ce99fbca06f5d01c9229d0f35d6f7aa4c35b6bf0ef04bcb7c"
    );
    assert!(request.verify(&key));

    let mut wrapping = DeviceWrapping {
        key_id: KeyId(1),
        key_fingerprint: KeyFingerprint(core::array::from_fn(|i| 0xf0 + i as u8)),
        to_replica: ReplicaId(Uuid::from_u128(0x20)),
        from_encryption: PublicKey(vec![0xa1, 0xa2]),
        from_signing: PublicKey(vec![0xb1, 0xb2]),
        wrapped: vec![0xc1, 0xc2, 0xc3],
        pairing_mac: None,
        signature: None,
        removed: None,
        remaining: None,
    };
    let vault_id = Uuid::from_u128(0x10);
    let from_replica = ReplicaId(Uuid::from_u128(0x30));
    let wrapping_input = concat!(
        "00000010",
        "00000000000000000000000000000010",
        "00000010",
        "00000000000000000000000000000030",
        "00000010",
        "00000000000000000000000000000020",
        "00000004",
        "00000001",
        "00000010",
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "00000002e1e2",
        "000000025152",
        "00000002a1a2",
        "00000002b1b2",
        "00000003c1c2c3",
    );
    assert_eq!(
        hex(&wrapping.pairing_input(vault_id, from_replica, &keys)),
        wrapping_input
    );
    key.seal_wrapping(&mut wrapping, vault_id, from_replica, &keys);
    assert_eq!(
        hex(&wrapping.pairing_mac.unwrap().0),
        "81a5773ca6b7042bfd79d32500bf11b4723e6b58e45cbaa8a1c4dcb6cb1e802e"
    );
    assert!(key.verify_wrapping(&wrapping, vault_id, from_replica, &keys));
}

#[test]
fn pairing_request_round_trips_and_refuses_unknown_field() {
    let key = vector_code().pair_key();
    let request = PairingRequest::new(
        RequestId(Uuid::from_u128(1)),
        BTreeMap::from([(vault(1), ReplicaId(Uuid::from_u128(2)))]),
        &sender_keys(),
        NAME.to_string(),
        &key,
    );
    let parsed = PairingRequest::parse(&request.to_bytes()).unwrap();
    assert_eq!(parsed, request);
    assert!(parsed.verify(&key));

    let mut value: serde_json::Value = serde_json::from_slice(&request.to_bytes()).unwrap();
    value["extra"] = serde_json::json!(1);
    assert!(PairingRequest::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    assert!(PairingRequest::parse(b"{}").is_err());
}
