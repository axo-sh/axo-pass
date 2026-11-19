// Tests that need a software `ManagedKey` run on macOS only.
#![cfg_attr(linux, allow(unused_imports, dead_code))]

use indoc::indoc;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::vaults::bundle::ExportMode;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::keys::SyncKey;
use crate::secrets::vaults::sync::model::{KeyId, PublicKey, ReplicaKeys};
use crate::secrets::vaults::sync::wrapping::base32::Crockford;
use crate::secrets::vaults::sync::wrapping::encoding::Canonical;
use crate::secrets::vaults::sync::wrapping::{
    AgeWrapping, DeviceUnwrap, DeviceWrapping, KeyFile, KeyFileError, PairingMac, Wrapping,
    WrappingSignature,
};

/// Replica of the test wrappings.
const TO_REPLICA: ReplicaId = ReplicaId(Uuid::from_u128(0x2a));

/// Unwrap that returns fixed bytes for any ciphertext, or fails if it has
/// none.
struct TestDeviceUnwrap(Option<Vec<u8>>);

impl DeviceUnwrap for TestDeviceUnwrap {
    fn unwrap_sync_key(&self, _wrapped: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        self.0.clone().map(Zeroizing::new)
    }
}

/// Public keys of a sending Mac, as SEC1 bytes that are not parsed.
fn from_keys() -> ReplicaKeys {
    ReplicaKeys {
        encryption: PublicKey(vec![4; 65]),
        signing: PublicKey(vec![5; 65]),
    }
}

/// `Device` wrapping with fixed bytes and a pairing MAC.
fn device_wrapping(key: &SyncKey) -> DeviceWrapping {
    let from = from_keys();
    DeviceWrapping {
        key_id: KeyId(1),
        key_fingerprint: key.fingerprint(),
        to_replica: TO_REPLICA,
        from_encryption: from.encryption,
        from_signing: from.signing,
        wrapped: vec![7; 97],
        pairing_mac: Some(PairingMac([9; 32])),
        signature: None,
        removed: None,
        remaining: None,
    }
}

#[cfg(macos)]
fn software_key() -> ManagedKey {
    ManagedKey::create_software_for_test().unwrap()
}

/// `Device` wrapping of `key` to the public key of `to`.
fn wrap_to(key: &SyncKey, to: &ManagedKey) -> DeviceWrapping {
    let to_encryption = PublicKey(to.public_key_sec1().unwrap());
    DeviceWrapping::wrap(KeyId(1), key, TO_REPLICA, &to_encryption, &from_keys()).unwrap()
}

/// `key.json` with one `Device`, one `Age`, and one wrapping of an unknown
/// kind, in that order.
const MIXED_KEY_FILE: &str = indoc! {r#"
    {
      "version": 1,
      "wrappings": [
        {
          "kind": "Device",
          "key_id": 1,
          "key_fingerprint": "EREREREREREREREREREREQ==",
          "to_replica": "00000000-0000-0000-0000-00000000002a",
          "from_encryption": "BAQE",
          "from_signing": "BQUF",
          "wrapped": "BwcH",
          "pairing_mac": "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk="
        },
        {
          "kind": "Age",
          "key_id": 1,
          "key_fingerprint": "EREREREREREREREREREREQ==",
          "recipient": "age1example",
          "wrapped": "armored"
        },
        {"kind":"Passkey",  "key_id": 1, "credential":"abc",  "nested": {"z": 1, "a": [2, 1]}}
      ]
    }
"#};

/// Exact text of the unknown wrapping in [`MIXED_KEY_FILE`].
const UNKNOWN_WRAPPING: &str =
    r#"{"kind":"Passkey",  "key_id": 1, "credential":"abc",  "nested": {"z": 1, "a": [2, 1]}}"#;

#[test]
fn unknown_wrapping_kind_skipped() {
    let file = KeyFile::parse(MIXED_KEY_FILE.as_bytes()).unwrap();

    assert_eq!(file.wrappings.len(), 3);
    assert!(file.invalid.is_empty(), "{:?}", file.invalid);
    let devices: Vec<_> = file.devices().collect();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].to_replica, TO_REPLICA);
    assert_eq!(devices[0].pairing_mac, Some(PairingMac([9; 32])));
    assert_eq!(devices[0].signature, None);
    let ages: Vec<_> = file.ages().collect();
    assert_eq!(ages.len(), 1);
    assert_eq!(ages[0].recipient, "age1example");
    let Wrapping::Unknown(unknown) = &file.wrappings[2] else {
        panic!("third wrapping is not unknown: {:?}", file.wrappings[2]);
    };
    assert_eq!(unknown.kind, "Passkey");
}

#[test]
fn unknown_kind_written_back_unchanged() {
    let file = KeyFile::parse(MIXED_KEY_FILE.as_bytes()).unwrap();
    let written = String::from_utf8(file.to_bytes()).unwrap();

    assert!(written.contains(UNKNOWN_WRAPPING), "{written}");
    let read = KeyFile::parse(written.as_bytes()).unwrap();
    assert_eq!(read, file);
}

#[test]
fn key_file_round_trips() {
    let key = SyncKey::generate();
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public().to_string();
    let file = KeyFile {
        wrappings: vec![
            Wrapping::Device(device_wrapping(&key)),
            Wrapping::Age(AgeWrapping::wrap(KeyId(1), &key, &recipient).unwrap()),
        ],
        invalid: Vec::new(),
    };

    let bytes = file.to_bytes();
    let json = String::from_utf8(bytes.clone()).unwrap();
    assert!(
        json.starts_with(r#"{"version":1,"wrappings":[{"kind":"Device","key_id":1,"#),
        "{json}"
    );
    assert!(json.contains(r#"{"kind":"Age","key_id":1,"#), "{json}");
    assert!(
        !json.contains("signature") && !json.contains("removed"),
        "{json}"
    );
    assert_eq!(KeyFile::parse(&bytes).unwrap(), file);
}

#[test]
fn rotation_fields_of_device_wrapping_round_trip() {
    let key = SyncKey::generate();
    let mut wrapping = device_wrapping(&key);
    wrapping.pairing_mac = None;
    wrapping.signature = Some(WrappingSignature(vec![3; 70]));
    wrapping.removed = Some(vec![ReplicaId(Uuid::from_u128(3))]);
    wrapping.remaining = Some(vec![TO_REPLICA]);
    let file = KeyFile {
        wrappings: vec![Wrapping::Device(wrapping)],
        invalid: Vec::new(),
    };

    let json = String::from_utf8(file.to_bytes()).unwrap();
    assert!(!json.contains("pairing_mac"), "{json}");
    assert_eq!(KeyFile::parse(json.as_bytes()).unwrap(), file);
}

#[test]
fn key_file_of_version_2_fails_as_version_skew() {
    let newer = MIXED_KEY_FILE.replace(r#""version": 1"#, r#""version": 2"#);
    assert!(matches!(
        KeyFile::parse(newer.as_bytes()),
        Err(KeyFileError::VersionSkew(_))
    ));

    // The version is read before the other fields.
    let newer = r#"{"version": 2, "wrappings": 5, "other": true}"#;
    assert!(matches!(
        KeyFile::parse(newer.as_bytes()),
        Err(KeyFileError::VersionSkew(_))
    ));

    let zero = r#"{"version": 0, "wrappings": []}"#;
    assert!(matches!(
        KeyFile::parse(zero.as_bytes()),
        Err(KeyFileError::VersionSkew(_))
    ));
}

#[test]
fn malformed_key_file_fails() {
    for text in [
        "",
        "not json",
        "[]",
        r#"{"wrappings": []}"#,
        r#"{"version": 1}"#,
        r#"{"version": 1, "wrappings": {}}"#,
        r#"{"version": 1, "wrappings": [], "other": 1}"#,
    ] {
        assert!(
            matches!(
                KeyFile::parse(text.as_bytes()),
                Err(KeyFileError::Malformed(_))
            ),
            "{text}"
        );
    }
}

#[test]
fn unknown_field_in_device_or_age_wrapping_fails_that_wrapping() {
    let text = MIXED_KEY_FILE
        .replace(r#""pairing_mac": "#, r#""other": 1, "pairing_mac": "#)
        .replace(r#""recipient": "#, r#""other": 1, "recipient": "#);
    let file = KeyFile::parse(text.as_bytes()).unwrap();

    assert_eq!(file.devices().count(), 0);
    assert_eq!(file.ages().count(), 0);
    assert_eq!(file.invalid.len(), 2, "{:?}", file.invalid);
    assert!(
        file.invalid[0].starts_with("Device wrapping"),
        "{:?}",
        file.invalid
    );
    assert!(
        file.invalid[1].starts_with("Age wrapping"),
        "{:?}",
        file.invalid
    );
    assert!(matches!(file.wrappings[..], [Wrapping::Unknown(_)]));

    // Invalid wrappings are not written.
    let written = String::from_utf8(file.to_bytes()).unwrap();
    assert!(
        !written.contains("Device") && !written.contains("Age"),
        "{written}"
    );
}

#[test]
fn wrapping_with_no_kind_or_missing_field_fails_that_wrapping() {
    let text = indoc! {r#"
        {
          "version": 1,
          "wrappings": [
            {"key_id": 1},
            {"kind": 3},
            "Device",
            {"kind": "Device", "key_id": 1},
            {"kind": "Age", "key_id": 1, "key_fingerprint": "EQ==", "recipient": "r", "wrapped": "w"}
          ]
        }
    "#};
    let file = KeyFile::parse(text.as_bytes()).unwrap();

    assert!(file.wrappings.is_empty(), "{:?}", file.wrappings);
    assert_eq!(file.invalid.len(), 5, "{:?}", file.invalid);
}

#[cfg(macos)]
#[test]
fn software_key_unwraps_with_private_key() {
    let key = SyncKey::generate();
    let to = software_key();
    let wrapping = wrap_to(&key, &to);

    assert_eq!(wrapping.key_id, KeyId(1));
    assert_eq!(wrapping.key_fingerprint, key.fingerprint());
    assert_eq!(wrapping.to_replica, TO_REPLICA);
    assert_eq!(wrapping.from_encryption, from_keys().encryption);
    assert_eq!(wrapping.from_signing, from_keys().signing);
    assert_eq!(wrapping.pairing_mac, None);
    assert_ne!(wrapping.wrapped, key.as_bytes());

    let unwrapped = wrapping.unwrap(&to).unwrap();
    assert_eq!(unwrapped.as_bytes(), key.as_bytes());

    // Two wrappings of one key differ, since each takes a new ephemeral key.
    assert_ne!(wrap_to(&key, &to).wrapped, wrapping.wrapped);
}

#[cfg(macos)]
#[test]
fn software_key_fails_with_wrong_private_key() {
    let key = SyncKey::generate();
    let wrapping = wrap_to(&key, &software_key());

    assert!(matches!(
        wrapping.unwrap(&software_key()),
        Err(Error::SyncKeyDecryptionError(1))
    ));
}

#[test]
fn key_wrapped_to_malformed_public_key_fails() {
    let key = SyncKey::generate();
    for public in [Vec::new(), vec![4; 65], vec![4; 10]] {
        assert!(
            matches!(
                DeviceWrapping::wrap(
                    KeyId(2),
                    &key,
                    TO_REPLICA,
                    &PublicKey(public.clone()),
                    &from_keys()
                ),
                Err(Error::SyncKeyEncryptionError(2))
            ),
            "{public:?}"
        );
    }
}

#[test]
fn device_unwrap_refuses_wrong_length_other_fingerprint_and_failed_unwrap() {
    let key = SyncKey::generate();
    let wrapping = device_wrapping(&key);

    let unwrapped = wrapping
        .unwrap(&TestDeviceUnwrap(Some(key.as_bytes().to_vec())))
        .unwrap();
    assert_eq!(unwrapped.as_bytes(), key.as_bytes());

    assert!(matches!(
        wrapping.unwrap(&TestDeviceUnwrap(None)),
        Err(Error::SyncKeyDecryptionError(1))
    ));
    for length in [0, 16, 31, 33] {
        assert!(matches!(
            wrapping.unwrap(&TestDeviceUnwrap(Some(vec![1; length]))),
            Err(Error::SyncKeyDecryptionError(1))
        ));
    }
    let other = SyncKey::generate();
    assert!(matches!(
        wrapping.unwrap(&TestDeviceUnwrap(Some(other.as_bytes().to_vec()))),
        Err(Error::SyncKeyFingerprintMismatch(1))
    ));

    // A fingerprint that differs in the last byte only is refused.
    let mut last_byte = wrapping.clone();
    last_byte.key_fingerprint.0[15] ^= 1;
    assert!(matches!(
        last_byte.unwrap(&TestDeviceUnwrap(Some(key.as_bytes().to_vec()))),
        Err(Error::SyncKeyFingerprintMismatch(1))
    ));
}

#[test]
fn age_wrapping_unwraps_with_its_identity_and_fails_with_another() {
    let key = SyncKey::generate();
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public().to_string();
    let wrapping = AgeWrapping::wrap(KeyId(3), &key, &recipient).unwrap();

    assert_eq!(wrapping.key_id, KeyId(3));
    assert_eq!(wrapping.key_fingerprint, key.fingerprint());
    assert_eq!(wrapping.recipient, recipient);
    assert!(
        wrapping
            .wrapped
            .starts_with("-----BEGIN AGE ENCRYPTED FILE-----")
    );
    assert_eq!(
        wrapping.unwrap(&identity).unwrap().as_bytes(),
        key.as_bytes()
    );

    let other = age::x25519::Identity::generate();
    assert!(matches!(
        wrapping.unwrap(&other),
        Err(Error::SyncKeyDecryptionError(3))
    ));
}

#[test]
fn age_wrapping_not_32_bytes_or_has_bad_recipient_fails() {
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public().to_string();
    let key = SyncKey::generate();
    let mut wrapping = AgeWrapping::wrap(KeyId(1), &key, &recipient).unwrap();
    wrapping.wrapped = ExportMode::Recipient(recipient.clone())
        .encrypt(&[1; 16])
        .unwrap();
    assert!(matches!(
        wrapping.unwrap(&identity),
        Err(Error::SyncKeyDecryptionError(1))
    ));

    assert!(matches!(
        AgeWrapping::wrap(KeyId(1), &key, "age1notarecipient"),
        Err(Error::SyncKeyEncryptionError(1))
    ));
}

#[test]
fn canonical_encoding_prefixes_fields_with_length_and_lists_with_count() {
    let bytes = Canonical::new()
        .field(b"ab")
        .list([b"c".as_slice(), b""].into_iter(), |c, item| c.field(item))
        .into_bytes();
    assert_eq!(
        bytes,
        [
            0, 0, 0, 2, b'a', b'b', // field "ab"
            0, 0, 0, 2, // count 2
            0, 0, 0, 1, b'c', // field "c"
            0, 0, 0, 0, // field ""
        ]
    );
}

#[test]
fn moving_bytes_between_two_fields_changes_canonical_encoding() {
    let encode = |a: &[u8], b: &[u8]| Canonical::new().field(a).field(b).into_bytes();
    assert_ne!(encode(b"ab", b"c"), encode(b"a", b"bc"));
    assert_ne!(encode(b"abc", b""), encode(b"", b"abc"));
    assert_eq!(encode(b"ab", b"c"), encode(b"ab", b"c"));

    // Moving an item out of a list into the next field changes the bytes.
    let listed = |items: &[&[u8]], last: &[u8]| {
        Canonical::new()
            .list(items.iter(), |c, item| c.field(item))
            .field(last)
            .into_bytes()
    };
    assert_ne!(listed(&[b"a", b"b"], b"c"), listed(&[b"a"], b"bc"));
    assert_ne!(listed(&[b"a", b"b"], b""), listed(&[b"a"], b"b"));
}

#[test]
fn crockford_encodes_with_its_alphabet() {
    assert_eq!(Crockford::encode(b"hello"), "D1JPRV3F");
    assert_eq!(Crockford::encode(&[0; 10]), "0000000000000000");
    assert_eq!(Crockford::encode(&[0xff; 10]), "ZZZZZZZZZZZZZZZZ");
    assert_eq!(
        Crockford::encode_grouped(&[0xff; 10], 4),
        "ZZZZ-ZZZZ-ZZZZ-ZZZZ"
    );

    let fingerprint = Crockford::encode_grouped(&[0x11; 16], 4);
    let groups: Vec<_> = fingerprint.split('-').map(str::len).collect();
    assert_eq!(groups, [4, 4, 4, 4, 4, 4, 2], "{fingerprint}");
    assert_eq!(Crockford::decode(&fingerprint).unwrap(), [0x11; 16]);
}

#[test]
fn crockford_reads_lowercase_hyphens_spaces_and_confusable_letters() {
    let bytes: Vec<u8> = (0..10).map(|i| i * 25).collect();
    let shown = Crockford::encode_grouped(&bytes, 4);
    assert_eq!(Crockford::decode(&shown).unwrap(), bytes);
    assert_eq!(Crockford::decode(&shown.to_lowercase()).unwrap(), bytes);
    assert_eq!(Crockford::decode(&shown.replace('-', " ")).unwrap(), bytes);
    assert_eq!(Crockford::decode(&shown.replace('-', "")).unwrap(), bytes);

    assert_eq!(Crockford::decode("d1jprv3f").unwrap(), b"hello");
    assert_eq!(
        Crockford::decode("OoOO-0000-iIlL-1111").unwrap(),
        Crockford::decode("0000-0000-1111-1111").unwrap()
    );
}

#[test]
fn crockford_refuses_character_outside_alphabet() {
    for text in [
        "D1JPRV3U",
        "D1JPRV3u",
        "D1JPRV3*",
        "D1JPRV3=",
        "D1JPRV3é",
        "D1JP_RV3F",
    ] {
        assert_eq!(Crockford::decode(text), None, "{text}");
    }
}
