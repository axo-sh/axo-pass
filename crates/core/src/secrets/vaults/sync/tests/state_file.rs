//! State file body and state file format.

use std::io::Write;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ciborium::Value;
use flate2::Compression;
use flate2::write::DeflateEncoder;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::view::State;
use super::{NOW, id, session};
use crate::secrets::vaults::autofill::item::{MatchKind, Role};
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::passkey::signals::{SignalEntry, UnknownEntry};
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::keys::{KeyFingerprint, SyncKey, SyncKeyring};
use crate::secrets::vaults::sync::model::{
    FolderValue, HistoryValue, KeyId, Placement, PublicKey, RecoveryRecipient, Removal,
    ReplicaKeys, SYNC_FORMAT_VERSION, SecretText, SectionValue, TrashValue, WebsiteValue,
};
use crate::secrets::vaults::sync::state_file::body::{BodyError, StateBody};
use crate::secrets::vaults::sync::state_file::padded::{MAX_BODY_LEN, PaddedBody, PaddingError};
use crate::secrets::vaults::sync::state_file::{
    Damage, StateFile, StateFileError, StateHash, StateHeader, StateSource,
};

mod body;

use body::{edited, field, with_unknown_field};

/// State with every register of every kind written, a conflict, and three
/// replicas. Replica 3 appears only in the per-replica maps.
pub(super) fn full_state() -> State {
    let mut one = session(1);
    let mut two = session(2);
    let retired = ReplicaId(id(3));
    let mut state = State::default();
    let m = one.mint(&mut state, NOW);
    let s = &mut state.store;
    s.name.write(&m, Some("Personal".to_string()));
    s.replica_names
        .entry(one.replica)
        .write(&m, "MacBook".to_string());
    s.replica_keys.entry(one.replica).write(
        &m,
        ReplicaKeys {
            encryption: PublicKey(vec![4, 1, 2]),
            signing: PublicKey(vec![4, 3, 4]),
        },
    );
    s.removed
        .entry(retired)
        .write(&m, Removal { key_id: KeyId(2) });
    s.left.entry(retired).write(&m, true);
    s.recovery.entry("age1example".to_string()).write(
        &m,
        RecoveryRecipient {
            key_id: KeyId(1),
            key_fingerprint: [7; 16],
        },
    );
    s.folders.entry(id(10)).write(
        &m,
        FolderValue {
            title: "Work".to_string(),
            position: Some(0),
        },
    );
    let signal = SignalEntry::Unknown(UnknownEntry {
        rp_id: "example.com".to_string(),
        credential_id: "AQID".to_string(),
        at: NOW,
    });
    s.signals.entry(signal.key()).write(&m, signal);

    let item = s.items.entry(id(20));
    item.title.write(&m, "GitHub".to_string());
    item.category.write(&m, Some("login".to_string()));
    item.key.write(&m, "github".to_string());
    item.folder.write(&m, Some(id(10)));
    item.sections.entry(id(21)).write(
        &m,
        SectionValue {
            title: "Recovery".to_string(),
            position: Some(0),
        },
    );
    item.websites.entry("https://github.com".to_string()).write(
        &m,
        WebsiteValue {
            match_kind: MatchKind::Host,
            position: 0,
        },
    );
    item.username.write(&m, Some(id(31)));
    item.password.write(&m, Some(id(30)));
    item.totp.write(&m, None);
    item.trashed.write(&m, None);

    let password = s.credentials.entry(id(30));
    password.item.write(&m, id(20));
    password.title.write(&m, "Password".to_string());
    password.kind.write(&m, FieldKind::default());
    password.key.write(&m, "password".to_string());
    password.placement.write(
        &m,
        Placement {
            section: Some(id(21)),
            position: Some(0),
        },
    );
    password.value.write(&m, SecretText::new("p1"));
    password.history.entry(id(40)).write(
        &m,
        HistoryValue {
            value: SecretText::new("p0"),
            replaced_at: NOW,
        },
    );
    password.last_used_day_at.entry(one.replica).write(&m, NOW);
    password.trashed.write(&m, None);

    let username = s.credentials.entry(id(31));
    username.item.write(&m, id(20));
    username.trashed.write(
        &m,
        Some(TrashValue {
            deleted_at: NOW,
            role: Some(Role::Username),
        }),
    );

    // Concurrent values of one password from replicas 1 and 2.
    let mut other = state.clone();
    let m = one.mint(&mut state, NOW + 1);
    let password = state.store.credentials.entry(id(30));
    password.value.write(&m, SecretText::new("p3"));
    let m = two.mint(&mut other, NOW + 2);
    let password = other.store.credentials.entry(id(30));
    password.value.write(&m, SecretText::new("p2"));
    other
        .store
        .replica_names
        .entry(two.replica)
        .write(&m, "iMac".to_string());
    state.join(other);
    state
}

/// Vault of every state file test.
pub(super) const VAULT: Uuid = Uuid::from_u128(0x100);

/// Writer of every state file test.
pub(super) const WRITER: ReplicaId = ReplicaId(Uuid::from_u128(1));

/// Sync key of the tests, with key id 1.
pub(super) fn key() -> SyncKey {
    SyncKey::from_bytes([1; 32])
}

/// Keyring with [`key`] under key id 1.
pub(super) fn keyring() -> SyncKeyring {
    SyncKeyring::new(vec![(KeyId(1), key())]).unwrap()
}

/// State file of the padded body `padded`, by [`WRITER`] under [`key`].
fn file_of(padded: &[u8]) -> Vec<u8> {
    StateFile::encode(padded, VAULT, WRITER, KeyId(1), &key()).unwrap()
}

/// State file of `state`.
fn file(state: &State) -> Vec<u8> {
    file_of(&PaddedBody::of(state).unwrap())
}

/// Source of `bytes` in the directories of [`VAULT`] and [`WRITER`].
fn source(bytes: &[u8]) -> StateSource {
    StateSource {
        vault_id: VAULT,
        replica_id: WRITER,
        hash: StateHash::of(bytes),
    }
}

/// Decode `bytes` under its own hash with [`keyring`].
fn decode(bytes: &[u8]) -> Result<(StateHeader, State), StateFileError> {
    StateFile::decode(bytes, &source(bytes), &keyring())
}

/// Header JSON and ciphertext of the state file `bytes`.
fn split(bytes: &[u8]) -> (serde_json::Value, Vec<u8>) {
    let len = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize;
    let header = serde_json::from_slice(&bytes[8..8 + len]).unwrap();
    (header, bytes[8 + len..].to_vec())
}

/// State file of the header JSON `header` and `ciphertext`.
fn join(header: &serde_json::Value, ciphertext: &[u8]) -> Vec<u8> {
    let header = serde_json::to_vec(header).unwrap();
    let len = (header.len() as u32).to_be_bytes();
    [&b"APST"[..], &len, &header, ciphertext].concat()
}

/// The state file `bytes` with `edit` applied to its header JSON.
fn with_header(bytes: &[u8], edit: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    let (mut header, ciphertext) = split(bytes);
    edit(&mut header);
    join(&header, &ciphertext)
}

#[test]
fn state_file_round_trips_and_named_by_hash_of_its_bytes() {
    let state = full_state();
    let bytes = file(&state);

    let (header, decoded) = decode(&bytes).unwrap();

    assert_eq!(decoded, state);
    assert_eq!(&bytes[..4], b"APST");
    assert_eq!(header.format_version, SYNC_FORMAT_VERSION);
    assert_eq!(header.vault_id, VAULT);
    assert_eq!(header.replica_id, WRITER);
    assert_eq!(header.key_id, KeyId(1));
    assert_eq!(header.key_fingerprint, key().fingerprint());
    let hex: String = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let expected = format!("{}.{hex}.apstate", ShortId::encode_uuid(VAULT));
    assert_eq!(StateFile::name(VAULT, StateHash::of(&bytes)), expected);
    assert_eq!(StateHash::of(&bytes).to_string(), hex);
    assert_eq!(StateHash::parse(&hex), Some(StateHash::of(&bytes)));
}

#[test]
fn header_is_json_with_ids_hyphenated_and_bytes_base64() {
    let (header, _) = split(&file(&State::default()));
    let fingerprint = B64.encode(key().fingerprint().0);
    assert_eq!(header["format_version"], 1);
    assert_eq!(header["vault_id"], VAULT.to_string());
    assert_eq!(header["replica_id"], WRITER.0.to_string());
    assert_eq!(header["key_id"], 1);
    assert_eq!(header["key_fingerprint"], fingerprint);
    assert_eq!(
        B64.decode(header["nonce"].as_str().unwrap()).unwrap().len(),
        12
    );
    assert_eq!(header.as_object().unwrap().len(), 6);
}

#[test]
fn aad_is_canonical_string_of_header() {
    let header = StateHeader {
        format_version: 1,
        vault_id: VAULT,
        replica_id: WRITER,
        key_id: KeyId(12),
        key_fingerprint: KeyFingerprint([0xab; 16]),
        nonce: [0; 12],
    };
    assert_eq!(
        header.aad(),
        "ap-state-body-v1:1:00000000-0000-0000-0000-000000000100:\
         00000000-0000-0000-0000-000000000001:12:abababababababababababababababab"
    );
}

#[test]
fn changed_header_field_fails_aad_check() {
    let bytes = file(&full_state());
    let other_vault = Uuid::from_u128(0x200);
    let other_replica = ReplicaId(Uuid::from_u128(2));
    // Key 1 also under key id 2, so a changed key id reaches the AAD check.
    let keyring = SyncKeyring::new(vec![(KeyId(1), key()), (KeyId(2), key())]).unwrap();

    let cases: [(&str, Vec<u8>, StateSource); 3] = [
        ("vault_id", other_vault, WRITER),
        ("replica_id", VAULT, other_replica),
        ("key_id", VAULT, WRITER),
    ]
    .map(|(field, vault_id, replica_id)| {
        let changed = with_header(&bytes, |header| {
            header[field] = match field {
                "vault_id" => other_vault.to_string().into(),
                "replica_id" => other_replica.0.to_string().into(),
                _ => 2.into(),
            };
        });
        let source = StateSource {
            vault_id,
            replica_id,
            hash: StateHash::of(&changed),
        };
        (field, changed, source)
    });
    for (field, changed, source) in cases {
        assert_eq!(
            StateFile::decode(&changed, &source, &keyring),
            Err(StateFileError::Quarantine(Damage::Decryption)),
            "{field}"
        );
    }
}

#[test]
fn fingerprint_mismatch_ignored() {
    let bytes = file(&full_state());
    let other = SyncKeyring::new(vec![(KeyId(1), SyncKey::from_bytes([2; 32]))]).unwrap();

    let error = StateFile::decode(&bytes, &source(&bytes), &other).unwrap_err();

    assert_eq!(error, StateFileError::OtherKey(KeyId(1)));
    assert!(!error.is_quarantine());
}

#[test]
fn unknown_key_id_waits_for_key() {
    let bytes = file(&full_state());
    let later = SyncKeyring::new(vec![(KeyId(2), key())]).unwrap();

    for keyring in [SyncKeyring::default(), later] {
        let error = StateFile::decode(&bytes, &source(&bytes), &keyring).unwrap_err();
        assert_eq!(error, StateFileError::WaitingForKey(KeyId(1)));
        assert!(!error.is_quarantine());
    }
}

#[test]
fn vault_or_replica_mismatch_fails() {
    let bytes = file(&full_state());
    let other_vault = Uuid::from_u128(0x200);
    let other_replica = ReplicaId(Uuid::from_u128(2));

    let in_other_vault = StateSource {
        vault_id: other_vault,
        ..source(&bytes)
    };
    let in_other_replica = StateSource {
        replica_id: other_replica,
        ..source(&bytes)
    };

    assert_eq!(
        StateFile::decode(&bytes, &in_other_vault, &keyring()),
        Err(StateFileError::Quarantine(Damage::WrongVault(VAULT)))
    );
    assert_eq!(
        StateFile::decode(&bytes, &in_other_replica, &keyring()),
        Err(StateFileError::Quarantine(Damage::WrongReplica(WRITER)))
    );
}

#[test]
fn file_whose_bytes_do_not_hash_to_its_name_fails() {
    let bytes = file(&full_state());
    let mut changed = bytes.clone();
    *changed.last_mut().unwrap() ^= 1;

    assert_eq!(
        StateFile::decode(&changed, &source(&bytes), &keyring()),
        Err(StateFileError::Quarantine(Damage::HashMismatch))
    );
}

#[test]
fn file_without_magic_or_with_header_length_past_end_fails() {
    let bytes = file(&full_state());
    let mut no_magic = bytes.clone();
    no_magic[0] = b'X';
    let mut long_header = bytes.clone();
    let past_end = (bytes.len() as u32).to_be_bytes();
    long_header[4..8].copy_from_slice(&past_end);
    let short = bytes[..6].to_vec();

    let cases = [
        ("no magic", no_magic, Damage::NoMagic),
        ("header length", long_header, Damage::HeaderLength),
        ("short", short, Damage::HeaderLength),
    ];
    for (case, bytes, damage) in cases {
        assert_eq!(
            decode(&bytes),
            Err(StateFileError::Quarantine(damage)),
            "{case}"
        );
    }
}

#[test]
fn header_with_unknown_field_fails() {
    let bytes = with_header(&file(&full_state()), |header| {
        header["unknown_field"] = 1.into();
    });

    let error = decode(&bytes).unwrap_err();

    assert!(
        matches!(&error, StateFileError::Quarantine(Damage::Header(message)) if message.contains("unknown field")),
        "{error}"
    );
}

#[test]
fn header_with_newer_format_version_is_version_skew() {
    let newer = with_header(&file(&full_state()), |header| {
        header["format_version"] = 2.into();
        header["field_of_format_2"] = 1.into();
    });
    let older = with_header(&file(&full_state()), |header| {
        header["format_version"] = 0.into();
    });

    assert!(matches!(
        decode(&newer),
        Err(StateFileError::VersionSkew(_))
    ));
    assert!(matches!(
        decode(&older),
        Err(StateFileError::Quarantine(Damage::Header(_)))
    ));
}

#[test]
fn body_with_unknown_field_in_file_is_version_skew() {
    let body = with_unknown_field(|v| field(v, "store"));
    let bytes = file_of(&PaddedBody::pad(&body).unwrap());

    assert!(matches!(
        decode(&bytes),
        Err(StateFileError::VersionSkew(_))
    ));
}

#[test]
fn malformed_body_in_file_quarantined() {
    let body = edited(|v| {
        let Value::Map(fields) = v else {
            panic!("not a map");
        };
        fields.retain(|(key, _)| key.as_text() != Some("context"));
    });
    let bytes = file_of(&PaddedBody::pad(&body).unwrap());

    assert!(matches!(
        decode(&bytes),
        Err(StateFileError::Quarantine(Damage::Body(
            BodyError::Malformed(_)
        )))
    ));
}

#[test]
fn padded_body_with_invalid_layout_fails() {
    let mut nonzero = PaddedBody::of(&full_state()).unwrap();
    *nonzero.last_mut().unwrap() = 1;
    let mut past_end = PaddedBody::of(&full_state()).unwrap();
    let prefix = (past_end.len() as u32 - 3).to_be_bytes();
    past_end[..4].copy_from_slice(&prefix);
    let short = Zeroizing::new(past_end[..3].to_vec());

    let cases = [
        ("nonzero padding", nonzero, PaddingError::NonzeroPadding),
        (
            "length prefix past end",
            past_end,
            PaddingError::LengthPrefix,
        ),
        (
            "shorter than length prefix",
            short,
            PaddingError::LengthPrefix,
        ),
    ];
    for (case, padded, error) in cases {
        assert_eq!(
            decode(&file_of(&padded)),
            Err(StateFileError::Quarantine(Damage::Padding(error))),
            "{case}"
        );
    }
}

/// Padded body of the raw DEFLATE stream `compressed`, with no padding.
fn padded_stream(compressed: &[u8]) -> Vec<u8> {
    let len = (compressed.len() as u32).to_be_bytes();
    [&len[..], compressed].concat()
}

/// Raw DEFLATE stream of `bytes`.
fn deflate(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn body_that_inflates_past_64_mb_fails() {
    let at_limit = deflate(&vec![0; MAX_BODY_LEN]);
    let past_limit = deflate(&vec![0; MAX_BODY_LEN + 1]);

    // A body of exactly the limit inflates, and fails only as CBOR.
    assert!(matches!(
        decode(&file_of(&padded_stream(&at_limit))),
        Err(StateFileError::Quarantine(Damage::Body(_)))
    ));
    assert_eq!(
        decode(&file_of(&padded_stream(&past_limit))),
        Err(StateFileError::Quarantine(Damage::Padding(
            PaddingError::TooLarge
        )))
    );
    assert!(PaddedBody::pad(&vec![0; MAX_BODY_LEN + 1]).is_err());
}

#[test]
fn truncated_stream_or_bytes_after_stream_fail() {
    let body = StateBody::encode(&full_state()).unwrap();
    let stream = deflate(&body);
    let truncated = &stream[..stream.len() - 1];
    let trailing = [&stream[..], &[0]].concat();

    for (case, compressed) in [("truncated", truncated), ("trailing", &trailing[..])] {
        assert!(
            matches!(
                decode(&file_of(&padded_stream(compressed))),
                Err(StateFileError::Quarantine(Damage::Padding(
                    PaddingError::Inflate(_)
                )))
            ),
            "{case}"
        );
    }
    let (_, state) = decode(&file_of(&padded_stream(&stream))).unwrap();
    assert_eq!(state, full_state());
}

#[test]
fn nearby_sizes_share_file_size() {
    let named = |name: &str| {
        let mut one = session(1);
        let mut state = State::default();
        let m = one.mint(&mut state, NOW);
        state.store.name.write(&m, Some(name.to_string()));
        state
    };

    let short = file(&named("a"));
    let long = file(&named(&"a".repeat(100)));

    assert_ne!(
        StateBody::encode(&named("a")).unwrap().len(),
        StateBody::encode(&named(&"a".repeat(100))).unwrap().len()
    );
    assert_eq!(short.len(), long.len());
    assert_eq!(PaddedBody::of(&State::default()).unwrap().len(), 64 * 1024);
}

#[test]
fn buckets_start_at_64_kib_and_grow_by_at_most_19_percent() {
    assert_eq!(PaddedBody::bucket(0), 65_536);
    assert_eq!(PaddedBody::bucket(65_536), 65_536);
    assert_eq!(PaddedBody::bucket(65_537), 77_936);
    assert_eq!(PaddedBody::bucket(131_072), 131_072);

    let mut bucket = PaddedBody::bucket(0);
    while bucket < MAX_BODY_LEN {
        let next = PaddedBody::bucket(bucket + 1);
        assert!(next as f64 <= bucket as f64 * 1.19, "{bucket} to {next}");
        bucket = next;
    }
}

#[test]
fn same_state_encodes_to_different_bytes_under_fresh_nonce_and_both_decode() {
    let state = full_state();
    let first = file(&state);
    let second = file(&state);

    assert_ne!(first, second);
    assert_ne!(split(&first).0["nonce"], split(&second).0["nonce"]);
    assert_eq!(decode(&first).unwrap().1, state);
    assert_eq!(decode(&second).unwrap().1, state);
}
