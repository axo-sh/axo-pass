//! Schema snapshot of sync format [`SYNC_FORMAT_VERSION`]: the serde forms
//! of the register value types.
//!
//! Samples are built from struct literals, and enums are listed next to an
//! exhaustive match, so a new field or variant fails to compile here until a
//! sample holds it. Each struct has a full sample with every field set and a
//! minimal sample with every optional field at its default. Each sample also
//! round-trips through CBOR.

use std::fmt::Debug;

use ciborium::Value;
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::*;
use crate::schema_snapshot::SchemaSnapshot;
use crate::secrets::vaults::passkey::signals::{
    AcceptedEntry, DismissEntry, DismissKind, RenameEntry, UnknownEntry,
};

/// Name of the sync schema in `snapshots/`.
const SCHEMA: &str = "sync-format";

/// Field added to each CBOR sample map to check that it is refused.
const UNKNOWN_FIELD: &str = "unknown_field";

fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

/// CBOR encoding of `value`.
fn cbor<T: Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).unwrap();
    bytes
}

/// Add `samples` as the sample `name`. Each sample must also round-trip
/// through CBOR unchanged, and its CBOR map must fail to parse with an
/// unknown field added.
fn add<T>(snapshot: &mut SchemaSnapshot, name: &str, samples: Vec<T>)
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    add_open(snapshot, name, samples, &[]);
}

/// [`add`] with the JSON objects at a key in `open_keys` left unchecked, as
/// [`SchemaSnapshot::add`] states.
fn add_open<T>(snapshot: &mut SchemaSnapshot, name: &str, samples: Vec<T>, open_keys: &[&str])
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    for sample in &samples {
        let bytes = cbor(sample);
        let parsed: T = ciborium::from_reader(&bytes[..]).unwrap();
        assert_eq!(&parsed, sample, "{name} changes in a CBOR round trip");

        let mut value: Value = ciborium::from_reader(&bytes[..]).unwrap();
        if let Value::Map(fields) = &mut value {
            fields.push((
                Value::Text(UNKNOWN_FIELD.to_string()),
                Value::Integer(1.into()),
            ));
            let edited = cbor(&value);
            let parsed: Result<T, _> = ciborium::from_reader(&edited[..]);
            assert!(
                parsed.is_err(),
                "{name} parses from CBOR with an unknown field"
            );
        }
    }
    snapshot.add(name, &samples, open_keys);
}

fn folder_values() -> Vec<FolderValue> {
    let full = FolderValue {
        title: "Work".to_string(),
        position: Some(1),
    };
    let minimal = FolderValue {
        title: "Work".to_string(),
        position: None,
    };
    vec![full, minimal]
}

fn section_values() -> Vec<SectionValue> {
    let full = SectionValue {
        title: "Recovery".to_string(),
        position: Some(1),
    };
    let minimal = SectionValue {
        title: "Recovery".to_string(),
        position: None,
    };
    vec![full, minimal]
}

/// Website value of every match kind. The default kind is the minimal sample.
fn website_values() -> Vec<WebsiteValue> {
    // A new kind fails to compile here until it is added to `kinds`.
    let _ = |kind: MatchKind| match kind {
        MatchKind::Domain | MatchKind::Host | MatchKind::StartsWith | MatchKind::Never => {},
    };
    let kinds = [
        MatchKind::Domain,
        MatchKind::Host,
        MatchKind::StartsWith,
        MatchKind::Never,
    ];
    kinds
        .into_iter()
        .zip(0..)
        .map(|(match_kind, position)| WebsiteValue {
            match_kind,
            position,
        })
        .collect()
}

fn placements() -> Vec<Placement> {
    let full = Placement {
        section: Some(id(1)),
        position: Some(2),
    };
    let minimal = Placement {
        section: None,
        position: None,
    };
    vec![full, minimal]
}

/// History value of every history kind, with a value as the kind states.
fn history_values() -> Vec<HistoryValue> {
    // A new kind fails to compile here until it is added below.
    let _ = |kind: HistoryKind| match kind {
        HistoryKind::ValueCreated | HistoryKind::ValueUpdated | HistoryKind::Unknown(_) => {},
    };
    let value = |kind, value: Option<&str>| HistoryValue {
        at: 1_700_000_005,
        kind,
        value: value.map(SecretText::new),
    };
    vec![
        value(HistoryKind::ValueCreated, None),
        value(HistoryKind::ValueUpdated, Some("p1")),
        value(
            HistoryKind::Unknown(serde_json::json!({"type": "renamed", "from": "Old title"})),
            None,
        ),
    ]
}

/// Trash value without a role, then with every role.
fn trash_values() -> Vec<TrashValue> {
    // A new role fails to compile here until it is added to `roles`.
    let _ = |role: Role| match role {
        Role::Username | Role::Password | Role::Totp => {},
    };
    let roles = [
        None,
        Some(Role::Username),
        Some(Role::Password),
        Some(Role::Totp),
    ];
    roles
        .into_iter()
        .map(|role| TrashValue {
            deleted_at: 1_700_000_006,
            role,
        })
        .collect()
}

fn secret_texts() -> Vec<SecretText> {
    vec![SecretText::new("p1"), SecretText::new("")]
}

fn replica_keys() -> Vec<ReplicaKeys> {
    vec![ReplicaKeys {
        encryption: PublicKey(vec![4, 1, 2]),
        signing: PublicKey(vec![4, 3, 4]),
    }]
}

fn removals() -> Vec<Removal> {
    vec![Removal { key_id: KeyId(2) }]
}

fn recovery_recipients() -> Vec<RecoveryRecipient> {
    vec![RecoveryRecipient {
        key_id: KeyId(1),
        key_fingerprint: [7; 16],
    }]
}

/// Signal entry of every list, and a dismissal of every kind.
fn signal_entries() -> Vec<SignalEntry> {
    // A new list or kind fails to compile here until a sample holds it.
    let _ = |entry: SignalEntry| match entry {
        SignalEntry::Unknown(_)
        | SignalEntry::Accepted(_)
        | SignalEntry::Rename(_)
        | SignalEntry::Dismissed(_) => {},
    };
    let _ = |kind: DismissKind| match kind {
        DismissKind::Rejection | DismissKind::Rename => {},
    };
    let mut entries = vec![
        SignalEntry::Unknown(UnknownEntry {
            rp_id: "example.com".to_string(),
            credential_id: "AQID".to_string(),
            at: 1_700_000_001,
        }),
        SignalEntry::Accepted(AcceptedEntry {
            rp_id: "example.com".to_string(),
            user_handle: "CQ".to_string(),
            credential_ids: vec!["AQID".to_string(), "BAUG".to_string()],
            at: 1_700_000_002,
        }),
        SignalEntry::Rename(RenameEntry {
            rp_id: "example.com".to_string(),
            user_handle: "CQ".to_string(),
            name: "ada".to_string(),
            at: 1_700_000_003,
        }),
    ];
    entries.extend(
        [DismissKind::Rejection, DismissKind::Rename]
            .into_iter()
            .map(|kind| {
                SignalEntry::Dismissed(DismissEntry {
                    rp_id: "example.com".to_string(),
                    credential_id: "AQID".to_string(),
                    kind,
                    at: 1_700_000_004,
                })
            }),
    );
    entries
}

/// Samples of every register value type with a serde form of its own.
fn sync_snapshot() -> SchemaSnapshot {
    let mut snapshot = SchemaSnapshot::new(SCHEMA, SYNC_FORMAT_VERSION);
    add(&mut snapshot, "folder-value", folder_values());
    add(&mut snapshot, "section-value", section_values());
    add(&mut snapshot, "website-value", website_values());
    add(&mut snapshot, "placement", placements());
    // An object with a history kind this build does not know is kept as is.
    add_open(&mut snapshot, "history-value", history_values(), &["kind"]);
    add(&mut snapshot, "trash-value", trash_values());
    add(&mut snapshot, "secret-text", secret_texts());
    add(&mut snapshot, "replica-keys", replica_keys());
    add(&mut snapshot, "removal", removals());
    add(&mut snapshot, "recovery-recipient", recovery_recipients());
    add(&mut snapshot, "signal-entry", signal_entries());
    snapshot
}

#[test]
fn sync_value_types_match_snapshot_of_their_format() {
    sync_snapshot().check();
}

#[test]
fn every_sample_round_trips_through_json_and_cbor_unchanged() {
    // The checks run as each sample is added.
    sync_snapshot();
}

#[test]
fn value_type_change_without_format_bump_fails_snapshot() {
    let mut snapshot = sync_snapshot();
    snapshot.edit("history-value", |text| {
        text.replace("\"at\"", "\"replaced_at\"")
    });

    let error = snapshot.compare().unwrap_err();

    assert!(error.contains("without a version bump"), "{error}");
    assert!(error.contains("history-value"), "{error}");
}

#[test]
fn uuid_is_cbor_byte_string_of_its_16_bytes() {
    let id = Uuid::from_u128(0x0011_2233_4455_6677_8899_aabb_ccdd_eeff);
    // Major type 2, byte string, with length 16.
    let mut expected = vec![0x50];
    expected.extend(id.as_bytes());
    assert_eq!(cbor(&id), expected);
    assert_eq!(cbor(&Some(id)), expected);
    assert_eq!(serde_json::to_string(&id).unwrap(), format!("\"{id}\""));
}

#[test]
fn bytes_are_cbor_byte_strings_and_json_base64() {
    let key = PublicKey(vec![4, 1, 2]);
    assert_eq!(cbor(&key), [0x43, 4, 1, 2]);
    assert_eq!(serde_json::to_string(&key).unwrap(), "\"BAEC\"");

    let fingerprint = [7u8; 16];
    let recipient = RecoveryRecipient {
        key_id: KeyId(1),
        key_fingerprint: fingerprint,
    };
    let mut expected = vec![0x50];
    expected.extend(fingerprint);
    let bytes = cbor(&recipient);
    assert!(bytes.windows(17).any(|w| w == expected.as_slice()));
}

#[test]
fn secret_text_zeroizes_on_drop_and_serializes_as_plain_string() {
    fn zeroizes_on_drop<T: ZeroizeOnDrop>() {}
    zeroizes_on_drop::<SecretText>();
    let text = SecretText::new("p1");
    assert_eq!(serde_json::to_string(&text).unwrap(), "\"p1\"");
    // Major type 3, text string, with length 2.
    assert_eq!(cbor(&text), [0x62, b'p', b'1']);
}
