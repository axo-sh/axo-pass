//! State file body and state file format.

use std::io::Write;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ciborium::Value;
use flate2::Compression;
use flate2::write::DeflateEncoder;
use indoc::indoc;
use proptest::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::generators::Script;
use super::view::State;
use super::{NOW, id, session};
use crate::schema_snapshot::SchemaSnapshot;
use crate::secrets::vaults::autofill::item::{MatchKind, Role};
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::passkey::signals::{SignalEntry, UnknownEntry};
use crate::secrets::vaults::sync::crdt::{
    ActorId, Ask, CausalContext, Mint, MvRegister, ReplicaId, Versioned, WriteId,
};
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

/// Name of the body schema in `snapshots/`.
const SCHEMA: &str = "sync-body";

/// CBOR encoding of `value`.
fn cbor<T: Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).unwrap();
    bytes
}

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

#[test]
fn register_from_values_matches_writes() {
    let mut one = session(1);
    let mut state = State::default();
    let first = one.mint(&mut state, NOW);
    let second = one.mint(&mut state, NOW);
    let mut written = MvRegister::<String, Ask>::default();
    written.write(&second, "b".to_string());
    written.write_repair(&first, "a".to_string());

    let values = written.values().map(|(id, value)| (id, value.clone()));
    let built = MvRegister::<String, Ask>::from_values(values);

    assert_eq!(built, written);
    assert_eq!(built.values().count(), 2);
    assert_eq!(
        MvRegister::<String, Ask>::from_values([]),
        MvRegister::default()
    );
}

#[test]
fn register_from_values_keeps_later_value_of_repeated_write_id() {
    let id = WriteId {
        actor: ActorId(id(1)),
        seq: 1,
    };
    let value = |value: &str| Versioned {
        counter: 2,
        written_at: NOW,
        value: value.to_string(),
    };

    let register = MvRegister::<String, Ask>::from_values([(id, value("a")), (id, value("b"))]);

    assert_eq!(register.get(id), Some(&value("b")));
    assert_eq!(register.values().count(), 1);
}

#[test]
fn context_iter_lists_each_actor_once_in_actor_order() {
    let a = ActorId(id(1));
    let b = ActorId(id(2));
    let mut context = CausalContext::default();
    context.record(WriteId { actor: b, seq: 3 });
    context.record(WriteId { actor: a, seq: 5 });
    context.record(WriteId { actor: b, seq: 1 });

    assert_eq!(context.iter().collect::<Vec<_>>(), [(a, 5), (b, 3)]);
    assert_eq!(CausalContext::default().iter().count(), 0);
}

#[test]
fn full_and_empty_states_round_trip_through_body_unchanged() {
    for state in [full_state(), State::default()] {
        let bytes = StateBody::encode(&state).unwrap();
        assert_eq!(StateBody::decode(&bytes).unwrap(), state);
    }
}

#[test]
fn ids_in_body_are_16_byte_strings() {
    let state = full_state();
    let bytes = StateBody::encode(&state).unwrap();
    for actor in state.actors.keys() {
        let mut expected = vec![0x50];
        expected.extend(actor.0.as_bytes());
        assert!(bytes.windows(17).any(|w| w == expected.as_slice()));
    }
}

#[test]
fn actor_without_info_fails_encode_decode() {
    let actor = ActorId(id(5));
    let mut state = State::default();
    state.context.record(WriteId { actor, seq: 1 });

    let error = BodyError::ActorWithoutInfo(actor);
    assert_eq!(StateBody::encode(&state), Err(error.clone()));
    assert_eq!(StateBody::decode(&cbor(&state)), Err(error));
}

#[test]
fn body_with_write_id_above_its_context_fails_to_decode() {
    let mut one = session(1);
    let mut state = State::default();
    let m = one.mint(&mut state, NOW);
    let ahead = Mint {
        write_id: WriteId {
            seq: 2,
            ..m.write_id
        },
        ..m
    };
    state.store.name.write(&ahead, Some("Personal".to_string()));

    assert_eq!(
        StateBody::decode(&cbor(&state)),
        Err(BodyError::NotCausallyClosed(ahead.write_id))
    );
}

/// Value of the field `name` in the CBOR map `value`.
fn field<'v>(value: &'v mut Value, name: &str) -> &'v mut Value {
    let Value::Map(fields) = value else {
        panic!("not a map: {value:?}");
    };
    fields
        .iter_mut()
        .find(|(key, _)| key.as_text() == Some(name))
        .map(|(_, value)| value)
        .unwrap()
}

/// Element `n` of the CBOR array or map `value`.
fn nth(value: &mut Value, n: usize) -> &mut Value {
    match value {
        Value::Array(values) => &mut values[n],
        Value::Map(entries) => &mut entries[n].1,
        _ => panic!("not an array or map: {value:?}"),
    }
}

/// CBOR of the full state with `edit` applied to its decoded CBOR value.
fn edited(edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let bytes = StateBody::encode(&full_state()).unwrap();
    let mut value: Value = ciborium::from_reader(&bytes[..]).unwrap();
    edit(&mut value);
    cbor(&value)
}

/// CBOR of the full state with an unknown field added to the map that `find`
/// returns.
fn with_unknown_field(find: impl FnOnce(&mut Value) -> &mut Value) -> Vec<u8> {
    edited(|value| {
        let Value::Map(fields) = find(value) else {
            panic!("not a map");
        };
        fields.push((
            Value::Text("unknown_field".to_string()),
            Value::Integer(1.into()),
        ));
    })
}

/// CBOR of the full state with the first entry of the array or map that
/// `find` returns listed twice.
fn with_repeated_entry(find: impl FnOnce(&mut Value) -> &mut Value) -> Vec<u8> {
    edited(|value| match find(value) {
        Value::Array(values) => values.push(values[0].clone()),
        Value::Map(entries) => entries.push(entries[0].clone()),
        other => panic!("not an array or map: {other:?}"),
    })
}

#[test]
fn body_with_unknown_field_fails_as_version_skew() {
    let cases: [(&str, Vec<u8>); 5] = [
        ("body", with_unknown_field(|v| v)),
        ("store", with_unknown_field(|v| field(v, "store"))),
        (
            "actor info",
            with_unknown_field(|v| nth(field(v, "actors"), 0)),
        ),
        (
            "item",
            with_unknown_field(|v| nth(field(field(v, "store"), "items"), 0)),
        ),
        (
            "folder value",
            with_unknown_field(|v| {
                let folders = field(field(v, "store"), "folders");
                nth(nth(nth(folders, 0), 0), 4)
            }),
        ),
    ];
    for (case, bytes) in cases {
        let error = StateBody::decode(&bytes).unwrap_err();
        assert!(error.is_version_skew(), "{case}: {error}");
    }
}

#[test]
fn malformed_body_fails_as_malformed_not_version_skew() {
    let bytes = StateBody::encode(&full_state()).unwrap();
    let truncated = bytes[..bytes.len() - 1].to_vec();
    let mut trailing = bytes.clone();
    trailing.push(0);
    let short_entry = edited(|v| {
        let Value::Array(entry) = nth(field(field(v, "store"), "name"), 0) else {
            panic!("entry is not an array");
        };
        entry.pop();
    });

    let cases: [(&str, Vec<u8>); 7] = [
        ("truncated", truncated),
        ("trailing", trailing),
        ("short entry", short_entry),
        (
            "repeated write id",
            with_repeated_entry(|v| field(field(v, "store"), "name")),
        ),
        (
            "repeated map key",
            with_repeated_entry(|v| field(field(v, "store"), "items")),
        ),
        (
            "repeated context actor",
            with_repeated_entry(|v| field(v, "context")),
        ),
        (
            "repeated actor",
            with_repeated_entry(|v| field(v, "actors")),
        ),
    ];
    for (case, bytes) in cases {
        let error = StateBody::decode(&bytes).unwrap_err();
        assert!(matches!(error, BodyError::Malformed(_)), "{case}: {error}");
    }
}

/// Example body of "State file format" in `07-transport.md`, in the plain id
/// form, with full ids, a kind object, and base64 bytes.
const EXAMPLE: &str = indoc! {r#"
    {
      "context": {
        "00000000-0000-0000-0000-0000000000a0": 3,
        "00000000-0000-0000-0000-0000000000b0": 5,
        "00000000-0000-0000-0000-0000000000a1": 1
      },
      "actors": {
        "00000000-0000-0000-0000-0000000000a0": { "replica": "00000000-0000-0000-0000-00000000000a", "started_at": 100 },
        "00000000-0000-0000-0000-0000000000b0": { "replica": "00000000-0000-0000-0000-00000000000b", "started_at": 200 },
        "00000000-0000-0000-0000-0000000000a1": { "replica": "00000000-0000-0000-0000-00000000000a", "started_at": 300 }
      },
      "store": {
        "name": [ ["00000000-0000-0000-0000-0000000000a0", 1, 1, 100, "Personal"] ],
        "replica_names": {
          "00000000-0000-0000-0000-00000000000a": [ ["00000000-0000-0000-0000-0000000000a0", 1, 1, 100, "MacBook Pro"] ],
          "00000000-0000-0000-0000-00000000000b": [ ["00000000-0000-0000-0000-0000000000b0", 1, 4, 200, "iMac"] ]
        },
        "replica_keys": {
          "00000000-0000-0000-0000-00000000000a": [ ["00000000-0000-0000-0000-0000000000a0", 1, 1, 100, { "encryption": "BAEC", "signing": "BAME" }] ],
          "00000000-0000-0000-0000-00000000000b": [ ["00000000-0000-0000-0000-0000000000b0", 1, 4, 200, { "encryption": "BAEC", "signing": "BAME" }] ]
        },
        "removed": {},
        "left": {},
        "recovery": {
          "age1example": [ ["00000000-0000-0000-0000-0000000000a0", 1, 1, 100, { "key_id": 1, "key_fingerprint": "BwcHBwcHBwcHBwcHBwcHBw==" }] ]
        },
        "folders": {
          "00000000-0000-0000-0000-000000000300": [ ["00000000-0000-0000-0000-0000000000a0", 2, 2, 110, { "title": "Work" }] ]
        },
        "signals": {},
        "items": {
          "00000000-0000-0000-0000-000000000100": {
            "title":    [ ["00000000-0000-0000-0000-0000000000a0", 3, 3, 120, "GitHub"] ],
            "category": [ ["00000000-0000-0000-0000-0000000000a0", 3, 3, 120, "login"] ],
            "key":      [ ["00000000-0000-0000-0000-0000000000a0", 3, 3, 120, "github"] ],
            "folder":   [ ["00000000-0000-0000-0000-0000000000a0", 3, 3, 120, "00000000-0000-0000-0000-000000000300"] ],
            "sections": {
              "00000000-0000-0000-0000-000000000400": [ ["00000000-0000-0000-0000-0000000000b0", 2, 5, 210, { "title": "Recovery" }] ]
            },
            "websites": {
              "https://github.com": [ ["00000000-0000-0000-0000-0000000000a0", 3, 3, 120, { "match": "domain", "position": 0 }] ]
            },
            "username": [ ["00000000-0000-0000-0000-0000000000a0", 3, 3, 120, "00000000-0000-0000-0000-000000000201"] ],
            "password": [ ["00000000-0000-0000-0000-0000000000a0", 3, 3, 120, "00000000-0000-0000-0000-000000000200"] ],
            "totp":     [ ["00000000-0000-0000-0000-0000000000a0", 3, 3, 120, null] ],
            "trashed":  []
          }
        },
        "credentials": {
          "00000000-0000-0000-0000-000000000200": {
            "item":      [ ["00000000-0000-0000-0000-0000000000a0", 3, 3, 120, "00000000-0000-0000-0000-000000000100"] ],
            "title":     [ ["00000000-0000-0000-0000-0000000000a0", 3, 3, 120, "Password"] ],
            "kind":      [ ["00000000-0000-0000-0000-0000000000a0", 3, 3, 120, { "type": "confidential", "multiline": false }] ],
            "key":       [ ["00000000-0000-0000-0000-0000000000a0", 3, 3, 120, "password"] ],
            "placement": [ ["00000000-0000-0000-0000-0000000000a0", 3, 3, 120, {}] ],
            "value": [
              ["00000000-0000-0000-0000-0000000000b0", 5, 8, 230, "p3"],
              ["00000000-0000-0000-0000-0000000000a1", 1, 6, 300, "p2"]
            ],
            "history": {
              "00000000-0000-0000-0000-000000000500": [ ["00000000-0000-0000-0000-0000000000a1", 1, 6, 300, { "value": "p1", "replaced_at": 300 }] ]
            },
            "last_used_day_at": {},
            "trashed": []
          }
        }
      }
    }
"#};

#[test]
fn transport_doc_example_decodes() {
    let example: State = serde_json::from_str(EXAMPLE).unwrap();
    let state = StateBody::decode(&cbor(&example)).unwrap();
    assert_eq!(state, example);

    let a0 = ActorId(Uuid::from_u128(0xa0));
    let b0 = ActorId(Uuid::from_u128(0xb0));
    let a1 = ActorId(Uuid::from_u128(0xa1));
    assert_eq!(
        state.context.iter().collect::<Vec<_>>(),
        [(a0, 3), (a1, 1), (b0, 5)]
    );
    assert_eq!(state.actors[&b0].replica, ReplicaId(Uuid::from_u128(0xb)));
    assert_eq!(state.actors[&a1].started_at, 300);

    let item = state.store.items.get(&Uuid::from_u128(0x100)).unwrap();
    assert_eq!(item.title.ordered()[0].1.value, "GitHub");
    let section = item.sections.get(&Uuid::from_u128(0x400)).unwrap();
    assert_eq!(
        section.ordered()[0].0.write_id,
        WriteId { actor: b0, seq: 2 }
    );

    let credential = state
        .store
        .credentials
        .get(&Uuid::from_u128(0x200))
        .unwrap();
    let values: Vec<&str> = credential
        .value
        .ordered()
        .iter()
        .map(|(_, value)| value.value.0.as_str())
        .collect();
    assert_eq!(values, ["p2", "p3"]);
    assert!(credential.history.get(&Uuid::from_u128(0x500)).is_some());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn generated_state_round_trips_through_body_unchanged(script in Script::strategy()) {
        let state = script.play();
        let bytes = StateBody::encode(&state).unwrap();
        prop_assert_eq!(StateBody::decode(&bytes).unwrap(), state);
    }
}

/// Parse a body sample and serialize it again. A kind with an unknown field
/// reads as `FieldKind::Unknown`, which no sample holds, so it is refused.
fn parse_sample(text: &str) -> Result<String, String> {
    let state: State = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let unknown_kind = state
        .store
        .credentials
        .iter()
        .flat_map(|(_, credential)| credential.kind.values())
        .any(|(_, kind)| matches!(kind.value, FieldKind::Unknown(_)));
    if unknown_kind {
        return Err("sample holds an unknown kind".to_string());
    }
    serde_json::to_string_pretty(&state).map_err(|e| e.to_string())
}

/// Full and minimal body samples in their JSON reading form.
fn body_snapshot() -> SchemaSnapshot {
    let mut snapshot = SchemaSnapshot::new(SCHEMA, SYNC_FORMAT_VERSION);
    for (name, state) in [
        ("full-body", full_state()),
        ("minimal-body", State::default()),
    ] {
        let text = serde_json::to_string_pretty(&state).unwrap();
        snapshot.add_text(name, text, &[], parse_sample);
    }
    snapshot
}

#[test]
fn state_body_matches_snapshot_of_its_format() {
    body_snapshot().check();
}

#[test]
fn state_body_change_without_format_bump_fails_snapshot() {
    let mut snapshot = body_snapshot();
    snapshot.edit("full-body", |text| text.replace("\"context\"", "\"seen\""));

    let error = snapshot.compare().unwrap_err();

    assert!(error.contains("without a version bump"), "{error}");
    assert!(error.contains("full-body"), "{error}");
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
fn nonzero_padding_byte_fails() {
    let mut padded = PaddedBody::of(&full_state()).unwrap();
    *padded.last_mut().unwrap() = 1;

    assert_eq!(
        decode(&file_of(&padded)),
        Err(StateFileError::Quarantine(Damage::Padding(
            PaddingError::NonzeroPadding
        )))
    );
}

#[test]
fn length_prefix_past_end_of_plaintext_fails() {
    let mut padded = PaddedBody::of(&full_state()).unwrap();
    let past_end = (padded.len() as u32 - 3).to_be_bytes();
    padded[..4].copy_from_slice(&past_end);

    for padded in [&padded[..], &padded[..3]] {
        assert_eq!(
            decode(&file_of(padded)),
            Err(StateFileError::Quarantine(Damage::Padding(
                PaddingError::LengthPrefix
            )))
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
