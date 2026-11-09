use ciborium::Value;
use indoc::indoc;
use proptest::prelude::*;
use serde::Serialize;
use uuid::Uuid;

use super::super::generators::Script;
use super::super::view::State;
use super::super::{NOW, id, session};
use super::full_state;
use crate::schema_snapshot::SchemaSnapshot;
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::sync::crdt::{
    ActorId, Ask, CausalContext, Mint, MvRegister, ReplicaId, Versioned, WriteId,
};
use crate::secrets::vaults::sync::model::SYNC_FORMAT_VERSION;
use crate::secrets::vaults::sync::state_file::body::{BodyError, StateBody};

/// Name of the body schema in `snapshots/`.
const SCHEMA: &str = "sync-body";

/// CBOR encoding of `value`.
fn cbor<T: Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).unwrap();
    bytes
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
pub(super) fn field<'v>(value: &'v mut Value, name: &str) -> &'v mut Value {
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
pub(super) fn edited(edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let bytes = StateBody::encode(&full_state()).unwrap();
    let mut value: Value = ciborium::from_reader(&bytes[..]).unwrap();
    edit(&mut value);
    cbor(&value)
}

/// CBOR of the full state with an unknown field added to the map that `find`
/// returns.
pub(super) fn with_unknown_field(find: impl FnOnce(&mut Value) -> &mut Value) -> Vec<u8> {
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
