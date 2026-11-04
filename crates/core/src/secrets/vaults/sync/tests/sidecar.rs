//! Status sidecar.

use std::fs;
use std::path::PathBuf;

use uuid::Uuid;

use super::state_file::{VAULT, WRITER};
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::state_file::StateHash;
use crate::secrets::vaults::sync::transport::TransportRoot;

/// Sidecar with a publish, joined files of two replicas, and a quarantined
/// file.
fn filled() -> Sidecar {
    let mut sidecar = Sidecar {
        last_publish: Some(StateHash::of(b"published")),
        ..Sidecar::default()
    };
    sidecar.record_joined(WRITER, StateHash::of(b"own"));
    sidecar.record_joined(ReplicaId(Uuid::from_u128(2)), StateHash::of(b"peer"));
    sidecar.quarantine(
        WRITER,
        "name.apstate".to_string(),
        StateHash::of(b"torn"),
        "body fails to decrypt".to_string(),
    );
    sidecar
}

#[test]
fn sidecar_round_trips_at_its_path() {
    let dir = tempfile::tempdir().unwrap();
    let sidecar = filled();

    sidecar.save(dir.path(), VAULT).unwrap();

    let name = format!("{}.json", ShortId::encode_uuid(VAULT));
    assert_eq!(
        Sidecar::path(dir.path(), VAULT),
        dir.path().join("sync").join(name)
    );
    assert_eq!(Sidecar::load(dir.path(), VAULT), sidecar);
    assert!(sidecar.is_joined(WRITER, StateHash::of(b"own")));
    assert!(!sidecar.is_joined(WRITER, StateHash::of(b"peer")));
    assert!(sidecar.is_quarantined(WRITER, "name.apstate", StateHash::of(b"torn")));
    // A later file at the same path with other bytes is not quarantined.
    assert!(!sidecar.is_quarantined(WRITER, "name.apstate", StateHash::of(b"good")));
}

#[test]
fn sidecar_that_is_missing_or_fails_to_parse_is_read_as_empty() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(Sidecar::load(dir.path(), VAULT), Sidecar::default());

    let path = Sidecar::path(dir.path(), VAULT);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let saved = serde_json::to_string(&filled()).unwrap();
    for contents in [
        "not json".to_string(),
        saved.replacen('{', "{\"unknown\": 1,", 1),
        saved.replace(&StateHash::of(b"own").to_string(), "abc"),
    ] {
        fs::write(&path, &contents).unwrap();
        assert_eq!(
            Sidecar::load(dir.path(), VAULT),
            Sidecar::default(),
            "{contents}"
        );
    }
}

#[test]
fn joined_hashes_are_kept_only_while_listed() {
    let mut sidecar = filled();
    let own = StateHash::of(b"own");
    let newer = StateHash::of(b"newer");
    sidecar.record_joined(WRITER, newer);

    assert!(!sidecar.retain_joined(WRITER, &[own, newer]));
    assert!(sidecar.retain_joined(WRITER, &[newer]));
    assert!(!sidecar.is_joined(WRITER, own));
    assert!(sidecar.is_joined(WRITER, newer));
    assert!(sidecar.retain_joined(WRITER, &[]));
    assert!(!sidecar.joined.contains_key(&WRITER));
}

#[test]
fn sidecar_with_root_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    for (root, json) in [
        (TransportRoot::ICloud, r#"{"kind":"ICloud"}"#),
        (
            TransportRoot::Folder {
                path: PathBuf::from("/Users/me/Dropbox/Vaults"),
            },
            r#"{"kind":"Folder","path":"/Users/me/Dropbox/Vaults"}"#,
        ),
    ] {
        let sidecar = Sidecar {
            transport: Some(root),
            ..filled()
        };
        sidecar.save(dir.path(), VAULT).unwrap();

        assert_eq!(Sidecar::load(dir.path(), VAULT), sidecar);
        let saved: serde_json::Value =
            serde_json::from_slice(&fs::read(Sidecar::path(dir.path(), VAULT)).unwrap()).unwrap();
        assert_eq!(
            saved["transport"],
            serde_json::from_str::<serde_json::Value>(json).unwrap()
        );
    }

    // A root of an unknown kind, or with an unknown field, fails the
    // sidecar.
    let path = Sidecar::path(dir.path(), VAULT);
    for root in [
        r#"{"kind":"Dropbox"}"#,
        r#"{"kind":"ICloud","path":"/"}"#,
        r#"{"kind":"Folder"}"#,
    ] {
        let mut saved = serde_json::to_value(filled()).unwrap();
        saved["transport"] = serde_json::from_str(root).unwrap();
        fs::write(&path, saved.to_string()).unwrap();
        assert_eq!(
            Sidecar::load(dir.path(), VAULT),
            Sidecar::default(),
            "{root}"
        );
    }
}

#[test]
fn sidecar_with_no_transport_field_parses_with_no_root() {
    let dir = tempfile::tempdir().unwrap();
    let mut saved = serde_json::to_value(filled()).unwrap();
    // A 6c sidecar has no `transport` field.
    saved.as_object_mut().unwrap().remove("transport").unwrap();
    let path = Sidecar::path(dir.path(), VAULT);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, saved.to_string()).unwrap();

    let loaded = Sidecar::load(dir.path(), VAULT);
    assert_eq!(loaded, filled());
    assert_eq!(loaded.transport, None);
}
