//! Status sidecar.

use std::fs;
use std::path::PathBuf;

use uuid::Uuid;

use super::load::{Fixture, GENERATION};
use super::state_file::{VAULT, WRITER};
use crate::secrets::vaults::Error;
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::local_state::LocalSyncState;
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
fn sidecar_that_is_missing_or_fails_to_parse_read_as_empty() {
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
fn joined_hashes_kept_only_while_listed() {
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
        (TransportRoot::ICloud {}, r#"{"kind":"ICloud"}"#),
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

#[test]
fn unparsable_sidecar_keeps_root_with_valid_transport() {
    let dir = tempfile::tempdir().unwrap();
    let path = Sidecar::path(dir.path(), VAULT);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let root = TransportRoot::Folder {
        path: PathBuf::from("/Users/me/Dropbox/Vaults"),
    };
    let saved = serde_json::to_value(Sidecar {
        transport: Some(root.clone()),
        ..filled()
    })
    .unwrap();
    let with = |field: &str, value: serde_json::Value| {
        let mut saved = saved.clone();
        saved[field] = value;
        saved.to_string()
    };
    for (contents, kept) in [
        // A field of a later build.
        (with("unknown", 1.into()), Some(root.clone())),
        (
            saved
                .to_string()
                .replace(&StateHash::of(b"own").to_string(), "abc"),
            Some(root),
        ),
        // A root of an unknown kind, or with an unknown field.
        (
            with("transport", serde_json::json!({"kind": "Dropbox"})),
            None,
        ),
        (
            with(
                "transport",
                serde_json::json!({"kind": "ICloud", "path": "/"}),
            ),
            None,
        ),
        ("not json".to_string(), None),
        ("[1, 2]".to_string(), None),
    ] {
        fs::write(&path, &contents).unwrap();
        let expected = Sidecar {
            transport: kept,
            ..Sidecar::default()
        };
        assert_eq!(Sidecar::load(dir.path(), VAULT), expected, "{contents}");
    }
}

#[test]
fn sidecar_that_cannot_be_read_fails_with_read_error() {
    let dir = tempfile::tempdir().unwrap();
    // A directory at the path of the sidecar cannot be read as a file.
    fs::create_dir_all(Sidecar::path(dir.path(), VAULT)).unwrap();

    assert!(matches!(
        Sidecar::read(dir.path(), VAULT),
        Err(Error::SyncStateReadError(_))
    ));
}

#[test]
fn sidecar_that_cannot_be_read_fails_transaction() {
    let fx = Fixture::synced();
    fx.put_state(GENERATION);
    let path = Sidecar::path(&fx.root, fx.id());
    fs::create_dir_all(&path).unwrap();
    let before = fx.on_disk();

    let result = fx.add_item();

    assert!(matches!(result, Err(Error::SyncStateReadError(_))));
    assert_eq!(fx.on_disk(), before);
    assert!(!LocalSyncState::staged_path(&fx.root, fx.id()).exists());
    assert!(path.is_dir());
}
