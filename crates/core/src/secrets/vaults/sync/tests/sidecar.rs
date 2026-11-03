//! Status sidecar.

use std::fs;

use uuid::Uuid;

use super::state_file::{VAULT, WRITER};
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::state_file::StateHash;

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
