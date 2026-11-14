//! File records in the sync state: the diff round trip, and the file kind as
//! an older build reads it.

use secrecy::SecretString;
use serde_json::json;

use super::super::apply::reload;
use super::super::view::State;
use super::super::{NOW, session};
use super::*;
use crate::secrets::vaults::files::record::FileKey;
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::sync::diff::LocalEdits;
use crate::secrets::vaults::sync::view::VaultView;

/// File record value whose blob, key, and plaintext hash are `n` in every
/// byte.
fn record_value(n: u8) -> SecretString {
    FileRecord {
        blob: FileHash([n; 32]),
        key: FileKey::from_bytes([n; 32]),
        sha256: FileHash([n; 32]),
        size: u64::from(n),
        name: format!("{n}.bin"),
        mime: None,
    }
    .encode()
    .unwrap()
}

/// Vault with item `item`, which holds credential `doc` of kind `kind` whose
/// value was replaced once, and credential `old` of kind `kind` in the
/// trash. Each value is a file record of its own blob.
fn vault_with_files(kind: &FieldKind) -> Vault {
    let mut vault = Vault::new_for_test();
    vault.add_or_update_item("item", "Item").unwrap();
    for (cred_key, n) in [("doc", 1), ("doc", 2), ("old", 3)] {
        vault
            .add_or_update_item_credential("item", cred_key, "Doc", kind.clone(), record_value(n))
            .unwrap();
    }
    vault.delete_item_credential("item", "old").unwrap();
    vault
}

/// State with the edits of `vault` recorded by replica 1.
fn recorded(vault: &Vault) -> State {
    let mut state = State::default();
    let mut session = session(1);
    let edits = LocalEdits::find(&state, vault, session.replica).unwrap();
    assert!(!edits.is_empty());
    edits.record(&mut state, &mut session, NOW);
    state
}

/// Assert that `vault` has no edits against `state` for replica `n`.
fn assert_no_edits_in(state: &State, vault: &Vault, n: u128) {
    let edits = LocalEdits::find(state, vault, session(n).replica).unwrap();
    assert!(edits.is_empty(), "{:?}", edits.edits());
}

/// Assert that `vault`, also after a save and reload, has no edits against
/// `state` for replica `n`.
fn assert_no_edits(state: &State, vault: &Vault, n: u128) {
    assert_no_edits_in(state, vault, n);
    assert_no_edits_in(state, &reload(vault), n);
}

/// Kinds in the kind registers of the credentials of `state`.
fn kinds(state: &State) -> Vec<FieldKind> {
    state
        .store
        .credentials
        .iter()
        .flat_map(|(_, cred)| cred.kind.values())
        .map(|(_, kind)| kind.value.clone())
        .collect()
}

#[test]
fn file_credentials_recorded_and_applied_to_other_vault_find_no_edits() {
    let vault = vault_with_files(&FieldKind::File);
    let blobs = vault.file_blobs().unwrap();
    assert_eq!(blobs.len(), 3);

    let state = recorded(&vault);

    assert_no_edits(&state, &vault, 1);
    assert_eq!(kinds(&state), [FieldKind::File, FieldKind::File]);
    assert_eq!(blobs::referenced(&state.store), blobs);

    let mut other = Vault::new_for_test();
    VaultView::of(&state).apply(&mut other).unwrap();
    assert_no_edits(&state, &other, 2);
    assert_eq!(other.file_blobs().unwrap(), blobs);
    assert!(other.holds_files());
}

#[test]
fn older_build_keeps_file_kind_as_unknown_and_writes_it_back_unchanged() {
    // An older build reads the file kind as an unknown kind that holds the
    // object. A reload on this build reads it as the file kind, so the vaults
    // of the older build are not reloaded.
    let unknown = FieldKind::Unknown(json!({"type": "file"}));
    let older = vault_with_files(&unknown);

    let state = recorded(&older);

    assert_no_edits_in(&state, &older, 1);
    assert_eq!(kinds(&state), [unknown.clone(), unknown.clone()]);
    // The blobs of an unknown kind are referenced, so they are uploaded and
    // kept.
    assert_eq!(blobs::referenced(&state.store), older.file_blobs().unwrap());
    let mut applied = Vault::new_for_test();
    VaultView::of(&state).apply(&mut applied).unwrap();
    assert_no_edits_in(&state, &applied, 2);

    // The state the older build writes reads as the file kind on this build,
    // and as the same state otherwise.
    let json = serde_json::to_string(&state).unwrap();
    let read: State = serde_json::from_str(&json).unwrap();
    assert_eq!(kinds(&read), [FieldKind::File, FieldKind::File]);
    assert_eq!(serde_json::to_string(&read).unwrap(), json);
    let newer = vault_with_files(&FieldKind::File);
    assert_eq!(blobs::referenced(&read.store), newer.file_blobs().unwrap());
}
