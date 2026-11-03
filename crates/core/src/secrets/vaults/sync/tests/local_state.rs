//! Local sync state envelope and the staged file.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::Deserialize;
use serde_json::json;
use serde_json::value::RawValue;
use zeroize::Zeroizing;

use super::id;
use super::state_file::{VAULT, WRITER, full_state, key, keyring};
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::format::signing::{TestSigner, VaultSigner};
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::keys::{SyncKeyring, TestKeyWrapper};
use crate::secrets::vaults::sync::local_state::{
    LocalStateError, LocalSyncState, PinSource, PinnedKeys,
};
use crate::secrets::vaults::sync::model::{KeyId, PublicKey};
use crate::secrets::vaults::sync::state_file::padded::PaddedBody;
use crate::secrets::vaults::sync::state_file::{
    Damage, StateFile, StateFileError, StateHash, StateSource,
};

/// Local sync state of [`full_state`] with every header field set, sealed
/// under [`keyring`], and its padded body.
fn local() -> (LocalSyncState, Zeroizing<Vec<u8>>) {
    let state = full_state();
    let padded = PaddedBody::of(&state).unwrap();
    let mut local = LocalSyncState::new(VAULT, WRITER, KeyId(1));
    local.generation = 44;
    local.published_context = state.context.clone();
    local.staged_context = Some(state.context.clone());
    local.staged_hash = Some(StateHash([1; 32]));
    local.stopped_build = Some("build-a".to_string());
    local.override_build = Some("build-b".to_string());
    local.sync_keys = keyring().wrap(&TestKeyWrapper).unwrap();
    local.pinned_keys.insert(
        ReplicaId(id(2)),
        PinnedKeys {
            source: PinSource::Pairing,
            encryption: PublicKey(vec![4, 1]),
            signing: PublicKey(vec![4, 2]),
        },
    );
    local.seal(&padded, &keyring()).unwrap();
    (local, padded)
}

/// File contents of [`local`], signed by the test device key.
fn contents() -> String {
    local().0.to_file_contents(&TestSigner::device()).unwrap()
}

/// Parse `contents` under the test device key.
fn parse(contents: &str) -> Result<LocalSyncState, LocalStateError> {
    LocalSyncState::parse(contents, &TestSigner::device())
}

/// Raw state JSON of the file contents `contents`.
fn raw_state(contents: &str) -> String {
    #[derive(Deserialize)]
    struct Envelope<'a> {
        #[serde(borrow)]
        state: &'a RawValue,
    }
    let envelope: Envelope = serde_json::from_str(contents).unwrap();
    envelope.state.get().to_string()
}

/// File contents holding the raw state JSON `state_json`, signed by the test
/// device key.
fn signed(state_json: &str) -> String {
    let message = [&b"ap-local-state-v1:"[..], state_json.as_bytes()].concat();
    let signature = B64.encode(TestSigner::device().sign(&message).unwrap());
    format!("{{\"signature\": \"{signature}\", \"state\": {state_json}}}")
}

/// `contents` with the first `from` replaced by `to`.
fn replaced(contents: &str, from: &str, to: &str) -> String {
    let changed = contents.replacen(from, to, 1);
    assert_ne!(changed, contents, "{from} is not in the file");
    changed
}

#[test]
fn local_state_round_trips_and_its_body_equals_staged_file_body() {
    let dir = tempfile::tempdir().unwrap();
    let (local, padded) = local();
    local.save(dir.path(), &TestSigner::device()).unwrap();

    let loaded = LocalSyncState::load(dir.path(), VAULT, &TestSigner::device()).unwrap();

    assert_eq!(loaded, local);
    assert_eq!(loaded.open(&keyring()).unwrap(), full_state());
    let keys = SyncKeyring::unwrap(&loaded.sync_keys, &TestKeyWrapper).unwrap();
    assert_eq!(keys.keys()[0].0, KeyId(1));
    assert_eq!(keys.keys()[0].1.fingerprint(), key().fingerprint());

    let staged = local.staged_file(&padded, &keyring()).unwrap();
    let source = StateSource {
        vault_id: VAULT,
        replica_id: WRITER,
        hash: StateHash::of(&staged),
    };
    let (header, staged_padded) = StateFile::open(&staged, &source, &keyring()).unwrap();
    assert_eq!(header.key_id, KeyId(1));
    assert_eq!(*loaded.open_padded(&keyring()).unwrap(), *staged_padded);
    assert_eq!(*staged_padded, *padded);
    let (_, state) = StateFile::decode(&staged, &source, &keyring()).unwrap();
    assert_eq!(state, full_state());
}

#[test]
fn local_files_are_named_by_short_vault_id_under_sync() {
    let root = std::path::Path::new("/app");
    let vault_id = ShortId::encode_uuid(VAULT);

    assert_eq!(
        LocalSyncState::path(root, VAULT),
        root.join("sync").join(format!("{vault_id}.state.json"))
    );
    assert_eq!(
        LocalSyncState::staged_path(root, VAULT),
        root.join("sync").join(format!("{vault_id}.staged.apstate"))
    );
}

#[test]
fn local_state_json_has_fields_of_plan() {
    let state: serde_json::Value = serde_json::from_str(&raw_state(&contents())).unwrap();
    let mut fields: Vec<&str> = state
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();

    assert_eq!(
        fields,
        [
            "body",
            "format_version",
            "generation",
            "key_id",
            "leaving",
            "nonce",
            "override_build",
            "pinned_keys",
            "published_context",
            "replica_id",
            "staged_context",
            "staged_hash",
            "stopped_build",
            "sync_keys",
            "vault_id",
            "view_version",
        ]
    );
    assert_eq!(state["staged_hash"], "01".repeat(32));
    assert_eq!(state["vault_id"], VAULT.to_string());
}

#[test]
fn sync_state_with_planted_sync_keys_entry_fails_verification() {
    let contents = contents();
    let planted = replaced(
        &contents,
        "\"sync_keys\": [",
        "\"sync_keys\": [{ \"key_id\": 9, \"wrapped\": \"cGxhbnRlZA==\" }, ",
    );

    assert!(matches!(
        parse(&planted),
        Err(LocalStateError::SignatureInvalid)
    ));
    // Signed again, the planted entry parses, so only the signature refuses
    // it.
    let resigned = parse(&signed(&raw_state(&planted))).unwrap();
    assert_eq!(resigned.sync_keys.len(), 2);
}

#[test]
fn changed_signed_header_field_fails_verification() {
    let contents = contents();
    let staged_hash = "01".repeat(32);
    let other_hash = "02".repeat(32);
    let cases = [
        ("generation", "\"generation\": 44", "\"generation\": 45"),
        ("leaving", "\"leaving\": false", "\"leaving\": true"),
        ("stopped_build", "\"build-a\"", "\"build-x\""),
        ("override_build", "\"build-b\"", "\"build-y\""),
        ("staged_hash", &staged_hash[..], &other_hash[..]),
        (
            "published_context",
            "\"published_context\": {",
            "\"published_context\": { \"00000000-0000-0000-0000-0000000000ff\": 9,",
        ),
    ];
    for (field, from, to) in cases {
        let changed = replaced(&contents, from, to);
        assert!(
            matches!(parse(&changed), Err(LocalStateError::SignatureInvalid)),
            "{field}"
        );
        let resigned = parse(&signed(&raw_state(&changed)));
        assert!(resigned.is_ok(), "{field}: {resigned:?}");
    }
}

#[test]
fn changed_generation_also_fails_body_aad() {
    let changed = replaced(&contents(), "\"generation\": 44", "\"generation\": 45");
    let resigned = parse(&signed(&raw_state(&changed))).unwrap();

    assert!(matches!(
        resigned.open(&keyring()),
        Err(LocalStateError::Decryption)
    ));
}

#[test]
fn local_sync_state_cannot_be_read_as_peer_state_file() {
    let (local, _) = local();
    let value = serde_json::to_value(&local).unwrap();
    let header = json!({
        "format_version": 1,
        "vault_id": VAULT,
        "replica_id": WRITER,
        "key_id": 1,
        "key_fingerprint": B64.encode(key().fingerprint().0),
        "nonce": value["nonce"],
    });
    let header = serde_json::to_vec(&header).unwrap();
    let body = B64.decode(value["body"].as_str().unwrap()).unwrap();
    let len = (header.len() as u32).to_be_bytes();
    let bytes = [&b"APST"[..], &len, &header, &body].concat();
    let source = StateSource {
        vault_id: VAULT,
        replica_id: WRITER,
        hash: StateHash::of(&bytes),
    };

    assert_eq!(
        StateFile::decode(&bytes, &source, &keyring()),
        Err(StateFileError::Quarantine(Damage::Decryption))
    );
}

#[test]
fn header_with_unknown_field_fails() {
    let state_json = raw_state(&contents()).replacen('{', "{\n  \"unknown_field\": 1,", 1);

    let error = parse(&signed(&state_json)).unwrap_err();

    assert!(
        matches!(&error, LocalStateError::Malformed(message) if message.contains("unknown field")),
        "{error}"
    );
}

#[test]
fn header_with_newer_format_version_is_version_skew() {
    let state_json = replaced(
        &raw_state(&contents()),
        "\"format_version\": 1,",
        "\"format_version\": 2, \"field_of_format_2\": 1,",
    );

    assert!(matches!(
        parse(&signed(&state_json)),
        Err(LocalStateError::VersionSkew(_))
    ));
}

#[test]
fn file_signed_by_random_signer_fails_under_device_signer() {
    let contents = local().0.to_file_contents(&TestSigner::random()).unwrap();

    assert!(matches!(
        parse(&contents),
        Err(LocalStateError::SignatureInvalid)
    ));
}

#[test]
fn envelope_without_signature_or_with_unknown_field_fails() {
    let state_json = raw_state(&contents());
    let unsigned = format!("{{\"state\": {state_json}}}");
    let extra = replaced(&signed(&state_json), "{", "{\"unknown_field\": 1, ");

    for contents in [unsigned, extra] {
        assert!(matches!(
            parse(&contents),
            Err(LocalStateError::Envelope(_))
        ));
    }
}

#[test]
fn missing_file_and_body_under_key_keyring_lacks_fail() {
    let dir = tempfile::tempdir().unwrap();

    assert!(matches!(
        LocalSyncState::load(dir.path(), VAULT, &TestSigner::device()),
        Err(LocalStateError::Missing)
    ));
    assert!(matches!(
        local().0.open(&SyncKeyring::default()),
        Err(LocalStateError::KeyMissing(KeyId(1)))
    ));
}
