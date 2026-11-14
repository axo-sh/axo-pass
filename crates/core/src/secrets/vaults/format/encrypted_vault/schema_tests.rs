//! Schema snapshot of vault format [`VAULT_FORMAT`]: the vault file and the
//! plaintext of every blob kind.
//!
//! Samples are built from struct literals, and enums are listed next to an
//! exhaustive match, so a new field or variant fails to compile here until a
//! sample holds it. Each struct has a full sample with every field set and a
//! minimal sample with every optional field at its default.

use serde_json::json;

use super::*;
use crate::schema_snapshot::SchemaSnapshot;
use crate::secrets::vaults::autofill::item::{MatchKind, Role, Website};
use crate::secrets::vaults::files::record::{FileHash, FileKey, FileRecord};
use crate::secrets::vaults::model::fields::{FieldKind, TextField};
use crate::secrets::vaults::model::history::HistoryKind;
use crate::secrets::vaults::model::{VaultFolderMetadata, VaultSectionMetadata};
use crate::secrets::vaults::passkey::signals::SignalStore;

/// Name of the vault schema in `snapshots/`.
const SCHEMA: &str = "vault-format";

/// Fixed id `n`. Its short id is 21 `1`s and the base58 digit of `n`.
fn id(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

/// Blob with fixed bytes. The bytes of a saved blob are random.
fn blob<T>() -> EncryptedBlob<T> {
    serde_json::from_value(json!("AAAAAAAAAAAAAAAAAAAAAAAA")).unwrap()
}

/// History entry with id `n`, with a value if `has_value`.
fn history_entry(n: u128, has_value: bool) -> HistoryEntry {
    HistoryEntry {
        id: id(n),
        metadata: blob(),
        value: has_value.then(blob),
    }
}

fn credential(history: Vec<HistoryEntry>) -> EncryptedVaultItemCredential {
    EncryptedVaultItemCredential {
        metadata: blob(),
        value: blob(),
        history,
    }
}

/// Item with every field set. Ids start at `n`.
fn full_item(n: u128) -> EncryptedVaultItem {
    EncryptedVaultItem {
        metadata: blob(),
        autofill: Some(blob()),
        credentials: BTreeMap::from([(id(n), credential(vec![history_entry(n + 1, true)]))]),
        deleted: BTreeMap::from([(
            id(n + 2),
            DeletedCredential {
                credential: credential(vec![history_entry(n + 3, false)]),
                info: blob(),
            },
        )]),
    }
}

fn full_vault() -> EncryptedVault {
    EncryptedVault {
        id: id(1),
        key: "personal".to_string(),
        name: Some("Personal".to_string()),
        generation: 3,
        replica_id: Some(id(2)),
        file_key: VaultFileKey::new(vec![0; 3]),
        metadata: Some(blob()),
        items: BTreeMap::from([(id(3), full_item(4))]),
        deleted: BTreeMap::from([(
            id(8),
            DeletedItem {
                item: full_item(9),
                info: blob(),
            },
        )]),
    }
}

fn minimal_vault() -> EncryptedVault {
    let item = EncryptedVaultItem {
        metadata: blob(),
        autofill: None,
        credentials: BTreeMap::from([(id(4), credential(Vec::new()))]),
        deleted: BTreeMap::new(),
    };
    EncryptedVault {
        id: id(1),
        key: "personal".to_string(),
        name: None,
        generation: 0,
        replica_id: None,
        file_key: VaultFileKey::new(vec![0; 3]),
        metadata: None,
        items: BTreeMap::from([(id(3), item)]),
        deleted: BTreeMap::new(),
    }
}

/// Contents of a vault file holding `vault`, with a fixed signature.
fn file_text(signature: Option<Vec<u8>>, vault: &EncryptedVault) -> String {
    let vault_json = RawValue::from_string(vault.to_vault_json().unwrap()).unwrap();
    let envelope = VaultEnvelope {
        format: VAULT_FORMAT,
        signature,
        vault: &vault_json,
    };
    serde_json::to_string_pretty(&envelope).unwrap()
}

/// Vault file `text` parsed and written again. The signature is not checked.
fn parse_file(text: &str) -> Result<String, String> {
    let envelope: VaultEnvelope = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let vault: EncryptedVault =
        serde_json::from_str(envelope.vault.get()).map_err(|e| e.to_string())?;
    if envelope.format != VAULT_FORMAT {
        return Err(format!("format {}", envelope.format));
    }
    Ok(file_text(envelope.signature, &vault))
}

fn vault_metadata() -> Vec<VaultMetadata> {
    let full = VaultMetadata {
        folders: vec![
            VaultFolderMetadata {
                id: id(13),
                title: "Folder".to_string(),
                position: Some(1),
            },
            VaultFolderMetadata {
                id: id(14),
                title: "Other".to_string(),
                position: None,
            },
        ],
        passkey_signals: SignalStore::schema_sample_for_test(),
    };
    let minimal = VaultMetadata {
        folders: Vec::new(),
        passkey_signals: SignalStore::new(),
    };
    vec![full, minimal]
}

fn item_metadata() -> Vec<VaultItemMetadata> {
    let full = VaultItemMetadata {
        title: "Item".to_string(),
        key: "item".to_string(),
        folder: Some(id(13)),
        sections: vec![
            VaultSectionMetadata {
                id: id(15),
                title: "Section".to_string(),
                position: Some(1),
            },
            VaultSectionMetadata {
                id: id(16),
                title: "Other".to_string(),
                position: None,
            },
        ],
        category: Some("login".to_string()),
        created_at: 1_700_000_001,
    };
    let minimal = VaultItemMetadata {
        title: "Item".to_string(),
        key: "item".to_string(),
        folder: None,
        sections: Vec::new(),
        category: None,
        created_at: 1_700_000_001,
    };
    vec![full, minimal]
}

fn item_autofill() -> Vec<ItemAutofill> {
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
    let full = ItemAutofill {
        websites: kinds
            .into_iter()
            .map(|match_kind| Website {
                url: "example.com".to_string(),
                match_kind,
            })
            .collect(),
        username: Some(id(17)),
        password: Some(id(18)),
        totp: Some(id(19)),
    };
    let minimal = ItemAutofill {
        websites: Vec::new(),
        username: None,
        password: None,
        totp: None,
    };
    vec![full, minimal]
}

/// Full and minimal credential metadata, then minimal metadata of every
/// field kind.
fn credential_metadata() -> Vec<VaultCredentialMetadata> {
    // A new kind fails to compile here until it is added to `kinds`.
    let _ = |kind: FieldKind| match kind {
        FieldKind::Text(_)
        | FieldKind::Confidential(_)
        | FieldKind::Email
        | FieldKind::Url
        | FieldKind::Phone
        | FieldKind::Date
        | FieldKind::Totp
        | FieldKind::Passkey
        | FieldKind::File
        | FieldKind::Unknown(_) => {},
    };
    let kinds = [
        FieldKind::Text(TextField { multiline: None }),
        FieldKind::Text(TextField {
            multiline: Some(true),
        }),
        FieldKind::Confidential(TextField { multiline: None }),
        FieldKind::Confidential(TextField {
            multiline: Some(false),
        }),
        FieldKind::Email,
        FieldKind::Url,
        FieldKind::Phone,
        FieldKind::Date,
        FieldKind::Totp,
        FieldKind::Passkey,
        FieldKind::File,
        FieldKind::Unknown(json!({"type": "wifi", "ssid": "home"})),
    ];
    let minimal = |kind: FieldKind| VaultCredentialMetadata {
        title: "Password".to_string(),
        key: "password".to_string(),
        kind,
        position: None,
        section: None,
        last_used_day_at: None,
        created_at: 1_700_000_002,
    };
    let full = VaultCredentialMetadata {
        title: "Password".to_string(),
        key: "password".to_string(),
        kind: FieldKind::Confidential(TextField {
            multiline: Some(true),
        }),
        position: Some(2),
        section: Some(id(15)),
        last_used_day_at: Some(1_700_000_000),
        created_at: 1_700_000_002,
    };
    let mut samples = vec![full, minimal(FieldKind::default())];
    samples.extend(kinds.into_iter().map(minimal));
    samples
}

/// History metadata of every history kind.
fn history_metadata() -> Vec<HistoryMetadata> {
    // A new kind fails to compile here until it is added to `kinds`.
    let _ = |kind: HistoryKind| match kind {
        HistoryKind::ValueCreated | HistoryKind::ValueUpdated | HistoryKind::Unknown(_) => {},
    };
    let kinds = [
        HistoryKind::ValueCreated,
        HistoryKind::ValueUpdated,
        HistoryKind::Unknown(json!({"type": "renamed", "from": "Old title"})),
    ];
    kinds
        .into_iter()
        .map(|kind| HistoryMetadata {
            at: 1_700_000_005,
            kind,
        })
        .collect()
}

/// Deleted info without a role, then with every role.
fn deleted_info() -> Vec<DeletedInfo> {
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
        .map(|role| DeletedInfo {
            deleted_at: 1_700_000_006,
            role,
        })
        .collect()
}

/// Full and minimal file records, the value of a file credential.
fn file_records() -> Vec<FileRecord> {
    let full = FileRecord {
        blob: FileHash([0xab; 32]),
        key: FileKey::from_bytes([7; 32]),
        sha256: FileHash([0x01; 32]),
        size: 12,
        name: "notes.txt".to_string(),
        mime: Some("text/plain".to_string()),
    };
    let minimal = FileRecord {
        blob: FileHash([0xcd; 32]),
        key: FileKey::from_bytes([8; 32]),
        sha256: FileHash([0x02; 32]),
        size: 0,
        name: "empty".to_string(),
        mime: None,
    };
    vec![full, minimal]
}

/// Samples of the vault file and of every blob plaintext struct.
fn vault_snapshot() -> SchemaSnapshot {
    let mut snapshot = SchemaSnapshot::new(SCHEMA, VAULT_FORMAT);
    for (name, vault) in [
        ("vault-file-full", full_vault()),
        ("vault-file-minimal", minimal_vault()),
    ] {
        let text = file_text(Some(vec![0; 3]), &vault);
        snapshot.add_text(name, text, &[], parse_file);
    }
    snapshot.add("vault-metadata", &vault_metadata(), &[]);
    snapshot.add("item-metadata", &item_metadata(), &[]);
    snapshot.add("item-autofill", &item_autofill(), &[]);
    // An object with a field kind this build does not know is kept as is.
    snapshot.add("credential-metadata", &credential_metadata(), &["kind"]);
    // An object with a history kind this build does not know is kept as is.
    snapshot.add("history-metadata", &history_metadata(), &["kind"]);
    snapshot.add("deleted-info", &deleted_info(), &[]);
    snapshot.add("file-record", &file_records(), &[]);
    snapshot
}

#[test]
fn vault_schema_matches_snapshot_of_its_format() {
    vault_snapshot().check();
}

#[test]
fn vault_file_change_without_format_bump_fails_snapshot() {
    let mut snapshot = vault_snapshot();
    snapshot.edit("vault-file-full", |text| {
        text.replace("\"replica_id\"", "\"replica\"")
    });

    let error = snapshot.compare().unwrap_err();

    assert!(error.contains("without a version bump"), "{error}");
    assert!(error.contains("vault-file-full"), "{error}");
}

#[test]
fn blob_plaintext_change_without_format_bump_fails_snapshot() {
    let mut snapshot = vault_snapshot();
    snapshot.edit("credential-metadata", |text| {
        text.replace("\"last_used_day_at\"", "\"last_used_at\"")
    });

    let error = snapshot.compare().unwrap_err();

    assert!(error.contains("without a version bump"), "{error}");
    assert!(error.contains("credential-metadata"), "{error}");
}
