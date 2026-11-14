use std::fmt::Write;

use serde_json::Value;

use super::*;
use crate::secrets::vaults::autofill::item::{MatchKind, Role, Website};
use crate::secrets::vaults::model::sync::{SyncHistoryEntry, SyncWriter};
use crate::secrets::vaults::sync::crdt::{CausalState, ReplicaId, Session};
use crate::secrets::vaults::sync::diff::LocalEdits;
use crate::secrets::vaults::sync::model::SyncState;
use crate::secrets::vaults::sync::view::VaultView;

/// Ids of the entries [`Vault::fill_for_test`] adds.
#[derive(Clone, Copy)]
struct Filled {
    kept: Uuid,
    removed: Uuid,
    folder: Uuid,
    section: Uuid,
    /// Live, in `kept`, with one previous value.
    alpha: Uuid,
    passkey: Uuid,
    /// Trashed, from `kept`.
    beta: Uuid,
    /// In the trashed item `removed`.
    gamma: Uuid,
    /// Trashed, from the trashed item `removed`.
    delta: Uuid,
    /// `value-created` entry of `alpha`.
    alpha_created: Uuid,
    /// Previous value of `alpha`.
    alpha_history: Uuid,
}

/// Overviews of the stored history entries of a live credential, oldest
/// first.
fn history_overviews(vault: &Vault, item_key: &str, cred_key: &str) -> Vec<HistoryOverview> {
    let item_id = item_id_of(vault, item_key);
    let cred_id = cred_id(vault, item_key, cred_key);
    vault.history_overviews(item_id, cred_id, vault.history.get(&cred_id))
}

/// Filled vault, saved and loaded so every blob is cached, and its ids.
fn filled() -> (Vault, Filled) {
    let mut vault = test_vault();
    vault.fill_for_test();
    let vault = reload(&vault);
    let removed = &vault.list_deleted_items()[0];
    let gamma = removed
        .item
        .credentials
        .values()
        .find(|cred| cred.key == "gamma")
        .unwrap()
        .id;
    let ids = Filled {
        kept: item_id_of(&vault, "kept"),
        removed: removed.item.id,
        folder: vault.list_folders()[0].id,
        section: *vault
            .get_item("kept")
            .unwrap()
            .sections
            .keys()
            .next()
            .unwrap(),
        alpha: cred_id(&vault, "kept", "alpha"),
        passkey: cred_id(&vault, "kept", "passkey"),
        beta: deleted_ids(&vault, "kept")[0],
        gamma,
        delta: removed.deleted_credentials[0].id,
        alpha_created: history_overviews(&vault, "kept", "alpha")[0].id,
        alpha_history: vault.list_history("kept", "alpha").unwrap()[0].id,
    };
    (vault, ids)
}

/// Vault file as JSON, with the deleted entries.
fn file(vault: &Vault) -> Value {
    serde_json::to_value(vault.to_encrypted(true).unwrap()).unwrap()
}

/// Paths of the values that differ between two vault files. Ids are short
/// ids. An array whose length changed is one path.
fn changed_paths(before: &Value, after: &Value) -> BTreeSet<String> {
    fn walk(path: String, a: Option<&Value>, b: Option<&Value>, out: &mut BTreeSet<String>) {
        match (a, b) {
            (Some(Value::Object(a)), Some(Value::Object(b))) => {
                for key in a.keys().chain(b.keys()) {
                    walk(format!("{path}/{key}"), a.get(key), b.get(key), out);
                }
            },
            (Some(Value::Array(a)), Some(Value::Array(b))) if a.len() == b.len() => {
                for (index, (a, b)) in a.iter().zip(b).enumerate() {
                    walk(format!("{path}/{index}"), Some(a), Some(b), out);
                }
            },
            (a, b) if a != b => {
                out.insert(path);
            },
            _ => {},
        }
    }
    let mut out = BTreeSet::new();
    walk(String::new(), Some(before), Some(after), &mut out);
    out
}

/// Short id, as in vault file paths.
fn short_id(id: Uuid) -> String {
    ShortId::encode_uuid(id)
}

/// Decrypted contents of a vault, live and trashed, as text.
fn contents(vault: &Vault) -> String {
    let entries = vault.sync_entries().unwrap();
    let mut out = String::new();
    for folder in entries.folders.values() {
        let VaultFolder {
            id,
            title,
            position,
        } = folder;
        writeln!(out, "folder {id} {title:?} {position:?}").unwrap();
    }
    for item in &entries.items {
        let trashed = item.trashed.as_ref().map(|t| (t.deleted_at, t.role));
        writeln!(out, "item {:?} {trashed:?}", item.overview).unwrap();
    }
    for cred in &entries.credentials {
        let trashed = cred.trashed.as_ref().map(|t| (t.deleted_at, t.role));
        let history: Vec<_> = cred
            .history
            .iter()
            .map(|h| {
                let value = h.value.as_ref().map(|v| v.expose_secret().clone());
                (h.id, &h.metadata, value)
            })
            .collect();
        writeln!(
            out,
            "credential {} {:?} {trashed:?} {:?} {history:?}",
            cred.item,
            cred.overview,
            cred.value.expose_secret(),
        )
        .unwrap();
    }
    out
}

/// Trash state, value, and history entry values of a credential, live or
/// trashed.
fn credential_entry(vault: &Vault, id: Uuid) -> (Uuid, Option<i64>, String, Vec<Option<String>>) {
    let entries = vault.sync_entries().unwrap();
    let cred = entries
        .credentials
        .iter()
        .find(|c| c.overview.id == id)
        .unwrap();
    (
        cred.item,
        cred.trashed.as_ref().map(|t| t.deleted_at),
        cred.value.expose_secret().clone(),
        cred.history
            .iter()
            .map(|h| h.value.as_ref().map(|v| v.expose_secret().clone()))
            .collect(),
    )
}

fn info(deleted_at: i64, role: Option<Role>) -> DeletedInfo {
    DeletedInfo { deleted_at, role }
}

type Mutation = Box<dyn Fn(&mut SyncWriter<'_>)>;

#[test]
fn each_mutation_changes_only_its_field_and_blobs() {
    let (base, ids) = filled();
    let Filled {
        kept,
        removed,
        folder,
        section,
        alpha,
        passkey,
        beta,
        gamma,
        delta,
        alpha_created,
        alpha_history,
    } = ids;
    let [k, r, a, b, g, d] = [kept, removed, alpha, beta, gamma, delta].map(short_id);
    let alpha_entries = history_overviews(&base, "kept", "alpha");
    let created_at = alpha_entries[0].at;
    let replaced_at = alpha_entries[1].at;
    // Stored history of `alpha`, with the previous value at `at` and `value`.
    let alpha_history_with = move |at: i64, value: &'static str| {
        [
            SyncHistoryEntry {
                id: alpha_created,
                metadata: HistoryMetadata {
                    at: created_at,
                    kind: HistoryKind::ValueCreated,
                },
                value: None,
            },
            SyncHistoryEntry {
                id: alpha_history,
                metadata: HistoryMetadata {
                    at,
                    kind: HistoryKind::ValueUpdated,
                },
                value: Some(value),
            },
        ]
    };
    let site = || vec![Website::new("example.org", MatchKind::Host)];
    let cases: Vec<(&str, Mutation, Vec<String>)> = vec![
        (
            "folder",
            Box::new(move |w| w.set_folder(folder, "Renamed", Some(3))),
            vec!["/metadata".to_string()],
        ),
        (
            "section of live item",
            Box::new(move |w| w.set_section(kept, section, "Renamed", Some(1)).unwrap()),
            vec![format!("/items/{k}/metadata")],
        ),
        (
            "section of trashed item",
            Box::new(move |w| {
                w.set_section(removed, Uuid::from_u128(9), "New", None)
                    .unwrap()
            }),
            vec![format!("/deleted/{r}/item/metadata")],
        ),
        (
            "live item title",
            Box::new(move |w| w.set_item_title(kept, "Title").unwrap()),
            vec![format!("/items/{k}/metadata")],
        ),
        (
            "trashed item title",
            Box::new(move |w| w.set_item_title(removed, "Title").unwrap()),
            vec![format!("/deleted/{r}/item/metadata")],
        ),
        (
            "trashed item category",
            Box::new(move |w| {
                w.set_item_category(removed, Some("login".to_string()))
                    .unwrap()
            }),
            vec![format!("/deleted/{r}/item/metadata")],
        ),
        (
            "trashed item folder",
            Box::new(move |w| w.set_item_folder(removed, Some(folder)).unwrap()),
            vec![format!("/deleted/{r}/item/metadata")],
        ),
        (
            "live item websites",
            Box::new(move |w| w.set_websites(kept, site()).unwrap()),
            vec![format!("/items/{k}/autofill")],
        ),
        (
            "trashed item websites",
            Box::new(move |w| w.set_websites(removed, site()).unwrap()),
            vec![format!("/deleted/{r}/item/autofill")],
        ),
        (
            "live item slots",
            Box::new(move |w| w.set_slots(kept, Some(passkey), Some(alpha), None).unwrap()),
            vec![format!("/items/{k}/autofill")],
        ),
        (
            "trashed item slots",
            Box::new(move |w| w.set_slots(removed, None, None, None).unwrap()),
            vec![format!("/deleted/{r}/item/autofill")],
        ),
        (
            "live credential title",
            Box::new(move |w| w.set_credential_title(alpha, "Title").unwrap()),
            vec![format!("/items/{k}/credentials/{a}/metadata")],
        ),
        (
            "trashed credential title",
            Box::new(move |w| w.set_credential_title(beta, "Title").unwrap()),
            vec![format!("/items/{k}/deleted/{b}/credential/metadata")],
        ),
        (
            "credential title in trashed item",
            Box::new(move |w| w.set_credential_title(gamma, "Title").unwrap()),
            vec![format!("/deleted/{r}/item/credentials/{g}/metadata")],
        ),
        (
            "trashed credential title in trashed item",
            Box::new(move |w| w.set_credential_title(delta, "Title").unwrap()),
            vec![format!("/deleted/{r}/item/deleted/{d}/credential/metadata")],
        ),
        (
            "credential kind in trashed item",
            Box::new(move |w| w.set_credential_kind(gamma, FieldKind::Totp).unwrap()),
            vec![format!("/deleted/{r}/item/credentials/{g}/metadata")],
        ),
        (
            "trashed credential placement in trashed item",
            Box::new(move |w| w.set_placement(delta, None, Some(4)).unwrap()),
            vec![format!("/deleted/{r}/item/deleted/{d}/credential/metadata")],
        ),
        (
            "trashed credential last used",
            Box::new(move |w| w.set_last_used(beta, Some(1_700_000_000)).unwrap()),
            vec![format!("/items/{k}/deleted/{b}/credential/metadata")],
        ),
        (
            "live credential value",
            Box::new(move |w| w.set_value(alpha, "new").unwrap()),
            vec![format!("/items/{k}/credentials/{a}/value")],
        ),
        (
            "trashed credential value",
            Box::new(move |w| w.set_value(beta, "new").unwrap()),
            vec![format!("/items/{k}/deleted/{b}/credential/value")],
        ),
        (
            "credential value in trashed item",
            Box::new(move |w| w.set_value(gamma, "new").unwrap()),
            vec![format!("/deleted/{r}/item/credentials/{g}/value")],
        ),
        (
            "trashed credential value in trashed item",
            Box::new(move |w| w.set_value(delta, "new").unwrap()),
            vec![format!("/deleted/{r}/item/deleted/{d}/credential/value")],
        ),
        (
            "history time",
            Box::new(move |w| w.set_history(alpha, &alpha_history_with(5, "one")).unwrap()),
            vec![format!("/items/{k}/credentials/{a}/history/1/metadata")],
        ),
        (
            "history value",
            Box::new(move |w| {
                let entries = alpha_history_with(replaced_at, "other");
                w.set_history(alpha, &entries).unwrap();
            }),
            vec![format!("/items/{k}/credentials/{a}/history/1/value")],
        ),
        (
            "history purge",
            Box::new(move |w| w.set_history(alpha, &[]).unwrap()),
            vec![format!("/items/{k}/credentials/{a}/history")],
        ),
        (
            "trashed credential info",
            Box::new(move |w| {
                w.set_credential_trashed(beta, Some(&info(5, None)))
                    .unwrap()
            }),
            vec![format!("/items/{k}/deleted/{b}/info")],
        ),
        (
            "trashed item info",
            Box::new(move |w| w.set_item_trashed(removed, Some(&info(5, None))).unwrap()),
            vec![format!("/deleted/{r}/info")],
        ),
    ];

    let before = file(&base);
    for (name, mutate, expected) in cases {
        let mut vault = reload(&base);
        mutate(&mut vault.sync_writer());
        let expected: BTreeSet<String> = expected.into_iter().collect();
        assert_eq!(changed_paths(&before, &file(&vault)), expected, "{name}");
        assert_ne!(contents(&vault), contents(&base), "{name}");
        assert_eq!(contents(&reload(&vault)), contents(&vault), "{name}");
    }
}

#[test]
fn edits_to_trashed_entries_leave_deleted_info_unchanged() {
    let (mut vault, ids) = filled();
    let trashed = |vault: &Vault| {
        let entries = vault.sync_entries().unwrap();
        let items: Vec<_> = entries
            .items
            .iter()
            .map(|i| i.trashed.as_ref().map(|t| (t.deleted_at, t.role)))
            .collect();
        let credentials: Vec<_> = entries
            .credentials
            .iter()
            .map(|c| c.trashed.as_ref().map(|t| (t.deleted_at, t.role)))
            .collect();
        (items, credentials)
    };
    let before = trashed(&vault);

    let mut writer = vault.sync_writer();
    writer.set_item_title(ids.removed, "Title").unwrap();
    writer.set_websites(ids.removed, Vec::new()).unwrap();
    for cred in [ids.beta, ids.gamma, ids.delta] {
        writer.set_credential_title(cred, "Title").unwrap();
        writer.set_value(cred, "new").unwrap();
        writer.set_history(cred, &[]).unwrap();
    }
    writer
        .set_placement(ids.beta, Some(ids.section), Some(2))
        .unwrap();

    assert_eq!(trashed(&vault), before);
    assert_eq!(trashed(&reload(&vault)), before);
}

#[test]
fn trash_moves_decrypt_after_reload() {
    let (mut vault, ids) = filled();
    let deleted_at = |vault: &Vault, id| credential_entry(vault, id).1;
    let beta_deleted_at = deleted_at(&vault, ids.beta);
    let delta_deleted_at = deleted_at(&vault, ids.delta);

    let mut writer = vault.sync_writer();
    // A live credential into a trashed item.
    writer.move_credential(ids.alpha, ids.removed).unwrap();
    // A trashed credential into a trashed item.
    writer.move_credential(ids.beta, ids.removed).unwrap();
    // A trashed credential of a trashed item into a live item.
    writer.move_credential(ids.delta, ids.kept).unwrap();
    // A credential of a trashed item into a live item.
    writer.move_credential(ids.gamma, ids.kept).unwrap();

    let vault = reload(&vault);
    // A `value-created` entry, then the previous value.
    let one = vec![None, Some("one".to_string())];
    assert_eq!(
        credential_entry(&vault, ids.alpha),
        (ids.removed, None, "two".to_string(), one.clone())
    );
    assert_eq!(
        credential_entry(&vault, ids.beta),
        (
            ids.removed,
            beta_deleted_at,
            "secret".to_string(),
            one.clone()
        )
    );
    assert_eq!(
        credential_entry(&vault, ids.delta),
        (
            ids.kept,
            delta_deleted_at,
            "secret".to_string(),
            one.clone()
        )
    );
    assert_eq!(
        credential_entry(&vault, ids.gamma),
        (ids.kept, None, "secret".to_string(), one)
    );
    assert_eq!(secret_of(&vault, "kept", "gamma"), "secret");
    // The source slots that named the moved credentials are cleared.
    assert_eq!(vault.get_item("kept").unwrap().autofill.password, None);
    assert_eq!(vault.list_deleted_items()[0].item.autofill.password, None);
}

#[test]
fn trash_and_restore_use_given_deleted_info() {
    let (mut vault, ids) = filled();

    let mut writer = vault.sync_writer();
    writer
        .set_credential_trashed(ids.alpha, Some(&info(7, Some(Role::Password))))
        .unwrap();
    writer
        .set_item_trashed(ids.kept, Some(&info(42, None)))
        .unwrap();
    let vault_trashed = reload(&vault);
    assert!(vault_trashed.get_item("kept").is_err());
    let kept = vault_trashed
        .list_deleted_items()
        .into_iter()
        .find(|entry| entry.item.id == ids.kept)
        .unwrap();
    assert_eq!(kept.deleted_at, 42);
    assert_eq!(kept.item.autofill.password, None);
    assert_eq!(credential_entry(&vault_trashed, ids.alpha).1, Some(7));
    let entries = vault_trashed.sync_entries().unwrap();
    let alpha = entries
        .credentials
        .iter()
        .find(|c| c.overview.id == ids.alpha)
        .unwrap();
    assert_eq!(alpha.trashed.as_ref().unwrap().role, Some(Role::Password));

    let mut writer = vault.sync_writer();
    writer.set_item_trashed(ids.kept, None).unwrap();
    writer.set_credential_trashed(ids.alpha, None).unwrap();
    let vault = reload(&vault);
    assert_eq!(secret_of(&vault, "kept", "alpha"), "two");
    assert_eq!(vault.list_history("kept", "alpha").unwrap().len(), 1);
    // A restore fills no role slot.
    assert_eq!(vault.get_item("kept").unwrap().autofill.password, None);
    assert_eq!(deleted_ids(&vault, "kept"), vec![ids.beta]);
}

#[test]
fn bulk_key_update_swaps_keys_and_fails_on_duplicate_without_change() {
    let vault = vault_with_credentials("item", &["alpha", "beta"]);
    let mut vault = reload(&vault);
    let item = item_id_of(&vault, "item");
    let other = item_id_of(&vault, "other-item");
    let alpha = cred_id(&vault, "item", "alpha");
    let beta = cred_id(&vault, "item", "beta");
    let keys = |pairs: &[(Uuid, &str)]| -> BTreeMap<Uuid, String> {
        pairs
            .iter()
            .map(|(id, key)| (*id, key.to_string()))
            .collect()
    };

    let before = file(&vault);
    let duplicates = [
        (keys(&[(item, "other-item")]), keys(&[])),
        (keys(&[]), keys(&[(alpha, "beta")])),
        (
            keys(&[(item, "other-item"), (other, "item")]),
            keys(&[(alpha, "gamma"), (beta, "gamma")]),
        ),
    ];
    for (items, credentials) in duplicates {
        let result = vault.sync_writer().set_keys(&items, &credentials);
        assert!(matches!(
            result,
            Err(Error::DuplicateItemKey(_) | Error::DuplicateCredentialKey(_))
        ));
        assert_eq!(file(&vault), before);
    }

    vault
        .sync_writer()
        .set_keys(
            &keys(&[(item, "other-item"), (other, "item")]),
            &keys(&[(alpha, "beta"), (beta, "alpha")]),
        )
        .unwrap();
    for vault in [&vault, &reload(&vault)] {
        assert_eq!(item_id_of(vault, "other-item"), item);
        assert_eq!(item_id_of(vault, "item"), other);
        assert_eq!(cred_id(vault, "other-item", "beta"), alpha);
        assert_eq!(cred_id(vault, "other-item", "alpha"), beta);
    }
}

#[test]
fn bulk_key_update_leaves_trashed_entries_out_of_uniqueness() {
    let (mut vault, ids) = filled();
    let keys = |pairs: &[(Uuid, &str)]| -> BTreeMap<Uuid, String> {
        pairs
            .iter()
            .map(|(id, key)| (*id, key.to_string()))
            .collect()
    };
    vault
        .sync_writer()
        .set_keys(
            &keys(&[(ids.kept, "removed")]),
            &keys(&[(ids.beta, "alpha"), (ids.delta, "gamma")]),
        )
        .unwrap();
    let vault = reload(&vault);
    assert_eq!(item_id_of(&vault, "removed"), ids.kept);
    assert_eq!(cred_id(&vault, "removed", "alpha"), ids.alpha);
    let beta = &vault.list_deleted("removed").unwrap()[0].credential;
    assert_eq!((beta.id, beta.key.as_str()), (ids.beta, "alpha"));
}

#[test]
fn no_mutation_trims_title_or_adds_history_entry() {
    let (mut vault, ids) = filled();
    let mut writer = vault.sync_writer();
    writer.set_folder(ids.folder, " Folder ", None);
    writer
        .set_section(ids.kept, ids.section, " Section ", None)
        .unwrap();
    writer.set_item_title(ids.kept, " Kept ").unwrap();
    writer.set_credential_title(ids.alpha, " Alpha ").unwrap();
    writer.set_value(ids.alpha, "three").unwrap();

    let vault = reload(&vault);
    assert_eq!(vault.list_folders()[0].title, " Folder ");
    let kept = vault.get_item("kept").unwrap();
    assert_eq!(kept.title, " Kept ");
    assert_eq!(kept.sections[&ids.section].title, " Section ");
    assert_eq!(
        vault.get_item_credential("kept", "alpha").unwrap().title,
        " Alpha "
    );
    assert_eq!(secret_of(&vault, "kept", "alpha"), "three");
    assert_eq!(vault.list_history("kept", "alpha").unwrap().len(), 1);
}

#[test]
fn entries_added_and_purged_by_id() {
    let (mut vault, ids) = filled();
    let added_item = Uuid::from_u128(1);
    let [in_trashed, in_added] = [2, 3].map(Uuid::from_u128);

    let mut writer = vault.sync_writer();
    writer
        .add_credential(
            ids.removed,
            in_trashed,
            "New",
            "new-field",
            FieldKind::default(),
            "value",
            100,
        )
        .unwrap();
    writer.add_item(added_item, "Added", "added", 101).unwrap();
    writer
        .add_credential(
            added_item,
            in_added,
            "Field",
            "field",
            FieldKind::default(),
            "other",
            102,
        )
        .unwrap();
    assert!(writer.add_item(added_item, "Again", "again", 103).is_err());
    assert!(
        writer
            .add_credential(
                ids.kept,
                in_added,
                "Again",
                "again",
                FieldKind::default(),
                "",
                104
            )
            .is_err()
    );
    let vault_added = reload(&vault);
    let secret = vault_added
        .get_deleted_credential_secret(ids.removed, in_trashed)
        .unwrap();
    assert_eq!(secret.expose_secret(), "value");
    assert_eq!(secret_of(&vault_added, "added", "field"), "other");

    let mut writer = vault.sync_writer();
    writer.set_history(ids.alpha, &[]).unwrap();
    writer.purge_credential(ids.beta).unwrap();
    writer.purge_credential(ids.gamma).unwrap();
    writer.purge_section(ids.kept, ids.section).unwrap();
    writer.purge_folder(ids.folder).unwrap();
    writer.purge_item(ids.removed).unwrap();
    writer.purge_item(added_item).unwrap();

    let vault = reload(&vault);
    assert!(vault.list_history("kept", "alpha").unwrap().is_empty());
    assert!(deleted_ids(&vault, "kept").is_empty());
    assert!(vault.list_deleted_items().is_empty());
    assert!(vault.list_folders().is_empty());
    assert!(vault.get_item("added").is_err());
    let kept = vault.get_item("kept").unwrap();
    assert_eq!(kept.folder, None);
    assert!(kept.sections.is_empty());
    assert_eq!(
        vault.get_item_credential("kept", "alpha").unwrap().section,
        None
    );
}

#[test]
fn mutations_leave_view_edits_empty() {
    let mut local = test_vault();
    local.fill_for_test();
    let mut applied = reload(&local);
    let kept = item_id_of(&local, "kept");
    let alpha = cred_id(&local, "kept", "alpha");
    let passkey = cred_id(&local, "kept", "passkey");
    let beta = deleted_ids(&local, "kept")[0];

    let mut state = CausalState::<SyncState>::default();
    let mut session = Session::new(ReplicaId(Uuid::from_u128(1)));
    let replica = session.replica;
    let find = |state: &CausalState<SyncState>, vault: &Vault| {
        LocalEdits::find(state, vault, replica).unwrap()
    };
    find(&state, &local).record(&mut state, &mut session, 1_000);
    assert!(find(&state, &applied).is_empty());

    // Local edits on one copy.
    local.add_or_update_item("kept", "Renamed").unwrap();
    let update = CredentialUpdate {
        title: Some("Alpha".to_string()),
        ..CredentialUpdate::default()
    };
    local
        .update_item_credential("kept", "alpha", update)
        .unwrap();
    local
        .add_or_update_item_credential(
            "kept",
            "alpha",
            "Alpha",
            FieldKind::default(),
            SecretString::from("three"),
        )
        .unwrap();
    local.restore_item_credential("kept", beta, None).unwrap();
    local.delete_item_credential("kept", "passkey").unwrap();
    find(&state, &local).record(&mut state, &mut session, 2_000);
    let view = VaultView::of(&state);

    // The same values on the other copy, through the mutations by id.
    let mut writer = applied.sync_writer();
    writer
        .set_item_title(kept, &view.items[&kept].title)
        .unwrap();
    let shown = &view.credentials[&alpha];
    writer.set_credential_title(alpha, &shown.title).unwrap();
    writer.set_value(alpha, shown.value.0.as_str()).unwrap();
    let history: Vec<SyncHistoryEntry<'_>> = shown
        .history
        .iter()
        .map(|h| SyncHistoryEntry {
            id: h.id,
            metadata: HistoryMetadata {
                at: h.at,
                kind: h.kind.clone(),
            },
            value: h.value.as_ref().map(|v| v.0.as_str()),
        })
        .collect();
    writer.set_history(alpha, &history).unwrap();
    writer.set_credential_trashed(beta, None).unwrap();
    let trashed = view.credentials[&passkey].trashed.clone().unwrap();
    writer
        .set_credential_trashed(passkey, Some(&info(trashed.deleted_at, trashed.role)))
        .unwrap();

    for vault in [&applied, &reload(&applied)] {
        let edits = find(&state, vault);
        assert!(edits.is_empty(), "{:?}", edits.edits());
    }
}
