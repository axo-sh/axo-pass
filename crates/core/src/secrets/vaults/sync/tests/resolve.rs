use std::collections::BTreeSet;

use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use super::apply::{Mac, filled, reload, sync};
use super::view::edited;
use super::{NOW, id};
use crate::secrets::vaults::model::Vault;
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::sync::apply::ApplyReport;
use crate::secrets::vaults::sync::crdt::{ActorId, WriteId};
use crate::secrets::vaults::sync::diff::Edit;
use crate::secrets::vaults::sync::model::SecretText;
use crate::secrets::vaults::sync::resolve::{
    Choice, HistoryIds, Resolve, ResolveError, ResolveReport,
};
use crate::secrets::vaults::sync::view::{AskRegister, Conflict, Entity, VaultView};

impl Mac {
    /// Apply a local change, give the history entries it added their derived
    /// ids, and record its edits.
    fn edit_with_history_ids(&mut self, change: impl FnOnce(&mut Vault)) {
        change(&mut self.vault);
        HistoryIds::rewrite(&self.state, &mut self.vault).unwrap();
        let edits = self.find();
        assert!(!edits.is_empty());
        edits.record(&mut self.state, &mut self.session, NOW);
    }

    /// Record a resolve request in a transaction with no vault change, and
    /// apply the view.
    fn resolve(&mut self, request: Resolve) -> Result<(ResolveReport, ApplyReport), ResolveError> {
        let mut edits = self.find();
        assert!(edits.is_empty());
        let report = edits.resolve(&self.state, request, NOW)?;
        assert!(
            edits
                .record(&mut self.state, &mut self.session, NOW)
                .is_some()
        );
        Ok((report, self.apply()))
    }

    /// Record "Keep `{key}-{suffix}`" for `entity`, and apply the view.
    fn keep_key(&mut self, entity: Entity) -> ApplyReport {
        let mut edits = self.find();
        assert!(edits.is_empty());
        edits.keep_key(&self.view(), entity).unwrap();
        assert!(
            edits
                .record(&mut self.state, &mut self.session, NOW)
                .is_some()
        );
        self.apply()
    }

    fn credential_id(&self, item: &str, key: &str) -> Uuid {
        self.vault.get_item_credential(item, key).unwrap().id
    }

    fn item_id(&self, key: &str) -> Uuid {
        self.vault.get_item(key).unwrap().id
    }

    /// Write ids of the value register of credential `id`.
    fn value_ids(&self, id: Uuid) -> BTreeSet<WriteId> {
        let credential = self.state.store.credentials.get(&id).unwrap();
        credential
            .value
            .values()
            .map(|(write_id, _)| write_id)
            .collect()
    }

    /// Write ids of the title register of item `id`.
    fn title_ids(&self, id: Uuid) -> BTreeSet<WriteId> {
        let item = self.state.store.items.get(&id).unwrap();
        item.title.values().map(|(write_id, _)| write_id).collect()
    }
}

/// Set the value of credential `alpha` of item `kept`.
fn set_alpha(vault: &mut Vault, value: &str) {
    vault
        .add_or_update_item_credential(
            "kept",
            "alpha",
            "alpha",
            FieldKind::default(),
            SecretString::from(value.to_string()),
        )
        .unwrap();
}

/// Ids of the history entries of credential `id` in the view that hold
/// `value`.
fn history_ids(view: &VaultView, id: Uuid, value: &str) -> Vec<Uuid> {
    view.credentials[&id]
        .history
        .iter()
        .filter(|h| h.value.as_ref().is_some_and(|v| v.0.as_str() == value))
        .map(|h| h.id)
        .collect()
}

/// Two Macs with a filled vault, whose value of `alpha` was set to `three`
/// on the first and to `four` on the second concurrently, then synced.
fn value_conflict() -> (Mac, Mac, Uuid) {
    let mut a = Mac::first(filled());
    let mut b = Mac::joined(&a, 2);
    let alpha = a.credential_id("kept", "alpha");
    a.edit_with_history_ids(|v| set_alpha(v, "three"));
    b.edit_with_history_ids(|v| set_alpha(v, "four"));
    sync(&mut a, &mut b);
    let conflict = Conflict {
        entity: Entity::Credential(alpha),
        register: AskRegister::Value,
    };
    assert!(a.view().conflicts().contains(&conflict));
    (a, b, alpha)
}

/// Two Macs with a filled vault, whose title of `kept` was changed on both
/// concurrently, then synced.
fn title_conflict() -> (Mac, Mac, Uuid) {
    let mut a = Mac::first(filled());
    let mut b = Mac::joined(&a, 2);
    let kept = a.item_id("kept");
    a.edit(|v| {
        v.add_or_update_item("kept", "Kept on A").unwrap();
    });
    b.edit(|v| {
        v.add_or_update_item("kept", "Kept on B").unwrap();
    });
    sync(&mut a, &mut b);
    let conflict = Conflict {
        entity: Entity::Item(kept),
        register: AskRegister::Title,
    };
    assert!(a.view().conflicts().contains(&conflict));
    (a, b, kept)
}

#[test]
fn derived_history_id_depends_only_on_credential_and_write_id() {
    let actor = ActorId(id(7));
    let write = |seq| WriteId { actor, seq };
    let derived = HistoryIds::derive(id(1), write(1));
    assert_eq!(derived, HistoryIds::derive(id(1), write(1)));
    assert_ne!(derived, HistoryIds::derive(id(1), write(2)));
    assert_ne!(derived, HistoryIds::derive(id(2), write(1)));
}

#[test]
fn history_entry_with_rewritten_id_decrypts_after_save_and_reload() {
    let mut a = Mac::first(filled());
    let alpha = a.credential_id("kept", "alpha");
    let replaced = *a.value_ids(alpha).first().unwrap();
    a.edit_with_history_ids(|v| set_alpha(v, "three"));

    let derived = HistoryIds::derive(alpha, replaced);
    for vault in [&a.vault, &reload(&a.vault)] {
        let previous = vault.get_history_value("kept", "alpha", derived).unwrap();
        assert_eq!(previous.expose_secret(), "two");
    }
    a.assert_no_edits(&reload(&a.vault));
}

#[test]
fn replaced_value_with_no_write_id_in_view_retains_random_id() {
    let mut a = Mac::first(filled());
    let history_before: Vec<Uuid> = a
        .vault
        .list_history("kept", "alpha")
        .unwrap()
        .iter()
        .map(|h| h.id)
        .collect();

    // A credential added and changed in one transaction has no write id.
    a.vault
        .add_or_update_item_credential(
            "kept",
            "fresh",
            "fresh",
            FieldKind::default(),
            SecretString::from("v1".to_string()),
        )
        .unwrap();
    a.vault
        .add_or_update_item_credential(
            "kept",
            "fresh",
            "fresh",
            FieldKind::default(),
            SecretString::from("v2".to_string()),
        )
        .unwrap();
    let random = a.vault.list_history("kept", "fresh").unwrap()[0].id;

    HistoryIds::rewrite(&a.state, &mut a.vault).unwrap();
    let history = a.vault.list_history("kept", "fresh").unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].id, random);
    let alpha: Vec<Uuid> = a
        .vault
        .list_history("kept", "alpha")
        .unwrap()
        .iter()
        .map(|h| h.id)
        .collect();
    assert_eq!(alpha, history_before);
}

#[test]
fn resolve_writes_unchosen_values_to_history() {
    let (mut a, mut b, alpha) = value_conflict();
    let read = a.value_ids(alpha);
    let four = *read
        .iter()
        .find(|w| a.state.actors[&w.actor].replica == b.session.replica)
        .unwrap();

    let request = Resolve {
        choice: Choice::Value(alpha, SecretText::new("three")),
        read,
    };
    let (report, _) = a.resolve(request).unwrap();

    assert_eq!(report.not_chosen.len(), 1);
    assert_eq!(report.not_chosen[0].write_id, four);
    assert_eq!(report.not_chosen[0].replica, Some(b.session.replica));
    let derived = HistoryIds::derive(alpha, four);
    assert_eq!(history_ids(&a.view(), alpha, "four"), [derived]);
    let value = a.vault.get_history_value("kept", "alpha", derived).unwrap();
    assert_eq!(value.expose_secret(), "four");

    b.join(&a);
    for mac in [&a, &b] {
        assert!(mac.view().conflicts().is_empty());
        let value = mac
            .vault
            .get_item_credential_secret("kept", "alpha")
            .unwrap();
        assert_eq!(value.unwrap().expose_secret(), "three");
    }
}

#[test]
fn choosing_shown_value_leaves_vault_unchanged_and_supersedes_every_value() {
    let (mut a, mut b, kept) = title_conflict();
    let shown = a.view().items[&kept].title.clone();
    let request = Resolve {
        choice: Choice::ItemTitle(kept, shown.clone()),
        read: a.title_ids(kept),
    };
    let (_, applied) = a.resolve(request).unwrap();
    assert!(applied.changed.is_empty());

    b.join(&a);
    for mac in [&a, &b] {
        assert!(mac.view().conflicts().is_empty());
        assert_eq!(mac.title_ids(kept).len(), 1);
        assert_eq!(mac.vault.get_item("kept").unwrap().title, shown);
    }
}

#[test]
fn concurrent_resolves_converge_on_one_entry() {
    let (mut a, mut b, alpha) = value_conflict();
    for mac in [&mut a, &mut b] {
        let request = Resolve {
            choice: Choice::Value(alpha, SecretText::new("three")),
            read: mac.value_ids(alpha),
        };
        mac.resolve(request).unwrap();
    }
    sync(&mut a, &mut b);

    let view = a.view();
    assert!(view.conflicts().is_empty());
    assert_eq!(history_ids(&view, alpha, "four").len(), 1);
    assert!(history_ids(&view, alpha, "three").is_empty());
}

#[test]
fn resolve_request_whose_read_write_ids_differ_refused() {
    let (a, _, alpha) = value_conflict();
    let mut read = a.value_ids(alpha);
    read.pop_first();
    let request = Resolve {
        choice: Choice::Value(alpha, SecretText::new("three")),
        read,
    };
    let mut edits = a.find();
    let refused = edits.resolve(&a.state, request, NOW).unwrap_err();
    let register = Conflict {
        entity: Entity::Credential(alpha),
        register: AskRegister::Value,
    };
    assert_eq!(refused, ResolveError::Changed(register));
    assert!(edits.is_empty());
}

#[test]
fn resolving_other_register_writes_no_history_and_reports_each_value_not_chosen() {
    let (a, b, kept) = title_conflict();
    let request = Resolve {
        choice: Choice::ItemTitle(kept, "Chosen".to_string()),
        read: a.title_ids(kept),
    };
    let mut edits = a.find();
    let report = edits.resolve(&a.state, request, NOW).unwrap();

    assert!(!edits.edits().iter().any(|e| matches!(e, Edit::History(..))));
    let mut replicas: Vec<_> = report.not_chosen.iter().map(|n| n.replica).collect();
    replicas.sort();
    let mut expected = vec![Some(a.session.replica), Some(b.session.replica)];
    expected.sort();
    assert_eq!(replicas, expected);
    assert!(report.not_chosen.iter().all(|n| n.written_at == NOW));
}

#[test]
fn keeping_suffixed_key_of_invalid_key_writes_shown_key_and_notice_clears() {
    let mut a = Mac::first(filled());
    let kept = a.item_id("kept");
    a.state = edited(&a.state, 9, |s, m| {
        s.items.entry(kept).key.write(m, "!!!".to_string());
    });
    a.apply();
    let shown = a.view().items[&kept].key.clone();
    assert_eq!(a.view().key_notices(), [Entity::Item(kept)]);

    let applied = a.keep_key(Entity::Item(kept));
    assert!(applied.key_changes.is_empty());
    let view = a.view();
    assert!(view.key_notices().is_empty());
    assert_eq!(view.items[&kept].key, shown);
    let register = &a.state.store.items.get(&kept).unwrap().key;
    let stored: Vec<&String> = register.values().map(|(_, v)| &v.value).collect();
    assert_eq!(stored, [&shown]);
}

#[test]
fn kept_suffixed_key_stays_after_holder_of_bare_key_trashed() {
    let mut a = Mac::first(Vault::new_for_test());
    let mut b = Mac::joined(&a, 2);
    a.edit(|v| {
        v.add_or_update_item("work", "Work").unwrap();
    });
    b.edit(|v| {
        v.add_or_update_item("work", "Work").unwrap();
    });
    sync(&mut a, &mut b);
    let view = a.view();
    let suffixed = view
        .items
        .values()
        .find(|i| i.key.starts_with("work-"))
        .unwrap();
    let (suffixed, key) = (suffixed.id, suffixed.key.clone());

    a.keep_key(Entity::Item(suffixed));
    a.edit(|v| v.delete_item("work").unwrap());
    b.join(&a);
    for mac in [&a, &b] {
        assert_eq!(mac.view().items[&suffixed].key, key);
        assert_eq!(mac.vault.get_item(&key).unwrap().id, suffixed);
    }
}
