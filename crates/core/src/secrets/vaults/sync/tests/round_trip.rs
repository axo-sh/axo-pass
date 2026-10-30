//! Round trip of generated sync states through the apply step and the diff.

use std::collections::BTreeSet;

use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;
use secrecy::ExposeSecret;
use uuid::Uuid;

use super::apply::reload;
use super::generators::{Ids, Script};
use super::view::State;
use super::{NOW, session};
use crate::secrets::vaults::autofill::item::{ItemAutofill, Role};
use crate::secrets::vaults::model::Vault;
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::passkey::signals::SignalStore;
use crate::secrets::vaults::storage::handle::validate_key;
use crate::secrets::vaults::sync::apply::ApplyReport;
use crate::secrets::vaults::sync::diff::LocalEdits;
use crate::secrets::vaults::sync::view::{RECOVERED_ITEM_TITLE, VaultView};

/// Replica of the diffs and of the recorded state. No generated session uses
/// it.
const LOCAL: u128 = 9;

/// Vault built by applying the view of `state` to an empty vault.
fn built(state: &State) -> Vault {
    let mut vault = Vault::new_for_test();
    VaultView::of(state).apply(&mut vault).unwrap();
    vault
}

/// Check that `vault` has no edits against the view of `state`, also after a
/// save and reload.
fn assert_no_edits(state: &State, vault: &Vault) -> Result<(), TestCaseError> {
    let replica = session(LOCAL).replica;
    for vault in [vault, &reload(vault)] {
        let edits = LocalEdits::find(state, vault, replica).unwrap();
        prop_assert!(edits.is_empty(), "{:?}", edits.edits());
    }
    Ok(())
}

/// Check that every key of `vault` passes `validate_key`, that keys are unique
/// among the live items and among the credentials of each item that are not
/// trashed, and that each key of a live item and of its live credentials finds
/// its entry.
fn assert_keys_unique_and_valid(vault: &Vault) -> Result<(), TestCaseError> {
    let entries = vault.sync_entries().unwrap();
    let mut items = BTreeSet::new();
    for entry in &entries.items {
        let key = &entry.overview.key;
        prop_assert!(validate_key(key), "invalid item key {key}");
        if entry.trashed.is_none() {
            prop_assert!(items.insert(key), "duplicate item key {key}");
        }
    }
    let mut credentials = BTreeSet::new();
    for entry in &entries.credentials {
        let key = &entry.overview.key;
        prop_assert!(validate_key(key), "invalid credential key {key}");
        if entry.trashed.is_none() {
            let unique = credentials.insert((entry.item, key));
            prop_assert!(unique, "duplicate credential key {key}");
        }
    }

    for item in vault.list_items() {
        prop_assert_eq!(vault.get_item(&item.key).unwrap().id, item.id);
        for credential in item.credentials.values() {
            let found = vault.get_item_credential(&item.key, &credential.key);
            prop_assert_eq!(found.unwrap().id, credential.id);
        }
    }
    Ok(())
}

/// Decrypted contents of a vault, in the order the vault lists them.
#[derive(Debug, PartialEq)]
struct Contents {
    name: Option<String>,
    /// Id, title, and position.
    folders: Vec<(Uuid, String, Option<u32>)>,
    signals: SignalStore,
    items: Vec<ItemContents>,
    credentials: Vec<CredentialContents>,
}

#[derive(Debug, PartialEq)]
struct ItemContents {
    id: Uuid,
    title: String,
    key: String,
    folder: Option<Uuid>,
    /// Id, title, and position.
    sections: Vec<(Uuid, String, Option<u32>)>,
    category: Option<String>,
    autofill: ItemAutofill,
    /// Deleted time and role.
    trashed: Option<(i64, Option<Role>)>,
}

#[derive(Debug, PartialEq)]
struct CredentialContents {
    id: Uuid,
    item: Uuid,
    title: String,
    key: String,
    kind: FieldKind,
    section: Option<Uuid>,
    position: Option<u32>,
    last_used_day_at: Option<i64>,
    /// Deleted time and role.
    trashed: Option<(i64, Option<Role>)>,
    value: String,
    /// Id, time, and value.
    history: Vec<(Uuid, i64, String)>,
}

impl Contents {
    fn of(vault: &Vault) -> Self {
        let entries = vault.sync_entries().unwrap();
        let items = entries
            .items
            .iter()
            .map(|entry| {
                let item = entry.overview;
                ItemContents {
                    id: item.id,
                    title: item.title.clone(),
                    key: item.key.clone(),
                    folder: item.folder,
                    sections: item
                        .sections
                        .values()
                        .map(|s| (s.id, s.title.clone(), s.position))
                        .collect(),
                    category: item.category.clone(),
                    autofill: item.autofill.clone(),
                    trashed: entry.trashed.as_ref().map(|t| (t.deleted_at, t.role)),
                }
            })
            .collect();
        let credentials = entries
            .credentials
            .iter()
            .map(|entry| {
                let credential = entry.overview;
                CredentialContents {
                    id: credential.id,
                    item: entry.item,
                    title: credential.title.clone(),
                    key: credential.key.clone(),
                    kind: credential.kind.clone(),
                    section: credential.section,
                    position: credential.position,
                    last_used_day_at: credential.last_used_day_at,
                    trashed: entry.trashed.as_ref().map(|t| (t.deleted_at, t.role)),
                    value: entry.value.expose_secret().clone(),
                    history: entry
                        .history
                        .iter()
                        .map(|h| (h.id, h.replaced_at, h.value.expose_secret().clone()))
                        .collect(),
                }
            })
            .collect();
        Self {
            name: entries.name.map(str::to_string),
            folders: entries
                .folders
                .values()
                .map(|f| (f.id, f.title.clone(), f.position))
                .collect(),
            signals: entries.passkey_signals.clone(),
            items,
            credentials,
        }
    }
}

/// Shown keys of the live items and of the credentials that are not trashed.
fn live_keys(view: &VaultView) -> impl Iterator<Item = &str> {
    let items = view.items.values().filter(|i| i.trashed.is_none());
    let credentials = view.credentials.values().filter(|c| c.trashed.is_none());
    items
        .map(|i| i.key.as_str())
        .chain(credentials.map(|c| c.key.as_str()))
}

#[test]
fn generated_states_hold_each_case_of_round_trip() {
    type Check = dyn Fn(&State, &VaultView) -> bool;
    let mut runner = TestRunner::deterministic();
    let strategy = Script::strategy();
    let states: Vec<(State, VaultView)> = (0..128)
        .map(|_| {
            let state = strategy.new_tree(&mut runner).unwrap().current().play();
            let view = VaultView::of(&state);
            (state, view)
        })
        .collect();

    let cases: [(&str, &Check); 14] = [
        ("a conflict in an Ask register", &|_, v| {
            !v.conflicts().is_empty()
        }),
        ("a key that fails validate_key", &|_, v| {
            !v.key_notices().is_empty()
        }),
        ("a key that needs normalizing", &|_, v| {
            live_keys(v).any(|k| k.starts_with("my-item"))
        }),
        ("a duplicate key", &|_, v| {
            live_keys(v).any(|k| k.starts_with("mail-") || k.starts_with("bank-"))
        }),
        ("a recovered item", &|_, v| {
            v.items.values().any(|i| i.title == RECOVERED_ITEM_TITLE)
        }),
        ("a credential of a purged item", &|s, v| {
            v.credentials.values().any(|c| {
                c.item != c.id && c.item != Ids::item(0) && s.store.items.get(&c.item).is_none()
            })
        }),
        ("a dangling folder", &|s, v| {
            s.store.items.iter().any(|(id, item)| {
                item.folder.shown().copied().flatten().is_some()
                    && v.items.get(id).is_some_and(|i| i.folder.is_none())
            })
        }),
        ("a dangling section", &|s, v| {
            s.store.credentials.iter().any(|(id, c)| {
                c.placement.shown().is_some_and(|p| p.section.is_some())
                    && v.credentials.get(id).is_some_and(|c| c.section.is_none())
            })
        }),
        ("a dangling slot", &|s, v| {
            s.store.items.iter().any(|(id, item)| {
                let Some(shown) = v.items.get(id) else {
                    return false;
                };
                [
                    (&item.username, shown.username),
                    (&item.password, shown.password),
                    (&item.totp, shown.totp),
                ]
                .into_iter()
                .any(|(slot, shown)| slot.shown().copied().flatten().is_some() && shown.is_none())
            })
        }),
        ("a trashed item with a credential", &|_, v| {
            v.items
                .values()
                .any(|i| i.trashed.is_some() && !i.credentials.is_empty())
        }),
        ("a trashed credential", &|_, v| {
            v.credentials.values().any(|c| c.trashed.is_some())
        }),
        ("concurrent moves of a credential", &|s, _| {
            s.store
                .credentials
                .iter()
                .any(|(_, c)| c.item.values().count() > 1)
        }),
        ("a history entry", &|_, v| {
            v.credentials.values().any(|c| !c.history.is_empty())
        }),
        ("a signal list longer than 500 entries", &|_, v| {
            v.signals.entries().count() > 500
        }),
    ];
    for (case, holds) in cases {
        let held = states.iter().any(|(state, view)| holds(state, view));
        assert!(held, "no generated state holds {case}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn vault_built_from_random_view_finds_no_edits(script in Script::strategy()) {
        let state = script.play();
        let vault = built(&state);
        assert_no_edits(&state, &vault)?;
    }

    #[test]
    fn random_view_applied_to_vault_built_from_another_finds_no_edits(
        first in Script::strategy(),
        second in Script::strategy(),
    ) {
        let mut vault = built(&first.play());
        let state = second.play();
        VaultView::of(&state).apply(&mut vault).unwrap();
        assert_no_edits(&state, &vault)?;
    }

    #[test]
    fn applied_vault_keys_are_unique_among_live_entries_and_valid(
        first in Script::strategy(),
        second in Script::strategy(),
    ) {
        let mut vault = built(&first.play());
        assert_keys_unique_and_valid(&vault)?;
        VaultView::of(&second.play()).apply(&mut vault).unwrap();
        assert_keys_unique_and_valid(&vault)?;
    }

    #[test]
    fn vault_recorded_against_empty_state_and_applied_again_is_unchanged(
        script in Script::strategy(),
    ) {
        let mut vault = built(&script.play());
        let before = Contents::of(&vault);

        let mut state = State::default();
        let mut local = session(LOCAL);
        let edits = LocalEdits::find(&state, &vault, local.replica).unwrap();
        edits.record(&mut state, &mut local, NOW);
        let report = VaultView::of(&state).apply(&mut vault).unwrap();

        prop_assert_eq!(report, ApplyReport::default());
        prop_assert_eq!(Contents::of(&vault), before);
        assert_no_edits(&state, &vault)?;
    }
}
