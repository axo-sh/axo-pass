use jiff::tz::TimeZone;
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use super::view::{State, edited};
use super::{NOW, session};
use crate::secrets::vaults::autofill::item::{ItemAutofill, MatchKind, Website};
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::model::{
    CredentialPlacement, CredentialUpdate, Vault, VaultItemCredentialOverview, display_order,
};
use crate::secrets::vaults::passkey::signals::Report;
use crate::secrets::vaults::sync::apply::{ApplyReport, KeyChange};
use crate::secrets::vaults::sync::crdt::Session;
use crate::secrets::vaults::sync::diff::{Edit, LocalEdits};
use crate::secrets::vaults::sync::model::TrashValue;
use crate::secrets::vaults::sync::view::{Entity, VaultView};

/// Vault, sync state, and session of one Mac.
pub(super) struct Mac {
    pub(super) vault: Vault,
    pub(super) state: State,
    pub(super) session: Session,
}

impl Mac {
    /// Mac of replica 1 whose state is recorded from `vault`.
    pub(super) fn first(vault: Vault) -> Self {
        let mut mac = Self {
            vault,
            state: State::default(),
            session: session(1),
        };
        let edits = mac.find();
        edits.record(&mut mac.state, &mut mac.session, NOW);
        mac
    }

    /// Mac of replica `n` with an empty vault and state.
    pub(super) fn empty(n: u128) -> Self {
        Self {
            vault: Vault::new_for_test(),
            state: State::default(),
            session: session(n),
        }
    }

    /// Mac of replica `n` with an empty vault, joined with `other`.
    pub(super) fn joined(other: &Mac, n: u128) -> Self {
        let mut mac = Self::empty(n);
        mac.join(other);
        mac
    }

    pub(super) fn find(&self) -> LocalEdits {
        LocalEdits::find(&self.state, &self.vault, self.session.replica).unwrap()
    }

    pub(super) fn assert_no_edits(&self, vault: &Vault) {
        let edits = LocalEdits::find(&self.state, vault, self.session.replica).unwrap();
        assert!(edits.is_empty(), "{:?}", edits.edits());
    }

    /// Apply a local change to the vault and record its edits, which must
    /// not be empty.
    pub(super) fn edit(&mut self, change: impl FnOnce(&mut Vault)) {
        change(&mut self.vault);
        let edits = self.find();
        assert!(!edits.is_empty());
        edits.record(&mut self.state, &mut self.session, NOW);
    }

    /// Join the state of `other` and apply the view.
    pub(super) fn join(&mut self, other: &Mac) -> ApplyReport {
        self.state.join(other.state.clone());
        self.apply()
    }

    /// Apply the view of the state, and check that the vault then has no
    /// edits, also after a save and reload.
    pub(super) fn apply(&mut self) -> ApplyReport {
        let report = VaultView::of(&self.state).apply(&mut self.vault).unwrap();
        self.assert_no_edits(&self.vault);
        self.assert_no_edits(&reload(&self.vault));
        report
    }

    pub(super) fn view(&self) -> VaultView {
        VaultView::of(&self.state)
    }
}

/// Save and load a vault under its own key.
pub(super) fn reload(vault: &Vault) -> Vault {
    let cipher = vault.unlocked_key().cipher_for_test();
    Vault::from_encrypted_with_cipher(cipher, vault.to_encrypted(true).unwrap()).unwrap()
}

/// Join each Mac with the other, and check that both show the same view and
/// that each vault holds it.
pub(super) fn sync(a: &mut Mac, b: &mut Mac) -> (ApplyReport, ApplyReport) {
    let report_a = a.join(b);
    let report_b = b.join(a);
    assert_eq!(a.view(), b.view());
    a.assert_no_edits(&b.vault);
    b.assert_no_edits(&a.vault);
    (report_a, report_b)
}

pub(super) fn filled() -> Vault {
    let mut vault = Vault::new_for_test();
    vault.fill_for_test();
    vault
}

fn add_item(vault: &mut Vault, key: &str) -> Uuid {
    vault.add_or_update_item(key, "Item").unwrap().id
}

pub(super) fn add_credential(vault: &mut Vault, item: &str, key: &str, value: &str) -> Uuid {
    vault
        .add_or_update_item_credential(
            item,
            key,
            &key.to_uppercase(),
            FieldKind::default(),
            SecretString::from(value.to_string()),
        )
        .unwrap()
        .id
}

fn websites(urls: &[&str]) -> ItemAutofill {
    ItemAutofill {
        websites: urls
            .iter()
            .map(|url| Website::new(*url, MatchKind::Domain))
            .collect(),
        ..ItemAutofill::default()
    }
}

fn report(n: u32) -> Report {
    Report::Unknown {
        rp_id: "example.com".to_string(),
        credential_id: n.to_be_bytes().to_vec(),
    }
}

/// Ids in list order: position, with no position last, then title, then id.
fn list_order<'a>(entries: impl Iterator<Item = (Uuid, Option<u32>, &'a str)>) -> Vec<Uuid> {
    let mut entries: Vec<_> = entries.collect();
    entries.sort_by(|a, b| (display_order(a.1, a.2), a.0).cmp(&(display_order(b.1, b.2), b.0)));
    entries.into_iter().map(|(id, _, _)| id).collect()
}

/// Vault keys of the live items.
fn item_keys(vault: &Vault) -> Vec<(Uuid, String)> {
    let mut keys: Vec<_> = vault
        .list_items()
        .iter()
        .map(|i| (i.id, i.key.clone()))
        .collect();
    keys.sort();
    keys
}

#[test]
fn view_applied_to_empty_vault_reproduces_filled_vault() {
    let a = Mac::first(filled());
    let b = Mac::joined(&a, 2);
    b.vault.assert_filled_for_test();
    reload(&b.vault).assert_filled_for_test();
    a.assert_no_edits(&b.vault);
}

#[test]
fn every_row_of_mapping_table_round_trips() {
    let mut a = Mac::first(filled());
    let mut b = Mac::joined(&a, 2);
    let mut step = |change: &dyn Fn(&mut Vault)| {
        a.edit(change);
        let report = b.join(&a);
        assert!(!report.changed.is_empty());
        a.assert_no_edits(&b.vault);
        b.assert_no_edits(&a.vault);
    };
    let folder_titled = |v: &Vault, title: &str| {
        v.list_folders()
            .iter()
            .find(|f| f.title == title)
            .unwrap()
            .id
    };
    let section_titled = |v: &Vault, title: &str| {
        v.get_item("kept")
            .unwrap()
            .sections
            .values()
            .find(|s| s.title == title)
            .unwrap()
            .id
    };
    let update =
        |title: Option<&str>, kind: Option<FieldKind>, key: Option<&str>| CredentialUpdate {
            key: key.map(str::to_string),
            title: title.map(str::to_string),
            kind,
        };

    // Vault name, folders, and signals.
    step(&|v| v.name = Some("Renamed".to_string()));
    step(&|v| {
        v.create_folder("Second");
    });
    step(&|v| {
        v.rename_folder(folder_titled(v, "Folder"), "First")
            .unwrap()
    });
    step(&|v| {
        let ids = [folder_titled(v, "Second"), folder_titled(v, "First")];
        v.reorder_folders(&ids).unwrap();
    });
    step(&|v| v.delete_folder(folder_titled(v, "Second")).unwrap());
    step(&|v| v.update_passkey_signals(|s| s.record(report(9), 1_700_000_100)));

    // Item registers, sections, websites, and role slots.
    step(&|v| {
        v.add_or_update_item("kept", "Kept again").unwrap();
    });
    step(&|v| {
        v.set_item_category("kept", Some("login".to_string()))
            .unwrap()
    });
    step(&|v| v.move_item("kept", None).unwrap());
    step(&|v| {
        v.create_item_section("kept", "Second").unwrap();
    });
    step(&|v| {
        v.rename_item_section("kept", section_titled(v, "Second"), "Third")
            .unwrap()
    });
    step(&|v| {
        let ids: Vec<Uuid> = [section_titled(v, "Third"), section_titled(v, "Section")].into();
        v.reorder_item_sections("kept", &ids).unwrap();
    });
    step(&|v| {
        v.delete_item_section("kept", section_titled(v, "Third"))
            .unwrap()
    });
    step(&|v| {
        let mut autofill = v.get_item("kept").unwrap().autofill.clone();
        autofill.websites = websites(&["a.com", "b.com"]).websites;
        v.set_item_autofill("kept", autofill).unwrap();
    });
    step(&|v| {
        let mut autofill = v.get_item("kept").unwrap().autofill.clone();
        autofill.websites.reverse();
        autofill.websites[0].match_kind = MatchKind::Host;
        v.set_item_autofill("kept", autofill).unwrap();
    });
    step(&|v| {
        let mut autofill = v.get_item("kept").unwrap().autofill.clone();
        autofill.username = Some(v.get_item_credential("kept", "passkey").unwrap().id);
        v.set_item_autofill("kept", autofill).unwrap();
    });

    // Credential registers and history.
    step(&|v| {
        v.update_item_credential("kept", "alpha", update(Some("First"), None, None))
            .unwrap();
    });
    step(&|v| {
        v.update_item_credential("kept", "alpha", update(None, Some(FieldKind::Email), None))
            .unwrap();
    });
    step(&|v| {
        v.update_item_credential("kept", "alpha", update(None, None, Some("first")))
            .unwrap();
    });
    step(&|v| v.move_item_credential("kept", "first", None).unwrap());
    step(&|v| {
        let placements = ["passkey", "first"].map(|key| CredentialPlacement {
            key: key.to_string(),
            section: None,
        });
        v.reorder_item_credentials("kept", &placements).unwrap();
    });
    step(&|v| {
        v.mark_credential_used("kept", "passkey", 1_800_000_000, &TimeZone::UTC)
            .unwrap();
    });
    step(&|v| {
        let value = SecretString::from("three".to_string());
        v.add_or_update_item_credential("kept", "first", "First", FieldKind::Email, value)
            .unwrap();
    });
    step(&|v| {
        let id = v.list_history("kept", "first").unwrap()[0].id;
        v.purge_history("kept", "first", id).unwrap();
    });

    // Moves, trash, restore, and purge.
    step(&|v| {
        add_item(v, "other");
    });
    step(&|v| {
        v.transfer_item_credential("kept", "passkey", "other", "passkey", None)
            .unwrap();
    });
    step(&|v| v.delete_item_credential("other", "passkey").unwrap());
    step(&|v| {
        let beta = v.list_deleted("kept").unwrap()[0].credential.id;
        v.restore_item_credential("kept", beta, None).unwrap();
    });
    step(&|v| {
        let beta = v.get_item_credential("kept", "beta").unwrap().id;
        v.delete_item_credential("kept", "beta").unwrap();
        v.purge_item_credential("kept", beta).unwrap();
    });
    step(&|v| v.delete_item("other").unwrap());
    step(&|v| {
        let deleted = v.list_deleted_items();
        let other = deleted.iter().find(|d| d.item.key == "other").unwrap();
        let other = other.item.id;
        v.restore_item(other, None).unwrap();
    });
    step(&|v| {
        let other = *v.get_item_id("other").unwrap();
        v.delete_item("other").unwrap();
        v.purge_item(other).unwrap();
    });
    step(&|v| {
        let removed = v.list_deleted_items()[0].item.id;
        v.purge_item(removed).unwrap();
    });
}

#[test]
fn placement_folder_and_slot_naming_purged_entry_resolve_and_nothing_written_back() {
    let mut vault = Vault::new_for_test();
    let folder = vault.create_folder("Folder").id;
    let item = add_item(&mut vault, "item");
    let section = vault.create_item_section("item", "Section").unwrap().id;
    let field = add_credential(&mut vault, "item", "field", "value");
    let pass = add_credential(&mut vault, "item", "pass", "secret");
    let mut a = Mac::first(vault);
    let mut b = Mac::joined(&a, 2);

    a.edit(|v| {
        v.delete_folder(folder).unwrap();
        v.delete_item_section("item", section).unwrap();
        v.delete_item_credential("item", "pass").unwrap();
        v.purge_item_credential("item", pass).unwrap();
    });
    b.edit(|v| {
        v.move_item("item", Some(folder)).unwrap();
        v.move_item_credential("item", "field", Some(section))
            .unwrap();
        let autofill = ItemAutofill {
            password: Some(pass),
            ..ItemAutofill::default()
        };
        v.set_item_autofill("item", autofill).unwrap();
    });
    sync(&mut a, &mut b);

    for mac in [&a, &b] {
        let shown = &mac.view().items[&item];
        assert_eq!(shown.folder, None);
        assert_eq!(shown.password, None);
        assert_eq!(mac.view().credentials[&field].section, None);
        let stored = mac.vault.get_item("item").unwrap();
        assert_eq!(stored.folder, None);
        assert!(stored.sections.is_empty());
        assert_eq!(stored.autofill.password, None);
        assert_eq!(stored.credentials[&field].section, None);
        assert!(!stored.credentials.contains_key(&pass));
        // The registers still name the purged entries.
        let registers = mac.state.store.items.get(&item).unwrap();
        assert_eq!(
            registers.folder.values().next().unwrap().1.value,
            Some(folder)
        );
    }
}

#[test]
fn website_reorder_syncs() {
    let mut vault = Vault::new_for_test();
    add_item(&mut vault, "item");
    vault
        .set_item_autofill("item", websites(&["a.com", "b.com", "c.com"]))
        .unwrap();
    let mut a = Mac::first(vault);
    let mut b = Mac::joined(&a, 2);

    let reordered = ["c.com", "a.com", "b.com"];
    a.edit(|v| v.set_item_autofill("item", websites(&reordered)).unwrap());
    b.join(&a);
    let urls: Vec<String> = b
        .vault
        .get_item("item")
        .unwrap()
        .autofill
        .websites
        .iter()
        .map(|w| w.url.clone())
        .collect();
    assert_eq!(urls, reordered);
}

#[test]
fn duplicate_keys_apply_suffixed_keys_and_write_nothing() {
    let mut a = Mac::first(Vault::new_for_test());
    let mut b = Mac::joined(&a, 2);
    let mut x = Uuid::nil();
    a.edit(|v| {
        x = add_item(v, "dup");
        add_credential(v, "dup", "field", "1");
    });
    let mut y = Uuid::nil();
    b.edit(|v| y = add_item(v, "dup"));
    // A credential with the same key in the item of `a`, from another Mac.
    let other = Uuid::from_u128(77);
    b.state = edited(&b.state, 9, |s, m| {
        let entry = s.credentials.entry(other);
        entry.item.write(m, x);
        entry.key.write(m, "field".to_string());
    });
    sync(&mut a, &mut b);

    for mac in [&a, &b] {
        let keys = item_keys(&mac.vault);
        assert_eq!(keys, item_keys(&a.vault));
        let bare = keys.iter().filter(|(_, key)| key == "dup").count();
        let suffixed = keys
            .iter()
            .filter(|(_, key)| key.starts_with("dup-"))
            .count();
        assert_eq!((bare, suffixed), (1, 1));
        let fields: Vec<String> = mac
            .vault
            .get_item_by_id(x)
            .unwrap()
            .credentials
            .values()
            .map(|c| c.key.clone())
            .collect();
        assert_eq!(fields.iter().filter(|k| *k == "field").count(), 1);
        assert_eq!(fields.iter().filter(|k| k.starts_with("field-")).count(), 1);
        // The registers hold the keys as written.
        let registers = mac.state.store.items.get(&x).unwrap();
        assert_eq!(registers.key.values().next().unwrap().1.value, "dup");
    }
}

#[test]
fn view_that_swaps_two_keys_applies_without_error() {
    let mut vault = Vault::new_for_test();
    let first = add_item(&mut vault, "aaa");
    let second = add_item(&mut vault, "bbb");
    let x = add_credential(&mut vault, "aaa", "xxx", "1");
    let y = add_credential(&mut vault, "aaa", "yyy", "2");
    let mut mac = Mac::first(vault);

    mac.state = edited(&mac.state, 9, |s, m| {
        s.items.entry(first).key.write(m, "bbb".to_string());
        s.items.entry(second).key.write(m, "aaa".to_string());
        s.credentials.entry(x).key.write(m, "yyy".to_string());
        s.credentials.entry(y).key.write(m, "xxx".to_string());
    });
    let report = mac.apply();

    assert_eq!(*mac.vault.get_item_id("bbb").unwrap(), first);
    assert_eq!(*mac.vault.get_item_id("aaa").unwrap(), second);
    assert_eq!(mac.vault.get_item_credential("bbb", "yyy").unwrap().id, x);
    assert_eq!(mac.vault.get_item_credential("bbb", "xxx").unwrap().id, y);
    let change = |entity, from: &str, to: &str| KeyChange {
        entity,
        from: from.to_string(),
        to: to.to_string(),
    };
    let mut expected = vec![
        change(Entity::Item(first), "aaa", "bbb"),
        change(Entity::Item(second), "bbb", "aaa"),
    ];
    let mut credentials = vec![
        change(Entity::Credential(x), "xxx", "yyy"),
        change(Entity::Credential(y), "yyy", "xxx"),
    ];
    credentials.sort_by_key(|c| c.entity);
    expected.sort_by_key(|c| c.entity);
    expected.extend(credentials);
    assert_eq!(report.key_changes, expected);
}

#[test]
fn entries_placed_at_same_position_on_two_macs_show_same_order_and_apply_finds_no_edits() {
    let mut vault = Vault::new_for_test();
    let f1 = vault.create_folder("F1").id;
    let f2 = vault.create_folder("F2").id;
    vault.reorder_folders(&[f1, f2]).unwrap();
    let item = add_item(&mut vault, "item");
    let s1 = vault.create_item_section("item", "S1").unwrap().id;
    let s2 = vault.create_item_section("item", "S2").unwrap().id;
    let c1 = add_credential(&mut vault, "item", "one", "1");
    let c2 = add_credential(&mut vault, "item", "two", "2");
    let unsectioned = |keys: &[&str]| -> Vec<CredentialPlacement> {
        keys.iter()
            .map(|key| CredentialPlacement {
                key: key.to_string(),
                section: None,
            })
            .collect()
    };
    vault
        .reorder_item_credentials("item", &unsectioned(&["one", "two"]))
        .unwrap();
    let mut a = Mac::first(vault);
    let mut b = Mac::joined(&a, 2);

    // Each Mac places a new folder, section, and credential first.
    let place_first = |v: &mut Vault, title: &str| {
        let folder = v.create_folder(title).id;
        v.reorder_folders(&[folder, f1, f2]).unwrap();
        let section = v.create_item_section("item", title).unwrap().id;
        v.reorder_item_sections("item", &[section, s1, s2]).unwrap();
        let key = title.to_lowercase();
        add_credential(v, "item", &key, "value");
        v.reorder_item_credentials("item", &unsectioned(&[&key, "one", "two"]))
            .unwrap();
    };
    a.edit(|v| place_first(v, "Yyy"));
    b.edit(|v| place_first(v, "Xxx"));
    sync(&mut a, &mut b);

    let orders = |v: &Vault| {
        let folders = list_order(
            v.list_folders()
                .iter()
                .map(|f| (f.id, f.position, f.title.as_str())),
        );
        let item = v.get_item("item").unwrap();
        let sections = list_order(
            item.sections
                .values()
                .map(|s| (s.id, s.position, s.title.as_str())),
        );
        let credentials = list_order(
            item.credentials
                .values()
                .map(|c: &VaultItemCredentialOverview| (c.id, c.position, c.title.as_str())),
        );
        (folders, sections, credentials)
    };
    let (folders, sections, credentials) = orders(&a.vault);
    assert_eq!(
        orders(&b.vault),
        (folders.clone(), sections.clone(), credentials.clone())
    );
    let titles = |ids: &[Uuid], title: &dyn Fn(Uuid) -> String| -> Vec<String> {
        ids.iter().map(|id| title(*id)).collect()
    };
    let folder_title = |id| a.vault.get_folder(id).unwrap().title.clone();
    assert_eq!(titles(&folders, &folder_title), ["Xxx", "Yyy", "F1", "F2"]);
    let stored = a.vault.get_item("item").unwrap();
    let section_title = |id| stored.sections[&id].title.clone();
    assert_eq!(
        titles(&sections, &section_title),
        ["Xxx", "Yyy", "S1", "S2"]
    );
    assert_eq!(credentials[2..], [c1, c2]);
    assert_eq!(a.view().items[&item].credentials, credentials);
}

#[test]
fn edits_concurrent_with_trash_leave_trashed_entry_with_edits() {
    let mut vault = Vault::new_for_test();
    let item = add_item(&mut vault, "item");
    add_item(&mut vault, "other");
    let user = add_credential(&mut vault, "item", "user", "ada");
    let pass = add_credential(&mut vault, "item", "pass", "secret");
    let moved = add_credential(&mut vault, "other", "moved", "value");
    let autofill = ItemAutofill {
        password: Some(pass),
        ..ItemAutofill::default()
    };
    vault.set_item_autofill("item", autofill).unwrap();
    let mut a = Mac::first(vault);
    let mut b = Mac::joined(&a, 2);

    let mut added = Uuid::nil();
    a.edit(|v| {
        v.add_or_update_item("item", "Edited").unwrap();
        added = add_credential(v, "item", "added", "new");
        v.transfer_item_credential("other", "moved", "item", "moved", None)
            .unwrap();
        let autofill = ItemAutofill {
            username: Some(user),
            password: Some(pass),
            ..ItemAutofill::default()
        };
        v.set_item_autofill("item", autofill).unwrap();
    });
    b.edit(|v| v.delete_item("item").unwrap());
    sync(&mut a, &mut b);

    for mac in [&a, &b] {
        assert!(mac.vault.get_item("item").is_err());
        let trashed = mac.vault.list_deleted_items();
        let trashed = trashed.iter().find(|d| d.item.id == item).unwrap();
        assert_eq!(trashed.item.title, "Edited");
        assert!(trashed.item.credentials.contains_key(&added));
        assert!(trashed.item.credentials.contains_key(&moved));
        assert_eq!(trashed.item.autofill.username, Some(user));
        let value = mac
            .vault
            .get_deleted_credential_secret(item, moved)
            .unwrap();
        assert_eq!(value.expose_secret(), "value");
    }

    // An edit to a credential concurrent with its trash.
    a.edit(|v| v.restore_item(item, None).map(|_| ()).unwrap());
    b.join(&a);
    a.edit(|v| {
        let value = SecretString::from("grace".to_string());
        v.add_or_update_item_credential("item", "user", "Edited", FieldKind::default(), value)
            .unwrap();
    });
    b.edit(|v| v.delete_item_credential("item", "user").unwrap());
    sync(&mut a, &mut b);

    for mac in [&a, &b] {
        let trashed = mac.vault.list_deleted("item").unwrap();
        assert_eq!(trashed.len(), 1);
        assert_eq!(trashed[0].credential.id, user);
        assert_eq!(trashed[0].credential.title, "Edited");
        let value = mac.vault.get_deleted_credential_secret(item, user).unwrap();
        assert_eq!(value.expose_secret(), "grace");
        assert_eq!(mac.vault.get_item("item").unwrap().autofill.username, None);
    }
}

#[test]
fn view_of_two_full_signal_stores_applies_every_entry_and_next_report_trims() {
    let mut a = Mac::first(Vault::new_for_test());
    let mut b = Mac::joined(&a, 2);
    a.edit(|v| {
        v.update_passkey_signals(|s| {
            for n in 0..500 {
                s.record(report(n), i64::from(n));
            }
        })
    });
    b.edit(|v| {
        v.update_passkey_signals(|s| {
            for n in 500..1000 {
                s.record(report(n), i64::from(n));
            }
        })
    });
    sync(&mut a, &mut b);
    assert_eq!(a.vault.passkey_signals().entries().count(), 1000);
    assert_eq!(b.vault.passkey_signals().entries().count(), 1000);

    a.vault
        .update_passkey_signals(|s| s.record(report(1000), 1000));
    assert_eq!(a.vault.passkey_signals().entries().count(), 500);
    let edits = a.find();
    let removed = edits
        .edits()
        .iter()
        .filter(|e| matches!(e, Edit::RemoveSignal(_)))
        .count();
    assert_eq!(removed, 501);
}

#[test]
fn key_that_needs_normalizing_written_normalized() {
    let mut vault = Vault::new_for_test();
    let item = add_item(&mut vault, "item");
    let mut mac = Mac::first(vault);
    mac.state = edited(&mac.state, 9, |s, m| {
        s.items.entry(item).key.write(m, " My Item ".to_string());
    });
    let report = mac.apply();
    assert_eq!(*mac.vault.get_item_id("my-item").unwrap(), item);
    let expected = KeyChange {
        entity: Entity::Item(item),
        from: "item".to_string(),
        to: "my-item".to_string(),
    };
    assert_eq!(report.key_changes, [expected]);
    assert!(report.key_notices.is_empty());
}

#[test]
fn key_that_fails_validation_shown_suffixed_with_notice_and_nothing_written() {
    let mut vault = Vault::new_for_test();
    let item = add_item(&mut vault, "item");
    let mut mac = Mac::first(vault);
    mac.state = edited(&mac.state, 9, |s, m| {
        s.items.entry(item).key.write(m, "!!!".to_string());
    });
    let report = mac.apply();
    let key = &mac.vault.get_item_by_id(item).unwrap().key;
    assert!(key.starts_with("item-"), "{key}");
    assert_eq!(report.key_notices, [Entity::Item(item)]);
}

#[test]
fn restoring_credential_fills_slot_on_both_macs() {
    let mut vault = Vault::new_for_test();
    add_item(&mut vault, "item");
    let pass = add_credential(&mut vault, "item", "pass", "secret");
    let autofill = ItemAutofill {
        password: Some(pass),
        ..ItemAutofill::default()
    };
    vault.set_item_autofill("item", autofill).unwrap();
    let mut a = Mac::first(vault);
    let mut b = Mac::joined(&a, 2);

    a.edit(|v| v.delete_item_credential("item", "pass").unwrap());
    b.join(&a);
    assert_eq!(b.vault.get_item("item").unwrap().autofill.password, None);

    b.edit(|v| {
        v.restore_item_credential("item", pass, None).unwrap();
    });
    a.join(&b);
    for mac in [&a, &b] {
        let item = mac.vault.get_item("item").unwrap();
        assert_eq!(item.autofill.password, Some(pass));
        assert!(item.credentials.contains_key(&pass));
    }
}

#[test]
fn concurrent_trashes_and_trash_concurrent_with_restore_apply_with_entry_trashed() {
    let mut vault = Vault::new_for_test();
    let item = add_item(&mut vault, "item");
    let field = add_credential(&mut vault, "item", "field", "value");
    add_item(&mut vault, "other");
    let mut a = Mac::first(vault);
    let mut b = Mac::joined(&a, 2);

    a.edit(|v| v.delete_item_credential("item", "field").unwrap());
    b.edit(|v| v.delete_item_credential("item", "field").unwrap());
    a.edit(|v| v.delete_item("item").unwrap());
    b.edit(|v| v.delete_item("item").unwrap());
    sync(&mut a, &mut b);
    for mac in [&a, &b] {
        assert!(mac.vault.get_item("item").is_err());
        let trashed = mac.vault.list_deleted_items();
        let trashed = trashed.iter().find(|d| d.item.id == item).unwrap();
        assert_eq!(trashed.deleted_credentials[0].id, field);
    }

    // A restore on this Mac and a trash from another.
    a.edit(|v| {
        v.restore_item(item, None).unwrap();
    });
    b.state = edited(&b.state, 9, |s, m| {
        let trashed = Some(TrashValue {
            deleted_at: 5,
            role: None,
        });
        s.items.entry(item).trashed.write(m, trashed);
    });
    a.join(&b);
    assert!(a.vault.get_item("item").is_err());
    assert!(
        a.vault
            .list_deleted_items()
            .iter()
            .any(|d| d.item.id == item)
    );
}

#[test]
fn applying_same_view_twice_changes_nothing_and_reports_nothing() {
    let a = Mac::first(filled());
    let mut b = Mac::joined(&a, 2);
    assert_eq!(b.apply(), ApplyReport::default());
}

#[test]
fn key_changed_because_peer_claimed_it_first_reported_and_local_rename_not() {
    let mut a = Mac::first(Vault::new_for_test());
    let mut b = Mac::joined(&a, 2);
    let mut x = Uuid::nil();
    a.edit(|v| x = add_item(v, "dup"));
    let mut y = Uuid::nil();
    b.edit(|v| y = add_item(v, "dup"));
    let (report_a, report_b) = sync(&mut a, &mut b);

    // Each Mac reports the key change of its own item only, if a peer
    // claimed the key first.
    let changes: Vec<(Entity, &str)> = report_a
        .key_changes
        .iter()
        .chain(&report_b.key_changes)
        .map(|c| (c.entity, c.from.as_str()))
        .collect();
    assert_eq!(changes.len(), 1);
    let suffixed = changes[0].0;
    assert_eq!(changes[0].1, "dup");
    let own = if report_a.key_changes.is_empty() {
        y
    } else {
        x
    };
    assert_eq!(suffixed, Entity::Item(own));

    // A local rename, through a trash and a restore with a new key, of an
    // item with no duplicate.
    let mut solo = Uuid::nil();
    a.edit(|v| solo = add_item(v, "solo"));
    a.edit(|v| {
        v.delete_item("solo").unwrap();
        v.restore_item(solo, Some("renamed".to_string())).unwrap();
    });
    assert_eq!(a.apply(), ApplyReport::default());
    assert_eq!(a.vault.get_item_by_id(solo).unwrap().key, "renamed");
}

#[test]
fn report_lists_every_entity_changed() {
    let vault = filled();
    let mut ids: Vec<Entity> = vec![Entity::Vault];
    for item in vault.list_items() {
        ids.push(Entity::Item(item.id));
        ids.extend(item.credentials.keys().map(|id| Entity::Credential(*id)));
    }
    for item in vault.list_deleted_items() {
        ids.push(Entity::Item(item.item.id));
        ids.extend(
            item.item
                .credentials
                .keys()
                .map(|id| Entity::Credential(*id)),
        );
        ids.extend(
            item.deleted_credentials
                .iter()
                .map(|c| Entity::Credential(c.id)),
        );
    }
    ids.extend(
        vault
            .list_deleted("kept")
            .unwrap()
            .iter()
            .map(|c| Entity::Credential(c.credential.id)),
    );
    ids.sort();

    let a = Mac::first(vault);
    let mut b = Mac::empty(2);
    let report = b.join(&a);
    let changed: Vec<Entity> = report.changed.into_iter().collect();
    assert_eq!(changed, ids);
    assert!(report.key_changes.is_empty());
}
