use jiff::tz::TimeZone;
use secrecy::SecretString;
use uuid::Uuid;

use super::super::view::edited;
use super::{Mac, add_credential, add_item, filled, reload, report, sync};
use crate::secrets::vaults::autofill::item::{ItemAutofill, MatchKind, Website};
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::model::{
    CredentialPlacement, CredentialUpdate, Vault, VaultItemCredentialOverview, display_order,
};
use crate::secrets::vaults::sync::apply::{ApplyReport, KeyChange};
use crate::secrets::vaults::sync::view::Entity;

fn websites(urls: &[&str]) -> ItemAutofill {
    ItemAutofill {
        websites: urls
            .iter()
            .map(|url| Website::new(*url, MatchKind::Domain))
            .collect(),
        ..ItemAutofill::default()
    }
}

/// Ids in list order: position, with no position last, then title, then id.
fn list_order<'a>(entries: impl Iterator<Item = (Uuid, Option<u32>, &'a str)>) -> Vec<Uuid> {
    let mut entries: Vec<_> = entries.collect();
    entries.sort_by(|a, b| (display_order(a.1, a.2), a.0).cmp(&(display_order(b.1, b.2), b.0)));
    entries.into_iter().map(|(id, _, _)| id).collect()
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
fn applying_same_view_twice_changes_nothing_and_reports_nothing() {
    let a = Mac::first(filled());
    let mut b = Mac::joined(&a, 2);
    assert_eq!(b.apply(), ApplyReport::default());
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
