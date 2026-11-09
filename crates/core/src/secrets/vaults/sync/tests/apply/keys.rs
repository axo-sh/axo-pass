use uuid::Uuid;

use super::super::view::edited;
use super::{Mac, add_credential, add_item, sync};
use crate::secrets::vaults::model::Vault;
use crate::secrets::vaults::sync::apply::{ApplyReport, KeyChange};
use crate::secrets::vaults::sync::view::Entity;

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
