use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use super::super::view::edited;
use super::{Mac, add_credential, add_item, report, sync};
use crate::secrets::vaults::autofill::item::ItemAutofill;
use crate::secrets::vaults::model::Vault;
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::sync::diff::Edit;
use crate::secrets::vaults::sync::model::TrashValue;

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
