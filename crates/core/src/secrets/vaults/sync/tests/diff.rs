use jiff::tz::TimeZone;
use secrecy::SecretString;
use uuid::Uuid;

use super::view::{State, edited, join};
use super::{NOW, id, session};
use crate::secrets::vaults::autofill::item::{ItemAutofill, MatchKind, Website};
use crate::secrets::vaults::format::encrypted_vault::VaultFileKey;
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::model::{CredentialPlacement, CredentialUpdate, Vault};
use crate::secrets::vaults::passkey::signals::{
    Report, SignalStore, clear_pending, record_pending,
};
use crate::secrets::vaults::sync::crdt::{CausalStore, ReplicaId, Session, WriteId};
use crate::secrets::vaults::sync::diff::{CredentialWrite, DiffError, Edit, LocalEdits};
use crate::secrets::vaults::sync::model::{FolderValue, Placement, SectionValue, WebsiteValue};
use crate::secrets::vaults::sync::view::VaultView;

const DAY: i64 = 86_400;

/// Sync state of one Mac and its session.
struct Mac {
    state: State,
    session: Session,
}

impl Mac {
    /// Mac of replica `n` with an empty state.
    fn new(n: u128) -> Self {
        Self {
            state: State::default(),
            session: session(n),
        }
    }

    /// Mac of replica `n` with a copy of the state of this Mac.
    fn copy(&self, n: u128) -> Self {
        Self {
            state: self.state.clone(),
            session: session(n),
        }
    }

    fn find(&self, vault: &Vault) -> LocalEdits {
        LocalEdits::find(&self.state, vault, self.session.replica).unwrap()
    }

    fn record(&mut self, edits: LocalEdits) -> Option<WriteId> {
        edits.record(&mut self.state, &mut self.session, NOW)
    }

    /// Record the edits of `vault`, which must not be empty, and check that
    /// the vault then has none. Returns the view.
    fn record_change(&mut self, vault: &Vault) -> VaultView {
        let edits = self.find(vault);
        assert!(!edits.is_empty());
        self.record(edits);
        self.assert_no_edits(vault);
        VaultView::of(&self.state)
    }

    fn assert_no_edits(&self, vault: &Vault) {
        let edits = self.find(vault);
        assert!(edits.is_empty(), "{:?}", edits.edits());
    }
}

fn add_item(vault: &mut Vault, key: &str) -> Uuid {
    vault.add_or_update_item(key, "Item").unwrap().id
}

fn add_credential(vault: &mut Vault, item: &str, key: &str, value: &str) -> Uuid {
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

/// Copy of `vault` with the same ids.
fn copy(vault: &Vault) -> Vault {
    vault
        .rekeyed(None, |_| Ok(VaultFileKey::new(vec![0; 32])))
        .unwrap()
}

#[test]
fn vault_diffed_against_view_of_own_sync_state_finds_no_edits() {
    let mut vault = Vault::new_for_test();
    vault.fill_for_test();
    let mut mac = Mac::new(1);
    mac.record_change(&vault);
}

#[test]
fn website_order_equal_to_view_finds_no_edits_and_reorder_writes_positions() {
    let mut vault = Vault::new_for_test();
    let item = add_item(&mut vault, "item");
    let urls = ["a.com", "b.com", "c.com"];
    vault.set_item_autofill("item", websites(&urls)).unwrap();
    let mut mac = Mac::new(1);
    mac.record_change(&vault);

    // Stored positions with a gap and a tie, in the same order.
    let value = |position| WebsiteValue {
        match_kind: MatchKind::Domain,
        position,
    };
    mac.state = edited(&mac.state, 2, |s, m| {
        let entry = &mut s.items.entry(item).websites;
        for (url, position) in urls.into_iter().zip([0, 5, 5]) {
            entry.entry(url.to_string()).write(m, value(position));
        }
    });
    mac.assert_no_edits(&vault);

    let reordered = ["a.com", "c.com", "b.com"];
    vault
        .set_item_autofill("item", websites(&reordered))
        .unwrap();
    let edits = mac.find(&vault);
    let expected = [
        Edit::Website(item, "c.com".to_string(), value(1)),
        Edit::Website(item, "b.com".to_string(), value(2)),
    ];
    assert_eq!(edits.edits(), expected);
    mac.record(edits);
    let view = VaultView::of(&mac.state);
    let shown: Vec<_> = view.items[&item]
        .websites
        .iter()
        .map(|w| w.url.as_str())
        .collect();
    assert_eq!(shown, reordered);
    mac.assert_no_edits(&vault);
}

#[test]
fn folder_section_and_credential_order_equal_to_view_finds_no_edits() {
    let mut vault = Vault::new_for_test();
    let a = vault.create_folder("A").id;
    let b = vault.create_folder("B").id;
    let c = vault.create_folder("C").id;
    vault.reorder_folders(&[c, a, b]).unwrap();
    let item = add_item(&mut vault, "item");
    let one = vault.create_item_section("item", "One").unwrap().id;
    let two = vault.create_item_section("item", "Two").unwrap().id;
    vault.reorder_item_sections("item", &[two, one]).unwrap();
    let [x, y, z] = ["xxx", "yyy", "zzz"].map(|key| add_credential(&mut vault, "item", key, key));
    let placements = ["zzz", "xxx", "yyy"].map(|key| CredentialPlacement {
        key: key.to_string(),
        section: None,
    });
    vault.reorder_item_credentials("item", &placements).unwrap();
    let mut mac = Mac::new(1);
    mac.record_change(&vault);

    // Stored positions with gaps and ties, in the same order.
    mac.state = edited(&mac.state, 2, |s, m| {
        for (folder, title, position) in [(c, "C", 10), (a, "A", 20), (b, "B", 20)] {
            let value = FolderValue {
                title: title.to_string(),
                position: Some(position),
            };
            s.folders.entry(folder).write(m, value);
        }
        for (section, title, position) in [(two, "Two", 4), (one, "One", 9)] {
            let value = SectionValue {
                title: title.to_string(),
                position: Some(position),
            };
            s.items.entry(item).sections.entry(section).write(m, value);
        }
        for (credential, position) in [(z, 3), (x, 7), (y, 7)] {
            let placement = Placement {
                section: None,
                position: Some(position),
            };
            s.credentials
                .entry(credential)
                .placement
                .write(m, placement);
        }
    });
    let view = VaultView::of(&mac.state);
    assert_eq!(view.folders[1].position, Some(20));
    assert_eq!(view.items[&item].credentials, [z, x, y]);
    mac.assert_no_edits(&vault);
}

#[test]
fn signal_lists_in_other_order_find_no_edits() {
    let mut vault = Vault::new_for_test();
    let report = |byte| Report::Unknown {
        rp_id: "example.com".to_string(),
        credential_id: vec![byte],
    };
    vault.update_passkey_signals(|signals| {
        signals.record(report(1), 5);
        signals.record(report(2), 1);
    });
    let mut mac = Mac::new(1);
    let view = mac.record_change(&vault);

    let stored: Vec<_> = vault.passkey_signals().entries().collect();
    let shown: Vec<_> = view.signals.entries().collect();
    assert_ne!(stored, shown);
    assert_eq!(stored, [shown[1].clone(), shown[0].clone()]);
}

#[test]
fn empty_slot_for_trashed_credential_finds_no_edits() {
    let mut vault = Vault::new_for_test();
    let item = add_item(&mut vault, "item");
    add_item(&mut vault, "other");
    let user = add_credential(&mut vault, "item", "user", "ada");
    let pass = add_credential(&mut vault, "item", "pass", "secret");
    let autofill = ItemAutofill {
        username: Some(user),
        password: Some(pass),
        ..ItemAutofill::default()
    };
    vault.set_item_autofill("item", autofill).unwrap();
    let mut mac = Mac::new(1);
    mac.record_change(&vault);

    vault.delete_item_credential("item", "user").unwrap();
    let view = mac.record_change(&vault);
    assert_eq!(view.items[&item].username, None);
    let registers = mac.state.store.items.get(&item).unwrap();
    assert_eq!(
        registers.username.values().next().unwrap().1.value,
        Some(user)
    );

    vault
        .transfer_item_credential("item", "pass", "other", "pass", None)
        .unwrap();
    let view = mac.record_change(&vault);
    assert_eq!(view.items[&item].password, None);
    let registers = mac.state.store.items.get(&item).unwrap();
    assert_eq!(
        registers.password.values().next().unwrap().1.value,
        Some(pass)
    );
}

#[test]
fn history_in_other_list_order_finds_no_edits() {
    let mut vault = Vault::new_for_test();
    add_item(&mut vault, "item");
    let mut credential = Uuid::nil();
    for value in ["1", "2", "3"] {
        credential = add_credential(&mut vault, "item", "field", value);
    }
    let mut mac = Mac::new(1);
    mac.record_change(&vault);

    let ids = |vault: &Vault| -> Vec<Uuid> {
        let history = vault.list_history("item", "field").unwrap();
        history.iter().map(|h| h.id).collect()
    };
    let before = ids(&vault);
    assert_eq!(before.len(), 2);
    vault.reverse_history_for_test(credential);
    assert_ne!(ids(&vault), before);
    mac.assert_no_edits(&vault);
}

#[test]
fn last_used_times_converge_on_later_time() {
    let mut vault = Vault::new_for_test();
    add_item(&mut vault, "item");
    let passkey = vault
        .add_or_update_item_credential(
            "item",
            "passkey",
            "Passkey",
            FieldKind::Passkey,
            SecretString::from("{}".to_string()),
        )
        .unwrap()
        .id;
    let mut mac = Mac::new(1);
    mac.record_change(&vault);

    let used = |day: i64| {
        let mut copy = copy(&vault);
        let used = copy
            .mark_credential_used("item", "passkey", day * DAY, &TimeZone::UTC)
            .unwrap();
        assert!(used);
        copy
    };
    let (vault_a, vault_b) = (used(3), used(2));
    let (mut a, mut b) = (mac.copy(2), mac.copy(3));
    a.record_change(&vault_a);
    b.record_change(&vault_b);

    let (ab, ba) = join(&a.state, &b.state);
    let view = VaultView::of(&ab);
    assert_eq!(view, VaultView::of(&ba));
    assert_eq!(view.credentials[&passkey].last_used_day_at, Some(3 * DAY));
    assert!(view.conflicts().is_empty());
    // Each replica wrote only its own register.
    let registers = &ab.store.credentials.get(&passkey).unwrap().last_used_day_at;
    let own = |n: u128| {
        let register = registers.get(&ReplicaId(id(n))).unwrap();
        let values: Vec<i64> = register.values().map(|(_, v)| v.value).collect();
        values
    };
    assert_eq!(own(2), [3 * DAY]);
    assert_eq!(own(3), [2 * DAY]);

    a.state = ab;
    b.state = ba;
    a.assert_no_edits(&vault_a);
    b.assert_no_edits(&vault_b);
}

#[test]
fn each_local_change_found_and_recorded_in_its_register() {
    let mut vault = Vault::new_for_test();
    let mut mac = Mac::new(1);
    let utc = TimeZone::UTC;

    // Vault name and folders.
    vault.name = Some("Vault".to_string());
    let view = mac.record_change(&vault);
    assert_eq!(view.name.as_deref(), Some("Vault"));

    let folder = vault.create_folder("Folder").id;
    let view = mac.record_change(&vault);
    assert_eq!(view.folders[0].id, folder);
    assert_eq!(view.folders[0].title, "Folder");

    vault.rename_folder(folder, "Renamed").unwrap();
    let view = mac.record_change(&vault);
    assert_eq!(view.folders[0].title, "Renamed");

    let other_folder = vault.create_folder("A").id;
    let view = mac.record_change(&vault);
    let order: Vec<_> = view.folders.iter().map(|f| f.id).collect();
    assert_eq!(order, [other_folder, folder]);
    vault.reorder_folders(&[folder, other_folder]).unwrap();
    let view = mac.record_change(&vault);
    let order: Vec<_> = view.folders.iter().map(|f| f.id).collect();
    assert_eq!(order, [folder, other_folder]);

    vault.delete_folder(other_folder).unwrap();
    let view = mac.record_change(&vault);
    assert_eq!(view.folders.len(), 1);

    // Item registers.
    let item = add_item(&mut vault, "item");
    let view = mac.record_change(&vault);
    assert_eq!(view.items[&item].title, "Item");

    vault.add_or_update_item("item", "Title").unwrap();
    let view = mac.record_change(&vault);
    assert_eq!(view.items[&item].title, "Title");

    vault
        .set_item_category("item", Some("login".to_string()))
        .unwrap();
    let view = mac.record_change(&vault);
    assert_eq!(view.items[&item].category.as_deref(), Some("login"));

    vault.delete_item("item").unwrap();
    let view = mac.record_change(&vault);
    assert!(view.items[&item].trashed.is_some());

    vault
        .restore_item(item, Some("renamed".to_string()))
        .unwrap();
    let view = mac.record_change(&vault);
    assert_eq!(view.items[&item].trashed, None);
    assert_eq!(view.items[&item].key, "renamed");

    vault.move_item("renamed", Some(folder)).unwrap();
    let view = mac.record_change(&vault);
    assert_eq!(view.items[&item].folder, Some(folder));

    let section = vault.create_item_section("renamed", "Section").unwrap().id;
    let view = mac.record_change(&vault);
    assert_eq!(view.items[&item].sections[0].id, section);

    vault
        .set_item_autofill("renamed", websites(&["a.com"]))
        .unwrap();
    let view = mac.record_change(&vault);
    assert_eq!(view.items[&item].websites[0].url, "a.com");

    // Credential registers.
    let field = vault
        .add_item_credential(
            "renamed",
            "field",
            "Field",
            FieldKind::default(),
            SecretString::from("one".to_string()),
        )
        .unwrap()
        .id;
    let view = mac.record_change(&vault);
    assert_eq!(view.credentials[&field].value.0.as_str(), "one");
    assert_eq!(view.items[&item].credentials, [field]);

    let autofill = ItemAutofill {
        password: Some(field),
        ..websites(&["a.com"])
    };
    vault.set_item_autofill("renamed", autofill).unwrap();
    let view = mac.record_change(&vault);
    assert_eq!(view.items[&item].password, Some(field));

    let update =
        |title: Option<&str>, kind: Option<FieldKind>, key: Option<&str>| CredentialUpdate {
            key: key.map(str::to_string),
            title: title.map(str::to_string),
            kind,
        };
    vault
        .update_item_credential("renamed", "field", update(Some("Title"), None, None))
        .unwrap();
    let view = mac.record_change(&vault);
    assert_eq!(view.credentials[&field].title, "Title");

    vault
        .update_item_credential(
            "renamed",
            "field",
            update(None, Some(FieldKind::Email), None),
        )
        .unwrap();
    let view = mac.record_change(&vault);
    assert_eq!(view.credentials[&field].kind, FieldKind::Email);

    vault
        .update_item_credential("renamed", "field", update(None, None, Some("email")))
        .unwrap();
    let view = mac.record_change(&vault);
    assert_eq!(view.credentials[&field].key, "email");

    vault
        .add_or_update_item_credential(
            "renamed",
            "email",
            "Title",
            FieldKind::Email,
            SecretString::from("two".to_string()),
        )
        .unwrap();
    let view = mac.record_change(&vault);
    let shown = &view.credentials[&field];
    assert_eq!(shown.value.0.as_str(), "two");
    assert_eq!(shown.history.len(), 1);
    assert_eq!(shown.history[0].value.0.as_str(), "one");
    let history_id = shown.history[0].id;

    vault
        .move_item_credential("renamed", "email", Some(section))
        .unwrap();
    let view = mac.record_change(&vault);
    assert_eq!(view.credentials[&field].section, Some(section));

    let second = add_credential(&mut vault, "renamed", "second", "value");
    mac.record_change(&vault);
    // Without positions, "SECOND" is listed before "Title".
    let placements = ["email", "second"].map(|key| CredentialPlacement {
        key: key.to_string(),
        section: Some(section),
    });
    vault
        .reorder_item_credentials("renamed", &placements)
        .unwrap();
    let view = mac.record_change(&vault);
    assert_eq!(view.credentials[&second].section, Some(section));
    assert_eq!(view.credentials[&field].position, Some(0));
    assert_eq!(view.credentials[&second].position, Some(1));

    vault.purge_history("renamed", "email", history_id).unwrap();
    let view = mac.record_change(&vault);
    assert!(view.credentials[&field].history.is_empty());

    vault
        .mark_credential_used("renamed", "email", DAY, &utc)
        .unwrap();
    let view = mac.record_change(&vault);
    assert_eq!(view.credentials[&field].last_used_day_at, Some(DAY));

    // Credential move, trash, restore, and purge.
    let other = add_item(&mut vault, "other");
    mac.record_change(&vault);
    vault
        .transfer_item_credential("renamed", "second", "other", "second", None)
        .unwrap();
    let view = mac.record_change(&vault);
    assert_eq!(view.credentials[&second].item, other);
    assert_eq!(view.items[&other].credentials, [second]);

    vault.delete_item_credential("other", "second").unwrap();
    let view = mac.record_change(&vault);
    assert!(view.credentials[&second].trashed.is_some());

    vault
        .restore_item_credential("other", second, None)
        .unwrap();
    let view = mac.record_change(&vault);
    assert_eq!(view.credentials[&second].trashed, None);

    vault.delete_item_credential("other", "second").unwrap();
    mac.record_change(&vault);
    vault.purge_item_credential("other", second).unwrap();
    let view = mac.record_change(&vault);
    assert!(!view.credentials.contains_key(&second));

    // Item trash, restore, and purge with its credentials.
    let kept = add_credential(&mut vault, "other", "kept", "value");
    mac.record_change(&vault);
    vault.delete_item("other").unwrap();
    let view = mac.record_change(&vault);
    assert!(view.items[&other].trashed.is_some());
    assert_eq!(view.credentials[&kept].trashed, None);

    vault.restore_item(other, None).unwrap();
    let view = mac.record_change(&vault);
    assert_eq!(view.items[&other].trashed, None);

    vault.delete_item("other").unwrap();
    mac.record_change(&vault);
    vault.purge_item(other).unwrap();
    let view = mac.record_change(&vault);
    assert!(!view.items.contains_key(&other));
    assert!(!view.credentials.contains_key(&kept));
    assert!(mac.state.store.credentials.get(&kept).is_none());

    // Signal record and trim.
    let report = |n: u32| Report::Unknown {
        rp_id: "example.com".to_string(),
        credential_id: n.to_be_bytes().to_vec(),
    };
    vault.update_passkey_signals(|signals| signals.record(report(0), 0));
    let view = mac.record_change(&vault);
    assert_eq!(view.signals.entries().count(), 1);
    let first = view.signals.entries().next().unwrap().key();

    vault.update_passkey_signals(|signals| {
        for n in 1..=500 {
            signals.record(report(n), i64::from(n));
        }
    });
    let edits = mac.find(&vault);
    assert!(edits.edits().contains(&Edit::RemoveSignal(first.clone())));
    let view = mac.record_change(&vault);
    assert_eq!(view.signals.entries().count(), 500);
    assert!(view.signals.entries().all(|e| e.key() != first));
}

#[test]
fn removal_only_diff_records_under_write_id_only_context_holds() {
    let mut vault = Vault::new_for_test();
    add_item(&mut vault, "item");
    add_credential(&mut vault, "item", "field", "one");
    add_credential(&mut vault, "item", "field", "two");
    let mut mac = Mac::new(1);
    mac.record_change(&vault);

    let history_id = vault.list_history("item", "field").unwrap()[0].id;
    vault.purge_history("item", "field", history_id).unwrap();
    let edits = mac.find(&vault);
    assert!(
        edits
            .edits()
            .iter()
            .all(|e| matches!(e, Edit::RemoveHistory(..)))
    );
    let write_id = mac.record(edits).unwrap();
    assert!(mac.state.context.covers(write_id));
    let found = mac.state.store.find_value(&mut |id, _| id == write_id);
    assert_eq!(found, None);
    mac.assert_no_edits(&vault);
}

#[test]
fn cleared_references_record_no_edit() {
    let mut vault = Vault::new_for_test();
    let folder = vault.create_folder("Folder").id;
    let item = add_item(&mut vault, "item");
    add_item(&mut vault, "other");
    vault.move_item("item", Some(folder)).unwrap();
    let section = vault.create_item_section("item", "Section").unwrap().id;
    let field = add_credential(&mut vault, "item", "field", "value");
    vault
        .move_item_credential("item", "field", Some(section))
        .unwrap();
    let pass = add_credential(&mut vault, "item", "pass", "secret");
    let autofill = ItemAutofill {
        username: Some(field),
        password: Some(pass),
        ..ItemAutofill::default()
    };
    vault.set_item_autofill("item", autofill).unwrap();
    let mut mac = Mac::new(1);
    mac.record_change(&vault);

    vault.delete_folder(folder).unwrap();
    let edits = mac.find(&vault);
    assert_eq!(edits.edits(), [Edit::RemoveFolder(folder)]);
    mac.record(edits);

    vault.delete_item_section("item", section).unwrap();
    let edits = mac.find(&vault);
    assert_eq!(edits.edits(), [Edit::RemoveSection(item, section)]);
    mac.record(edits);

    vault.delete_item_credential("item", "field").unwrap();
    let edits = mac.find(&vault);
    assert!(
        matches!(
            edits.edits(),
            [Edit::Credential(id, CredentialWrite::Trashed(Some(_)))] if *id == field
        ),
        "{:?}",
        edits.edits()
    );
    mac.record(edits);

    vault
        .transfer_item_credential("item", "pass", "other", "pass", None)
        .unwrap();
    let edits = mac.find(&vault);
    assert!(!edits.is_empty());
    assert!(
        edits
            .edits()
            .iter()
            .all(|e| matches!(e, Edit::Credential(id, _) if *id == pass)),
        "{:?}",
        edits.edits()
    );
    mac.record(edits);
    mac.assert_no_edits(&vault);
}

#[test]
fn suffixed_key_in_vault_not_edit_and_rename_writes_new_key() {
    let mut vault = Vault::new_for_test();
    let item = add_item(&mut vault, "item");
    add_credential(&mut vault, "item", "xxx", "1");
    let y = add_credential(&mut vault, "item", "yyy", "2");
    let mut mac = Mac::new(1);
    mac.record_change(&vault);

    // Another Mac stores the key of `x` in `y`, so `y` is shown suffixed.
    mac.state = edited(&mac.state, 2, |s, m| {
        s.credentials.entry(y).key.write(m, "xxx".to_string());
    });
    let view = VaultView::of(&mac.state);
    let suffixed = view.credentials[&y].key.clone();
    assert_ne!(suffixed, "xxx");
    assert!(suffixed.starts_with("xxx-"));

    let update = |key: &str| CredentialUpdate {
        key: Some(key.to_string()),
        ..CredentialUpdate::default()
    };
    vault
        .update_item_credential("item", "yyy", update(&suffixed))
        .unwrap();
    mac.assert_no_edits(&vault);

    vault
        .update_item_credential("item", &suffixed, update("zzz"))
        .unwrap();
    let edits = mac.find(&vault);
    let expected = [Edit::Credential(y, CredentialWrite::Key("zzz".to_string()))];
    assert_eq!(edits.edits(), expected);
    mac.record(edits);
    let view = VaultView::of(&mac.state);
    assert_eq!(view.credentials[&y].key, "zzz");
    assert_eq!(view.items[&item].credentials.len(), 2);
}

#[test]
fn earlier_last_used_time_in_vault_not_edit() {
    let mut vault = Vault::new_for_test();
    add_item(&mut vault, "item");
    let field = add_credential(&mut vault, "item", "field", "value");
    vault
        .mark_credential_used("item", "field", DAY, &TimeZone::UTC)
        .unwrap();
    let mut mac = Mac::new(1);
    mac.record_change(&vault);

    mac.state = edited(&mac.state, 2, |s, m| {
        let entry = s.credentials.entry(field);
        entry
            .last_used_day_at
            .entry(ReplicaId(id(2)))
            .write(m, 2 * DAY);
    });
    let view = VaultView::of(&mac.state);
    assert_eq!(view.credentials[&field].last_used_day_at, Some(2 * DAY));
    mac.assert_no_edits(&vault);
}

#[test]
fn vault_with_two_websites_with_one_url_fails_diff() {
    let mut vault = Vault::new_for_test();
    let item = add_item(&mut vault, "item");
    let autofill = ItemAutofill {
        websites: vec![
            Website::new("a.com", MatchKind::Domain),
            Website::new("a.com", MatchKind::Host),
        ],
        ..ItemAutofill::default()
    };
    vault.set_item_autofill_unchecked_for_test("item", autofill);
    let err = LocalEdits::find(&State::default(), &vault, ReplicaId(id(1))).unwrap_err();
    assert!(
        matches!(&err, DiffError::DuplicateWebsite { item: i, url } if *i == item && url == "a.com"),
        "{err:?}"
    );
}

#[test]
fn diff_reads_stored_signals_and_pending_report_records_no_edit() {
    let mut vault = Vault::new_for_test();
    add_item(&mut vault, "item");
    let mut mac = Mac::new(1);
    mac.record_change(&vault);

    let report = || Report::Unknown {
        rp_id: "diff-pending.example".to_string(),
        credential_id: vec![7],
    };
    record_pending(report(), NOW);
    let edits = mac.find(&vault);
    let mut applied = SignalStore::new();
    applied.record(report(), NOW);
    clear_pending(&applied);
    assert!(edits.is_empty(), "{:?}", edits.edits());
}
