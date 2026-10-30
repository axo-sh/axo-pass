use std::collections::BTreeSet;

use uuid::Uuid;

use super::view::{State, base, concurrent, edited, join, trash};
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::storage::handle::validate_key;
use crate::secrets::vaults::sync::crdt::Mint;
use crate::secrets::vaults::sync::model::{Placement, SecretText, SyncState};
use crate::secrets::vaults::sync::view::keys::{
    CREDENTIAL_KEY_PREFIX, ITEM_KEY_PREFIX, KeyGroup, KeyTaken, Suffix,
};
use crate::secrets::vaults::sync::view::{
    AskRegister, Conflict, Entity, RECOVERED_ITEM_TITLE, VaultView,
};

/// Entry id whose 16 bytes are `n`, so ids differ in their first base32
/// characters.
fn wide(n: u8) -> Uuid {
    Uuid::from_bytes([n; 16])
}

fn add_item(s: &mut SyncState, m: &Mint, item: Uuid, key: &str) {
    let entry = s.items.entry(item);
    entry.title.write(m, "Item".to_string());
    entry.key.write(m, key.to_string());
}

fn add_credential(s: &mut SyncState, m: &Mint, credential: Uuid, item: Uuid, key: &str) {
    let entry = s.credentials.entry(credential);
    entry.item.write(m, item);
    entry.title.write(m, "Field".to_string());
    entry.key.write(m, key.to_string());
}

/// Key register values of item `item`.
fn stored_item_keys(state: &State, item: Uuid) -> Vec<String> {
    let entry = state.store.items.get(&item).unwrap();
    entry.key.values().map(|(_, v)| v.value.clone()).collect()
}

#[test]
fn suffix_is_lowercase_rfc_4648_base32_without_padding() {
    let vectors = [
        ("", ""),
        ("f", "my"),
        ("fo", "mzxq"),
        ("foo", "mzxw6"),
        ("foob", "mzxw6yq"),
        ("fooba", "mzxw6ytb"),
        ("foobar", "mzxw6ytboi"),
    ];
    for (input, expected) in vectors {
        assert_eq!(Suffix::base32(input.as_bytes()), expected, "{input}");
    }
    let id = Uuid::from_bytes([0xff; 16]);
    assert_eq!(Suffix::base32(id.as_bytes()), "77777777777777777777777774");
    assert_eq!(Suffix::key("login", id, 4), "login-7777");
}

#[test]
fn purge_concurrent_with_restore_shows_one_recovered_item_with_remaining_credentials() {
    let (item, removed_a, removed_b) = (wide(1), wide(11), wide(12));
    let (kept_a, kept_b) = (wide(13), wide(14));
    let start = base(|s, m| {
        add_item(s, m, item, "login");
        add_credential(s, m, removed_a, item, "user");
        add_credential(s, m, removed_b, item, "pass");
        s.items.entry(item).trashed.write(m, trash(10, None));
    });
    let purge = |s: &mut SyncState, _: &Mint| {
        s.items.remove(&item);
        s.credentials.remove(&removed_a);
        s.credentials.remove(&removed_b);
    };
    let add = |s: &mut SyncState, m: &Mint| {
        add_credential(s, m, kept_a, item, "user");
        add_credential(s, m, kept_b, item, "code");
    };

    // Purge concurrent with a restore that adds credentials.
    let (_, view) = concurrent(&start, purge, |s, m| {
        s.items.entry(item).trashed.write(m, None);
        add(s, m);
    });
    assert_eq!(view.items.len(), 1);
    let shown = &view.items[&item];
    assert_eq!(shown.title, RECOVERED_ITEM_TITLE);
    assert_eq!(shown.trashed, None);
    assert!(validate_key(&shown.key));
    assert_eq!(shown.key, Suffix::key(ITEM_KEY_PREFIX, item, 4));
    assert_eq!(shown.credentials, [kept_a, kept_b]);
    assert!(!view.credentials.contains_key(&removed_a));
    assert!(!view.credentials.contains_key(&removed_b));
    assert!(view.key_notices().is_empty());

    // Purge concurrent with credentials added to the item only. The item has
    // no register, and its credentials appear in one recovered item.
    let (state, view) = concurrent(&start, purge, add);
    assert!(state.store.items.get(&item).is_none());
    assert_eq!(view.items.len(), 1);
    assert_eq!(view.items[&item].title, RECOVERED_ITEM_TITLE);
    assert_eq!(view.items[&item].credentials, [kept_a, kept_b]);
    assert_eq!(view.credentials[&kept_a].item, item);
    assert_eq!(view.credentials[&kept_a].key, "user");
    assert_eq!(view.credentials[&kept_b].key, "code");

    // A credential whose item register holds no value is shown in a
    // recovered item with its own id.
    let orphan = wide(20);
    let state = edited(&state, 2, |s, m| {
        let title = "Orphan".to_string();
        s.credentials.entry(orphan).title.write(m, title);
    });
    let view = VaultView::of(&state);
    assert_eq!(view.credentials[&orphan].item, orphan);
    assert_eq!(view.items[&orphan].title, RECOVERED_ITEM_TITLE);
    assert_eq!(view.items[&orphan].credentials, [orphan]);
}

#[test]
fn duplicate_keys_show_bare_key_on_lowest_order_key_and_suffix_on_others() {
    let (holder, first, second) = (wide(1), wide(2), wide(3));
    let (first_field, second_field) = (wide(11), wide(12));
    let start = base(|s, m| add_item(s, m, holder, "holder"));
    let (_, view) = concurrent(
        &start,
        |s, m| {
            add_item(s, m, first, "login");
            add_credential(s, m, first_field, holder, "user");
        },
        |s, m| {
            add_item(s, m, second, "login");
            add_credential(s, m, second_field, holder, "user");
        },
    );
    assert_eq!(view.items[&first].key, "login");
    assert_eq!(view.items[&second].key, Suffix::key("login", second, 4));
    assert_eq!(view.credentials[&first_field].key, "user");
    assert_eq!(
        view.credentials[&second_field].key,
        Suffix::key("user", second_field, 4)
    );
    assert!(view.key_notices().is_empty());
}

#[test]
fn established_key_is_kept_when_newer_duplicate_arrives() {
    let (established, newer) = (wide(2), wide(1));
    // Replica 3 has the higher actor id. The newer write orders above it by
    // counter.
    let start = edited(&State::default(), 3, |s, m| {
        add_item(s, m, established, "login");
    });
    let state = edited(&start, 2, |s, m| add_item(s, m, newer, "login"));
    let view = VaultView::of(&state);
    assert_eq!(view.items[&established].key, "login");
    assert_eq!(view.items[&newer].key, Suffix::key("login", newer, 4));
}

#[test]
fn suffix_equal_to_stored_or_assigned_key_grows_to_6_then_8_characters() {
    let (bare, duplicate, holds_4, holds_6) = (wide(1), wide(2), wide(3), wide(4));
    let start = base(|s, m| {
        add_item(s, m, bare, "login");
        add_item(s, m, duplicate, "login");
        add_item(s, m, holds_4, &Suffix::key("login", duplicate, 4));
    });
    let view = VaultView::of(&start);
    assert_eq!(view.items[&bare].key, "login");
    assert_eq!(
        view.items[&duplicate].key,
        Suffix::key("login", duplicate, 6)
    );
    assert_eq!(view.items[&holds_4].key, Suffix::key("login", duplicate, 4));

    let state = edited(&start, 1, |s, m| {
        add_item(s, m, holds_6, &Suffix::key("login", duplicate, 6));
    });
    let view = VaultView::of(&state);
    assert_eq!(
        view.items[&duplicate].key,
        Suffix::key("login", duplicate, 8)
    );

    // Two suffixes with the same first 4 characters. The first in order key
    // order, then id order, takes 4 characters.
    let later_bytes = [0xab; 16];
    let mut earlier_bytes = later_bytes;
    earlier_bytes[3] = 0x0b;
    let (later, earlier) = (
        Uuid::from_bytes(later_bytes),
        Uuid::from_bytes(earlier_bytes),
    );
    assert_eq!(
        Suffix::key("main", later, 4),
        Suffix::key("main", earlier, 4)
    );
    let state = base(|s, m| {
        add_item(s, m, bare, "main");
        add_item(s, m, later, "main");
        add_item(s, m, earlier, "main");
    });
    let view = VaultView::of(&state);
    assert_eq!(view.items[&bare].key, "main");
    assert_eq!(view.items[&earlier].key, Suffix::key("main", earlier, 4));
    assert_eq!(view.items[&later].key, Suffix::key("main", later, 6));
}

#[test]
fn trashed_entries_are_left_out_of_duplicate_key_rule() {
    let (holder, trashed, live) = (wide(1), wide(2), wide(3));
    let (trashed_field, live_field) = (wide(11), wide(12));
    let start = base(|s, m| {
        add_item(s, m, holder, "holder");
        add_item(s, m, trashed, "login");
        s.items.entry(trashed).trashed.write(m, trash(10, None));
        add_credential(s, m, trashed_field, holder, "user");
        let entry = s.credentials.entry(trashed_field);
        entry.trashed.write(m, trash(10, None));
    });
    let state = edited(&start, 2, |s, m| {
        add_item(s, m, live, "login");
        add_credential(s, m, live_field, holder, "user");
    });
    let view = VaultView::of(&state);
    assert_eq!(view.items[&live].key, "login");
    assert_eq!(view.items[&trashed].key, "login");
    assert_eq!(view.credentials[&live_field].key, "user");
    assert_eq!(view.credentials[&trashed_field].key, "user");
}

#[test]
fn key_that_needs_normalizing_is_shown_normalized() {
    let (item, credential) = (wide(1), wide(11));
    let state = edited(&State::default(), 2, |s, m| {
        add_item(s, m, item, "  My Login ");
        add_credential(s, m, credential, item, "Pass\tWord");
    });
    let view = VaultView::of(&state);
    assert_eq!(view.items[&item].key, "my-login");
    assert_eq!(view.credentials[&credential].key, "pass-word");
    assert!(view.key_notices().is_empty());
    assert_eq!(stored_item_keys(&state, item), ["  My Login "]);
}

#[test]
fn key_that_fails_validation_is_shown_suffixed_and_marked_for_notice() {
    let (item, credential) = (wide(1), wide(11));
    let state = edited(&State::default(), 2, |s, m| {
        add_item(s, m, item, "!!");
        add_credential(s, m, credential, item, "a");
    });
    let view = VaultView::of(&state);
    let shown = &view.items[&item];
    assert_eq!(shown.key, Suffix::key(ITEM_KEY_PREFIX, item, 4));
    assert!(shown.key_notice);
    let shown = &view.credentials[&credential];
    assert_eq!(shown.key, Suffix::key(CREDENTIAL_KEY_PREFIX, credential, 4));
    assert!(shown.key_notice);
    assert_eq!(
        view.key_notices(),
        [Entity::Item(item), Entity::Credential(credential)]
    );
    assert_eq!(stored_item_keys(&state, item), ["!!"]);
}

#[test]
fn rename_to_stored_key_of_suffixed_entry_is_refused_naming_that_entry() {
    let (holder, bare, suffixed, other) = (wide(1), wide(2), wide(3), wide(4));
    let (bare_field, suffixed_field, other_field) = (wide(11), wide(12), wide(13));
    let (trashed, trashed_field) = (wide(5), wide(14));
    let start = base(|s, m| {
        add_item(s, m, holder, "holder");
        add_item(s, m, bare, "login");
        add_credential(s, m, bare_field, holder, "user");
        add_item(s, m, trashed, "trashed");
        s.items.entry(trashed).trashed.write(m, trash(10, None));
        add_credential(s, m, trashed_field, holder, "trashed");
        let entry = s.credentials.entry(trashed_field);
        entry.trashed.write(m, trash(10, None));
    });
    let state = edited(&start, 2, |s, m| {
        add_item(s, m, suffixed, "login");
        add_item(s, m, other, "other");
        add_credential(s, m, suffixed_field, holder, "user");
        add_credential(s, m, other_field, holder, "other");
    });
    let view = VaultView::of(&state);
    assert_eq!(view.items[&suffixed].key, Suffix::key("login", suffixed, 4));

    let refused = KeyTaken {
        key: "login".to_string(),
        entries: vec![Entity::Item(bare), Entity::Item(suffixed)],
    };
    assert_eq!(
        view.check_key(KeyGroup::Items, other, "login"),
        Err(refused.clone())
    );
    assert_eq!(
        view.check_key(KeyGroup::Items, other, " Login"),
        Err(refused)
    );
    // The bare entry stores the key too, so only the suffixed entry is
    // named for a rename of the bare entry.
    assert_eq!(
        view.check_key(KeyGroup::Items, bare, "login"),
        Err(KeyTaken {
            key: "login".to_string(),
            entries: vec![Entity::Item(suffixed)],
        })
    );
    // A new entry.
    assert!(view.check_key(KeyGroup::Items, wide(9), "login").is_err());
    assert_eq!(view.check_key(KeyGroup::Items, other, "fresh"), Ok(()));
    // Trashed entries hold no key.
    assert_eq!(view.check_key(KeyGroup::Items, other, "trashed"), Ok(()));

    let credentials = KeyGroup::Credentials(holder);
    assert_eq!(
        view.check_key(credentials, other_field, "user"),
        Err(KeyTaken {
            key: "user".to_string(),
            entries: vec![
                Entity::Credential(bare_field),
                Entity::Credential(suffixed_field),
            ],
        })
    );
    assert_eq!(view.check_key(credentials, other_field, "trashed"), Ok(()));
    // Another item is another group.
    assert_eq!(
        view.check_key(KeyGroup::Credentials(other), wide(15), "user"),
        Ok(())
    );
}

#[test]
fn every_shown_key_is_valid_and_unique_among_live_entries_of_its_group() {
    let keys = [
        "login", "login", "Login", " login ", "!!", "", "a", "item", "field", "my key", "MY KEY",
    ];
    let (holder, trashed_holder) = (wide(200), wide(201));
    let start = base(|s, m| {
        add_item(s, m, holder, "holder");
        add_item(s, m, trashed_holder, "holder");
        s.items
            .entry(trashed_holder)
            .trashed
            .write(m, trash(10, None));
        for (n, key) in (1u8..).zip(keys) {
            add_item(s, m, wide(n), key);
            add_credential(s, m, wide(n + 50), holder, key);
            add_credential(s, m, wide(n + 100), trashed_holder, key);
        }
        // Stored keys equal to the suffixes of the duplicates.
        add_item(s, m, wide(30), &Suffix::key("login", wide(2), 4));
        add_item(s, m, wide(31), &Suffix::key(ITEM_KEY_PREFIX, wide(5), 4));
        // Entries with no key register.
        s.items.entry(wide(32)).title.write(m, "No key".to_string());
        let entry = s.credentials.entry(wide(80));
        entry.item.write(m, holder);
    });
    // Concurrent renames and creates on two Macs.
    let (_, view) = concurrent(
        &start,
        |s, m| {
            s.items.entry(wide(1)).key.write(m, "main".to_string());
            add_item(s, m, wide(40), "login");
            add_credential(s, m, wide(90), holder, "login");
        },
        |s, m| {
            s.items.entry(wide(1)).key.write(m, "!!".to_string());
            add_item(s, m, wide(41), "login");
            add_credential(s, m, wide(91), holder, "login");
        },
    );

    let mut live_items = BTreeSet::new();
    for item in view.items.values() {
        assert!(validate_key(&item.key), "{}", item.key);
        if item.trashed.is_none() {
            assert!(live_items.insert(item.key.clone()), "{}", item.key);
        }
    }
    for item in [holder, trashed_holder] {
        let mut live = BTreeSet::new();
        for id in &view.items[&item].credentials {
            let credential = &view.credentials[id];
            assert!(validate_key(&credential.key), "{}", credential.key);
            if credential.trashed.is_none() {
                assert!(live.insert(credential.key.clone()), "{}", credential.key);
            }
        }
        assert_eq!(live.len(), keys.len() + usize::from(item == holder) * 3);
    }
}

#[test]
fn next_entry_shows_bare_key_if_holder_is_renamed_or_trashed() {
    let (bare, next) = (wide(1), wide(2));
    let start = base(|s, m| add_item(s, m, bare, "login"));
    let start = edited(&start, 2, |s, m| add_item(s, m, next, "login"));
    assert_eq!(
        VaultView::of(&start).items[&next].key,
        Suffix::key("login", next, 4)
    );

    let renamed = edited(&start, 2, |s, m| {
        s.items.entry(bare).key.write(m, "main".to_string());
    });
    let view = VaultView::of(&renamed);
    assert_eq!(view.items[&bare].key, "main");
    assert_eq!(view.items[&next].key, "login");

    let trashed = edited(&start, 2, |s, m| {
        s.items.entry(bare).trashed.write(m, trash(10, None));
    });
    let view = VaultView::of(&trashed);
    assert_eq!(view.items[&bare].key, "login");
    assert_eq!(view.items[&next].key, "login");
}

#[test]
fn of_two_concurrent_creates_lower_lamport_counter_is_shown_bare() {
    let (holder, higher, lower) = (wide(1), wide(2), wide(3));
    let start = base(|s, m| add_item(s, m, holder, "holder"));
    // Replica 2 writes once more first, so its create has the higher counter.
    let busy = edited(&start, 2, |s, m| {
        s.items.entry(holder).title.write(m, "Busy".to_string());
    });
    let busy = edited(&busy, 2, |s, m| add_item(s, m, higher, "login"));
    let quiet = edited(&start, 3, |s, m| add_item(s, m, lower, "login"));
    let (ab, ba) = join(&busy, &quiet);
    let view = VaultView::of(&ab);
    assert_eq!(view, VaultView::of(&ba));
    assert_eq!(view.items[&lower].key, "login");
    assert_eq!(view.items[&higher].key, Suffix::key("login", higher, 4));
}

#[test]
fn key_register_with_conflict_takes_part_with_chosen_value() {
    let (conflicted, other) = (wide(1), wide(2));
    let start = base(|s, m| {
        add_item(s, m, conflicted, "login");
        add_item(s, m, other, "main");
    });
    let (_, view) = concurrent(
        &start,
        |s, m| s.items.entry(conflicted).key.write(m, "zzz".to_string()),
        |s, m| s.items.entry(conflicted).key.write(m, "main".to_string()),
    );
    assert_eq!(view.items[&other].key, "main");
    assert_eq!(
        view.items[&conflicted].key,
        Suffix::key("main", conflicted, 4)
    );
    assert!(view.conflicts().contains(&Conflict {
        entity: Entity::Item(conflicted),
        register: AskRegister::Key,
    }));
}

#[test]
fn recovered_entry_with_some_registers_shows_them_and_defaults_for_the_rest() {
    let (item, positioned, recovered) = (wide(1), wide(11), wide(12));
    let state = base(|s, m| {
        s.items.entry(item).title.write(m, "Partial".to_string());
        add_credential(s, m, positioned, item, "positioned");
        let entry = s.credentials.entry(positioned);
        entry.title.write(m, "Zed".to_string());
        let placement = Placement {
            section: None,
            position: Some(0),
        };
        entry.placement.write(m, placement);
        let entry = s.credentials.entry(recovered);
        entry.item.write(m, item);
        entry.title.write(m, "Note".to_string());
        entry.value.write(m, SecretText::new("v"));
    });
    let view = VaultView::of(&state);

    let shown = &view.items[&item];
    assert_eq!(shown.title, "Partial");
    assert_eq!(shown.key, Suffix::key(ITEM_KEY_PREFIX, item, 4));
    assert_eq!(shown.category, None);
    assert_eq!(shown.folder, None);
    assert_eq!(shown.trashed, None);
    assert_eq!(shown.credentials, [positioned, recovered]);

    let shown = &view.credentials[&recovered];
    assert_eq!(shown.title, "Note");
    assert_eq!(shown.key, Suffix::key(CREDENTIAL_KEY_PREFIX, recovered, 4));
    assert_eq!(shown.kind, FieldKind::default());
    assert_eq!(shown.value, SecretText::new("v"));
    assert_eq!(shown.section, None);
    assert_eq!(shown.position, None);
    assert!(view.key_notices().is_empty());
}

#[test]
fn credentials_of_trashed_item_that_share_key_are_suffixed() {
    let item = wide(1);
    let (first, second) = (wide(11), wide(12));
    let start = base(|s, m| {
        add_item(s, m, item, "login");
        s.items.entry(item).trashed.write(m, trash(10, None));
    });
    let (_, view) = concurrent(
        &start,
        |s, m| add_credential(s, m, first, item, "user"),
        |s, m| add_credential(s, m, second, item, "user"),
    );
    assert!(view.items[&item].trashed.is_some());
    assert_eq!(view.credentials[&first].key, "user");
    assert_eq!(
        view.credentials[&second].key,
        Suffix::key("user", second, 4)
    );
}
