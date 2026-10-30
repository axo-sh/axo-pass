use uuid::Uuid;

use super::{NOW, id, session};
use crate::secrets::vaults::autofill::item::{MatchKind, Role};
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::passkey::signals::{RenameEntry, Report, SignalEntry, SignalStore};
use crate::secrets::vaults::sync::crdt::{CausalState, Mint, MvRegister, Policy, ReplicaId};
use crate::secrets::vaults::sync::model::{
    FolderValue, HistoryValue, KeyId, Placement, PublicKey, RecoveryRecipient, Removal,
    ReplicaKeys, SecretText, SectionValue, SyncState, TrashValue, WebsiteValue,
};
use crate::secrets::vaults::sync::view::{AskRegister, Conflict, Entity, VaultView};

type State = CausalState<SyncState>;

/// State written by one mint of replica 1.
fn base(edit: impl FnOnce(&mut SyncState, &Mint)) -> State {
    edited(&State::default(), 1, edit)
}

/// `state` after one mint of replica `n` that applies `edit`.
fn edited(state: &State, n: u128, edit: impl FnOnce(&mut SyncState, &Mint)) -> State {
    let mut state = state.clone();
    let m = session(n).mint(&mut state, NOW);
    edit(&mut state.store, &m);
    state
}

/// Join of `a` and `b`, in both orders.
fn join(a: &State, b: &State) -> (State, State) {
    let mut ab = a.clone();
    ab.join(b.clone());
    let mut ba = b.clone();
    ba.join(a.clone());
    (ab, ba)
}

/// View of `base` edited concurrently by replica 2 with `a` and by replica 3
/// with `b`. The view of the join is the same in both orders. Values of
/// replica 3 have the higher order key.
fn concurrent(
    base: &State,
    a: impl FnOnce(&mut SyncState, &Mint),
    b: impl FnOnce(&mut SyncState, &Mint),
) -> (State, VaultView) {
    let (ab, ba) = join(&edited(base, 2, a), &edited(base, 3, b));
    let view = VaultView::of(&ab);
    assert_eq!(view, VaultView::of(&ba));
    (ab, view)
}

fn add_item(s: &mut SyncState, m: &Mint, item: Uuid) {
    let entry = s.items.entry(item);
    entry.title.write(m, "Item".to_string());
    entry.key.write(m, "item".to_string());
}

fn add_credential(s: &mut SyncState, m: &Mint, credential: Uuid, item: Uuid, title: &str) {
    let entry = s.credentials.entry(credential);
    entry.item.write(m, item);
    entry.title.write(m, title.to_string());
    entry.key.write(m, title.to_lowercase());
}

fn trash(deleted_at: i64, role: Option<Role>) -> Option<TrashValue> {
    Some(TrashValue { deleted_at, role })
}

fn count<T, P: Policy>(register: &MvRegister<T, P>) -> usize {
    register.values().count()
}

fn rename(name: &str, at: i64) -> SignalEntry {
    SignalEntry::Rename(RenameEntry {
        rp_id: "example.com".to_string(),
        user_handle: "CQ".to_string(),
        name: name.to_string(),
        at,
    })
}

#[test]
fn references_to_purged_entries_resolve_as_stated() {
    let (item, folder, section) = (id(1), id(2), id(3));
    let (placed, slotted) = (id(11), id(12));
    let full = base(|s, m| {
        add_item(s, m, item);
        s.folders.entry(folder).write(m, FolderValue::default());
        s.items.entry(item).folder.write(m, Some(folder));
        s.items
            .entry(item)
            .sections
            .entry(section)
            .write(m, SectionValue::default());
        add_credential(s, m, placed, item, "Placed");
        let placement = Placement {
            section: Some(section),
            position: Some(0),
        };
        s.credentials.entry(placed).placement.write(m, placement);
        add_credential(s, m, slotted, item, "Slotted");
        s.items.entry(item).username.write(m, Some(slotted));
    });
    let before = VaultView::of(&full);
    assert_eq!(before.items[&item].folder, Some(folder));
    assert_eq!(before.credentials[&placed].section, Some(section));
    assert_eq!(before.items[&item].username, Some(slotted));

    let purged = edited(&full, 2, |s, _| {
        s.folders.remove(&folder);
        s.items.entry(item).sections.remove(&section);
        s.credentials.remove(&slotted);
    });
    let view = VaultView::of(&purged);

    let shown = &view.items[&item];
    assert_eq!(shown.folder, None);
    assert_eq!(shown.username, None);
    assert_eq!(view.credentials[&placed].section, None);
    assert_eq!(view.credentials[&placed].position, Some(0));
    assert!(view.conflicts().is_empty());
    // The registers still name the purged entries.
    let stored = purged.store.items.get(&item).unwrap();
    assert_eq!(stored.folder.values().next().unwrap().1.value, Some(folder));
    assert_eq!(
        stored.username.values().next().unwrap().1.value,
        Some(slotted)
    );
}

#[test]
fn username_slot_and_totp_slot_changed_on_two_macs_show_no_conflict() {
    let (item, user, code) = (id(1), id(11), id(12));
    let start = base(|s, m| {
        add_item(s, m, item);
        add_credential(s, m, user, item, "User");
        add_credential(s, m, code, item, "Code");
    });
    let (_, view) = concurrent(
        &start,
        |s, m| s.items.entry(item).username.write(m, Some(user)),
        |s, m| s.items.entry(item).totp.write(m, Some(code)),
    );
    assert_eq!(view.items[&item].username, Some(user));
    assert_eq!(view.items[&item].totp, Some(code));
    assert!(view.conflicts().is_empty());
}

#[test]
fn websites_added_at_same_position_on_two_macs_show_same_order() {
    let item = id(1);
    let website = |position| WebsiteValue {
        match_kind: MatchKind::Domain,
        position,
    };
    let start = base(|s, m| {
        add_item(s, m, item);
        let websites = &mut s.items.entry(item).websites;
        websites
            .entry("https://z.com".to_string())
            .write(m, website(0));
    });
    let (_, view) = concurrent(
        &start,
        |s, m| {
            let websites = &mut s.items.entry(item).websites;
            websites
                .entry("https://b.com".to_string())
                .write(m, website(1));
        },
        |s, m| {
            let websites = &mut s.items.entry(item).websites;
            websites
                .entry("https://a.com".to_string())
                .write(m, website(1));
        },
    );
    let urls: Vec<_> = view.items[&item]
        .websites
        .iter()
        .map(|w| w.url.as_str())
        .collect();
    assert_eq!(urls, ["https://z.com", "https://a.com", "https://b.com"]);
}

#[test]
fn key_change_concurrent_with_title_edit_shows_no_conflict() {
    let (item, credential) = (id(1), id(11));
    let start = base(|s, m| {
        add_item(s, m, item);
        add_credential(s, m, credential, item, "Field");
    });
    let (_, view) = concurrent(
        &start,
        |s, m| {
            s.items.entry(item).key.write(m, "renamed".to_string());
            let entry = s.credentials.entry(credential);
            entry.key.write(m, "renamed".to_string());
        },
        |s, m| {
            s.items.entry(item).title.write(m, "Title".to_string());
            let entry = s.credentials.entry(credential);
            entry.title.write(m, "Title".to_string());
        },
    );
    assert_eq!(view.items[&item].key, "renamed");
    assert_eq!(view.items[&item].title, "Title");
    assert_eq!(view.credentials[&credential].key, "renamed");
    assert_eq!(view.credentials[&credential].title, "Title");
    assert!(view.conflicts().is_empty());
}

#[test]
fn title_edit_concurrent_with_category_or_kind_edit_shows_no_conflict() {
    let (item, credential) = (id(1), id(11));
    let start = base(|s, m| {
        add_item(s, m, item);
        add_credential(s, m, credential, item, "Field");
    });
    let (_, view) = concurrent(
        &start,
        |s, m| {
            s.items.entry(item).title.write(m, "Title".to_string());
            let entry = s.credentials.entry(credential);
            entry.title.write(m, "Title".to_string());
        },
        |s, m| {
            let category = Some("login".to_string());
            s.items.entry(item).category.write(m, category);
            s.credentials
                .entry(credential)
                .kind
                .write(m, FieldKind::Email);
        },
    );
    assert_eq!(view.items[&item].title, "Title");
    assert_eq!(view.items[&item].category.as_deref(), Some("login"));
    assert_eq!(view.credentials[&credential].title, "Title");
    assert_eq!(view.credentials[&credential].kind, FieldKind::Email);
    assert!(view.conflicts().is_empty());
}

#[test]
fn concurrent_trashes_and_trash_concurrent_with_restore_leave_entry_trashed() {
    let (item, credential) = (id(1), id(11));
    let start = base(|s, m| {
        add_item(s, m, item);
        add_credential(s, m, credential, item, "Field");
    });

    // Two trashes. The later `deleted_at` is shown.
    let (_, view) = concurrent(
        &start,
        |s, m| {
            s.items.entry(item).trashed.write(m, trash(20, None));
            let entry = s.credentials.entry(credential);
            entry.trashed.write(m, trash(20, None));
        },
        |s, m| {
            s.items.entry(item).trashed.write(m, trash(10, None));
            let entry = s.credentials.entry(credential);
            entry.trashed.write(m, trash(10, None));
        },
    );
    assert_eq!(view.items[&item].trashed, trash(20, None));
    assert_eq!(view.credentials[&credential].trashed, trash(20, None));
    assert!(view.conflicts().is_empty());

    // Two trashes at one time. The higher order key is shown.
    let (_, view) = concurrent(
        &start,
        |s, m| {
            let entry = s.credentials.entry(credential);
            entry.trashed.write(m, trash(20, Some(Role::Username)));
        },
        |s, m| {
            let entry = s.credentials.entry(credential);
            entry.trashed.write(m, trash(20, Some(Role::Password)));
        },
    );
    assert_eq!(
        view.credentials[&credential].trashed,
        trash(20, Some(Role::Password))
    );

    // A restore concurrent with a trash.
    let trashed = edited(&start, 1, |s, m| {
        s.items.entry(item).trashed.write(m, trash(5, None));
        s.credentials
            .entry(credential)
            .trashed
            .write(m, trash(5, None));
    });
    let (_, view) = concurrent(
        &trashed,
        |s, m| {
            s.items.entry(item).trashed.write(m, trash(30, None));
            let entry = s.credentials.entry(credential);
            entry.trashed.write(m, trash(30, None));
        },
        |s, m| {
            s.items.entry(item).trashed.write(m, None);
            s.credentials.entry(credential).trashed.write(m, None);
        },
    );
    assert_eq!(view.items[&item].trashed, trash(30, None));
    assert_eq!(view.credentials[&credential].trashed, trash(30, None));
    assert!(view.conflicts().is_empty());
}

#[test]
fn folders_sections_and_credentials_placed_at_same_position_show_same_order() {
    let item = id(1);
    let (first, a_new, b_new, unplaced) = (id(20), id(22), id(21), id(23));
    let start = base(|s, m| {
        add_item(s, m, item);
        let folder = FolderValue {
            title: "First".to_string(),
            position: Some(0),
        };
        s.folders.entry(first).write(m, folder);
        let section = SectionValue {
            title: "First".to_string(),
            position: Some(0),
        };
        s.items.entry(item).sections.entry(first).write(m, section);
        add_credential(s, m, first, item, "First");
        let placement = Placement {
            section: None,
            position: Some(0),
        };
        s.credentials.entry(first).placement.write(m, placement);
        add_credential(s, m, unplaced, item, "A");
        s.folders.entry(unplaced).write(
            m,
            FolderValue {
                title: "A".to_string(),
                position: None,
            },
        );
    });
    // Each Mac adds an entry at position 1 with one title.
    let place = |new: Uuid| {
        move |s: &mut SyncState, m: &Mint| {
            let folder = FolderValue {
                title: "New".to_string(),
                position: Some(1),
            };
            s.folders.entry(new).write(m, folder);
            let section = SectionValue {
                title: "New".to_string(),
                position: Some(1),
            };
            s.items.entry(item).sections.entry(new).write(m, section);
            add_credential(s, m, new, item, "New");
            let placement = Placement {
                section: None,
                position: Some(1),
            };
            s.credentials.entry(new).placement.write(m, placement);
        }
    };
    let (_, view) = concurrent(&start, place(a_new), place(b_new));

    let folders: Vec<_> = view.folders.iter().map(|f| f.id).collect();
    assert_eq!(folders, [first, b_new, a_new, unplaced]);
    let sections: Vec<_> = view.items[&item].sections.iter().map(|s| s.id).collect();
    assert_eq!(sections, [first, b_new, a_new]);
    assert_eq!(
        view.items[&item].credentials,
        [first, b_new, a_new, unplaced]
    );
}

#[test]
fn credentials_are_listed_by_section_order_with_default_section_first() {
    let item = id(1);
    let (early, late) = (id(2), id(3));
    let (in_late, in_early, in_default) = (id(11), id(12), id(13));
    let state = base(|s, m| {
        add_item(s, m, item);
        let sections = &mut s.items.entry(item).sections;
        let section = |position| SectionValue {
            title: String::new(),
            position: Some(position),
        };
        sections.entry(early).write(m, section(0));
        sections.entry(late).write(m, section(1));
        for (credential, section) in [
            (in_late, Some(late)),
            (in_early, Some(early)),
            (in_default, None),
        ] {
            add_credential(s, m, credential, item, "Field");
            let placement = Placement {
                section,
                position: None,
            };
            s.credentials
                .entry(credential)
                .placement
                .write(m, placement);
        }
    });
    let view = VaultView::of(&state);
    assert_eq!(
        view.items[&item].credentials,
        [in_default, in_early, in_late]
    );
}

#[test]
fn concurrent_moves_leave_credential_in_item_with_higher_order_key() {
    let (from, to_a, to_b, credential) = (id(1), id(2), id(3), id(11));
    let start = base(|s, m| {
        for item in [from, to_a, to_b] {
            add_item(s, m, item);
        }
        add_credential(s, m, credential, from, "Field");
        s.items.entry(from).username.write(m, Some(credential));
    });
    let mv = |to: Uuid| {
        move |s: &mut SyncState, m: &Mint| {
            s.credentials.entry(credential).item.write(m, to);
            s.items.entry(to).username.write(m, Some(credential));
        }
    };
    let (_, view) = concurrent(&start, mv(to_a), mv(to_b));

    assert_eq!(view.credentials[&credential].item, Some(to_b));
    assert_eq!(view.items[&to_b].credentials, [credential]);
    assert_eq!(view.items[&to_b].username, Some(credential));
    assert!(view.items[&to_a].credentials.is_empty());
    assert_eq!(view.items[&to_a].username, None);
    assert_eq!(view.items[&from].username, None);
    assert!(view.conflicts().is_empty());
}

#[test]
fn conflicts_of_other_policies_are_not_listed() {
    let (item, credential, folder) = (id(1), id(11), id(2));
    let (other_folder, section, replica) = (id(3), id(4), ReplicaId(id(1)));
    let start = base(|s, m| {
        add_item(s, m, item);
        add_credential(s, m, credential, item, "Field");
        s.folders.entry(folder).write(m, FolderValue::default());
        s.folders
            .entry(other_folder)
            .write(m, FolderValue::default());
    });
    let write = |n: u8| {
        move |s: &mut SyncState, m: &Mint| {
            let text = n.to_string();
            let at = i64::from(n);
            let entry = s.items.entry(item);
            entry
                .folder
                .write(m, Some([folder, other_folder][usize::from(n % 2)]));
            let section_value = SectionValue {
                title: text.clone(),
                position: Some(0),
            };
            entry.sections.entry(section).write(m, section_value);
            let website = WebsiteValue {
                match_kind: MatchKind::Domain,
                position: u32::from(n),
            };
            entry
                .websites
                .entry("https://a.com".to_string())
                .write(m, website);
            entry.trashed.write(
                m,
                n.is_multiple_of(2).then_some(TrashValue {
                    deleted_at: at,
                    role: None,
                }),
            );

            let entry = s.credentials.entry(credential);
            entry.item.write(m, item);
            let placement = Placement {
                section: None,
                position: Some(u32::from(n)),
            };
            entry.placement.write(m, placement);
            let history = HistoryValue {
                value: SecretText::new(text.clone()),
                replaced_at: at,
            };
            entry.history.entry(id(40)).write(m, history);
            entry.last_used_day_at.entry(replica).write(m, at);
            entry.trashed.write(m, trash(at, None));

            let folder_value = FolderValue {
                title: text.clone(),
                position: None,
            };
            s.folders.entry(folder).write(m, folder_value);
            s.signals
                .entry(rename("", 0).key())
                .write(m, rename(&text, at));
            s.replica_names.entry(replica).write(m, text.clone());
            s.left.entry(replica).write(m, n.is_multiple_of(2));
            let keys = ReplicaKeys {
                encryption: PublicKey(vec![n]),
                signing: PublicKey(vec![n]),
            };
            s.replica_keys.entry(replica).write(m, keys);
            let removal = Removal {
                key_id: KeyId(u32::from(n)),
            };
            s.removed.entry(replica).write(m, removal);
            let recipient = RecoveryRecipient {
                key_id: KeyId(u32::from(n)),
                key_fingerprint: [n; 16],
            };
            s.recovery.entry("age1a".to_string()).write(m, recipient);
        }
    };
    let (state, view) = concurrent(&start, write(1), write(2));

    assert!(view.conflicts().is_empty(), "{:?}", view.conflicts());
    // Every register holds the values of both Macs.
    let s = &state.store;
    let i = s.items.get(&item).unwrap();
    let c = s.credentials.get(&credential).unwrap();
    let counts = [
        count(&i.folder),
        count(i.sections.get(&section).unwrap()),
        count(i.websites.get(&"https://a.com".to_string()).unwrap()),
        count(&i.trashed),
        count(&c.item),
        count(&c.placement),
        count(c.history.get(&id(40)).unwrap()),
        count(c.last_used_day_at.get(&replica).unwrap()),
        count(&c.trashed),
        count(s.folders.get(&folder).unwrap()),
        count(s.signals.get(&rename("", 0).key()).unwrap()),
        count(s.replica_names.get(&replica).unwrap()),
        count(s.left.get(&replica).unwrap()),
        count(s.replica_keys.get(&replica).unwrap()),
        count(s.removed.get(&replica).unwrap()),
        count(s.recovery.get(&"age1a".to_string()).unwrap()),
    ];
    assert_eq!(counts, [2; 16]);

    // Own registers with two values show the higher order key.
    assert_eq!(view.replica_names[&replica], "2");
    assert!(view.left[&replica]);
}

#[test]
fn concurrent_ask_values_that_differ_are_listed_by_entity_and_register() {
    let (item, credential) = (id(1), id(11));
    let start = base(|s, m| {
        add_item(s, m, item);
        add_credential(s, m, credential, item, "Field");
    });
    let write = |text: &'static str| {
        move |s: &mut SyncState, m: &Mint| {
            s.name.write(m, Some(text.to_string()));
            s.items.entry(item).title.write(m, text.to_string());
            let value = SecretText::new(text);
            s.credentials.entry(credential).value.write(m, value);
        }
    };
    let (_, view) = concurrent(&start, write("A"), write("B"));

    assert_eq!(view.name.as_deref(), Some("B"));
    assert_eq!(view.items[&item].title, "B");
    assert_eq!(view.credentials[&credential].value, SecretText::new("B"));
    let mut conflicts = view.conflicts().to_vec();
    conflicts.sort();
    let expected = [
        Conflict {
            entity: Entity::Vault,
            register: AskRegister::Name,
        },
        Conflict {
            entity: Entity::Item(item),
            register: AskRegister::Title,
        },
        Conflict {
            entity: Entity::Credential(credential),
            register: AskRegister::Value,
        },
    ];
    assert_eq!(conflicts, expected);
}

/// State with 500 unknown reports, at `first` to `first + 499`, written by
/// replica `n`.
fn full_signals(start: &State, n: u128, first: u32) -> State {
    let mut store = SignalStore::default();
    for k in first..first + 500 {
        let report = Report::Unknown {
            rp_id: "example.com".to_string(),
            credential_id: k.to_be_bytes().to_vec(),
        };
        store.record(report, i64::from(k));
    }
    assert_eq!(store.entries().count(), 500);
    edited(start, n, |s, m| {
        for entry in store.entries() {
            s.signals.entry(entry.key()).write(m, entry);
        }
    })
}

#[test]
fn view_of_two_full_signal_stores_holds_every_entry() {
    let start = State::default();
    let (ab, _) = join(&full_signals(&start, 2, 0), &full_signals(&start, 3, 500));
    let view = VaultView::of(&ab);

    let ats: Vec<_> = view
        .signals
        .entries()
        .map(|entry| match entry {
            SignalEntry::Unknown(e) => e.at,
            other => panic!("{other:?}"),
        })
        .collect();
    let expected: Vec<i64> = (0..1000).collect();
    assert_eq!(ats, expected);
}

#[test]
fn signal_lists_are_ordered_by_time_then_report_id() {
    let rename_of = |user_handle: &str, at| {
        SignalEntry::Rename(RenameEntry {
            rp_id: "example.com".to_string(),
            user_handle: user_handle.to_string(),
            name: "ada".to_string(),
            at,
        })
    };
    let entries = [
        rename_of("B", 5),
        rename_of("A", 5),
        rename_of("C", 1),
        rename_of("D", 9),
    ];
    let state = base(|s, m| {
        for entry in entries.clone() {
            s.signals.entry(entry.key()).write(m, entry);
        }
    });
    let view = VaultView::of(&state);
    let shown: Vec<_> = view.signals.entries().collect();
    let [b, a, c, d] = entries;
    assert_eq!(shown, [c, a, b, d]);
}

#[test]
fn slot_holding_trashed_credential_and_empty_value_shows_no_conflict() {
    let (item, credential) = (id(1), id(11));
    let start = base(|s, m| {
        add_item(s, m, item);
        add_credential(s, m, credential, item, "Field");
    });
    let (state, view) = concurrent(
        &start,
        |s, m| {
            s.items.entry(item).username.write(m, Some(credential));
            let entry = s.credentials.entry(credential);
            entry.trashed.write(m, trash(10, Some(Role::Username)));
        },
        |s, m| s.items.entry(item).username.write(m, None),
    );
    assert_eq!(count(&state.store.items.get(&item).unwrap().username), 2);
    assert_eq!(view.items[&item].username, None);
    assert!(view.conflicts().is_empty());
}

#[test]
fn history_entries_from_two_macs_are_ordered_by_time_then_id() {
    let (item, credential) = (id(1), id(11));
    let start = base(|s, m| {
        add_item(s, m, item);
        add_credential(s, m, credential, item, "Field");
    });
    let add = |entries: &'static [(u128, i64)]| {
        move |s: &mut SyncState, m: &Mint| {
            let history = &mut s.credentials.entry(credential).history;
            for (n, replaced_at) in entries {
                let value = HistoryValue {
                    value: SecretText::new(n.to_string()),
                    replaced_at: *replaced_at,
                };
                history.entry(id(*n)).write(m, value);
            }
        }
    };
    let (_, view) = concurrent(&start, add(&[(40, 20), (42, 10)]), add(&[(41, 10)]));

    let shown: Vec<_> = view.credentials[&credential]
        .history
        .iter()
        .map(|h| (h.id, h.replaced_at))
        .collect();
    assert_eq!(shown, [(id(41), 10), (id(42), 10), (id(40), 20)]);
}

#[test]
fn equal_values_and_values_equal_after_resolution_show_no_conflict() {
    let item = id(1);
    let start = base(|s, m| add_item(s, m, item));
    let (_, view) = concurrent(
        &start,
        |s, m| {
            s.items.entry(item).title.write(m, "Same".to_string());
            s.items.entry(item).username.write(m, Some(id(90)));
        },
        |s, m| {
            s.items.entry(item).title.write(m, "Same".to_string());
            s.items.entry(item).username.write(m, Some(id(91)));
        },
    );
    assert_eq!(view.items[&item].title, "Same");
    assert_eq!(view.items[&item].username, None);
    assert!(view.conflicts().is_empty());
}

#[test]
fn different_last_used_times_show_later_time_with_no_conflict() {
    let (item, credential) = (id(1), id(11));
    let start = base(|s, m| {
        add_item(s, m, item);
        add_credential(s, m, credential, item, "Passkey");
    });
    let (_, view) = concurrent(
        &start,
        |s, m| {
            let entry = s.credentials.entry(credential);
            entry.last_used_day_at.entry(ReplicaId(id(2))).write(m, 200);
        },
        |s, m| {
            let entry = s.credentials.entry(credential);
            entry.last_used_day_at.entry(ReplicaId(id(3))).write(m, 100);
        },
    );
    assert_eq!(view.credentials[&credential].last_used_day_at, Some(200));
    assert!(view.conflicts().is_empty());
}

#[test]
fn edit_concurrent_with_trash_shows_trashed_entry_with_edit() {
    let (item, credential) = (id(1), id(11));
    let start = base(|s, m| {
        add_item(s, m, item);
        add_credential(s, m, credential, item, "Field");
    });
    let (_, view) = concurrent(
        &start,
        |s, m| {
            s.items.entry(item).title.write(m, "Edited".to_string());
            let value = SecretText::new("new");
            s.credentials.entry(credential).value.write(m, value);
        },
        |s, m| {
            s.items.entry(item).trashed.write(m, trash(10, None));
            let entry = s.credentials.entry(credential);
            entry.trashed.write(m, trash(10, None));
        },
    );
    assert_eq!(view.items[&item].title, "Edited");
    assert_eq!(view.items[&item].trashed, trash(10, None));
    assert_eq!(view.credentials[&credential].value, SecretText::new("new"));
    assert_eq!(view.credentials[&credential].trashed, trash(10, None));
    assert!(view.conflicts().is_empty());
}

#[test]
fn merge_view_of_one_report_is_same_for_every_order_of_joins() {
    let start = State::default();
    let key = rename("", 0).key();
    let states = [("x", 10), ("y", 20), ("z", 20)].map(|(name, at)| {
        let n = u128::from(name.as_bytes()[0]);
        edited(&start, n, |s, m| {
            s.signals.entry(key.clone()).write(m, rename(name, at))
        })
    });
    let orders = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    for order in orders {
        let mut state = State::default();
        for index in order {
            state.join(states[index].clone());
        }
        let shown: Vec<_> = VaultView::of(&state).signals.entries().collect();
        // Values fold in order key order. Replica `z` has the highest order
        // key, and its entry is at least as new as the others.
        assert_eq!(shown, [rename("z", 20)], "{order:?}");
    }
}

#[test]
fn username_and_password_set_to_one_credential_show_it_in_one_slot() {
    let (item, credential) = (id(1), id(11));
    let start = base(|s, m| {
        add_item(s, m, item);
        add_credential(s, m, credential, item, "Field");
    });
    let (_, view) = concurrent(
        &start,
        |s, m| s.items.entry(item).username.write(m, Some(credential)),
        |s, m| s.items.entry(item).password.write(m, Some(credential)),
    );
    assert_eq!(view.items[&item].username, None);
    assert_eq!(view.items[&item].password, Some(credential));

    let (_, view) = concurrent(
        &start,
        |s, m| s.items.entry(item).password.write(m, Some(credential)),
        |s, m| s.items.entry(item).username.write(m, Some(credential)),
    );
    assert_eq!(view.items[&item].username, Some(credential));
    assert_eq!(view.items[&item].password, None);
    assert!(view.conflicts().is_empty());
}

#[test]
fn missing_registers_show_defaults() {
    let (item, credential) = (id(1), id(11));
    let state = base(|s, m| {
        s.items.entry(item).folder.write(m, None);
        s.credentials.entry(credential).item.write(m, item);
    });
    let view = VaultView::of(&state);
    let shown = &view.items[&item];
    assert_eq!(shown.title, "");
    assert_eq!(shown.key, "");
    assert_eq!(shown.credentials, [credential]);
    let shown = &view.credentials[&credential];
    assert_eq!(shown.title, "");
    assert_eq!(shown.kind, FieldKind::default());
    assert_eq!(shown.value, SecretText::default());
    assert_eq!(shown.section, None);
    assert_eq!(shown.trashed, None);
}
