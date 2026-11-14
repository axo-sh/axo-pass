use super::*;

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
fn signal_lists_ordered_by_time_then_report_id() {
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
fn trashed_credential_slot_no_conflict() {
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
fn history_entries_from_two_macs_ordered_by_time_then_id() {
    let (item, credential) = (id(1), id(11));
    let start = base(|s, m| {
        add_item(s, m, item);
        add_credential(s, m, credential, item, "Field");
    });
    let add = |entries: &'static [(u128, i64)]| {
        move |s: &mut SyncState, m: &Mint| {
            let history = &mut s.credentials.entry(credential).history;
            for (n, at) in entries {
                let value = HistoryValue {
                    at: *at,
                    kind: HistoryKind::ValueUpdated,
                    value: Some(SecretText::new(n.to_string())),
                };
                history.entry(id(*n)).write(m, value);
            }
        }
    };
    let (_, view) = concurrent(&start, add(&[(40, 20), (42, 10)]), add(&[(41, 10)]));

    let shown: Vec<_> = view.credentials[&credential]
        .history
        .iter()
        .map(|h| (h.id, h.at))
        .collect();
    assert_eq!(shown, [(id(41), 10), (id(42), 10), (id(40), 20)]);
}

#[test]
fn equal_resolved_values_show_no_conflict() {
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
fn username_password_share_one_slot() {
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
    assert_eq!(shown.title, RECOVERED_ITEM_TITLE);
    assert_eq!(shown.key, Suffix::key(ITEM_KEY_PREFIX, item, 4));
    assert_eq!(shown.credentials, [credential]);
    let shown = &view.credentials[&credential];
    assert_eq!(shown.title, RECOVERED_CREDENTIAL_TITLE);
    assert_eq!(shown.key, Suffix::key(CREDENTIAL_KEY_PREFIX, credential, 4));
    assert_eq!(shown.kind, FieldKind::default());
    assert_eq!(shown.value, SecretText::default());
    assert_eq!(shown.section, None);
    assert_eq!(shown.trashed, None);
}
