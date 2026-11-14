use super::*;

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
fn different_slots_edited_show_no_conflict() {
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
fn title_vs_category_edit_no_conflict() {
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
fn same_position_inserts_order_equally() {
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
fn credentials_ordered_by_section_default_first() {
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
fn concurrent_moves_pick_higher_order_key() {
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

    assert_eq!(view.credentials[&credential].item, to_b);
    assert_eq!(view.items[&to_b].credentials, [credential]);
    assert_eq!(view.items[&to_b].username, Some(credential));
    assert!(view.items[&to_a].credentials.is_empty());
    assert_eq!(view.items[&to_a].username, None);
    assert_eq!(view.items[&from].username, None);
    assert!(view.conflicts().is_empty());
}

#[test]
fn conflicts_of_other_policies_not_listed() {
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
                at,
                kind: HistoryKind::ValueUpdated,
                value: Some(SecretText::new(text.clone())),
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
fn differing_ask_values_listed() {
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
