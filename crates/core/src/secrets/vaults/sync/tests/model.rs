use std::collections::BTreeSet;
use std::fmt::Debug;

use super::{NOW, id, session};
use crate::secrets::vaults::autofill::item::{MatchKind, Role};
use crate::secrets::vaults::model::fields::{FieldKind, TextField};
use crate::secrets::vaults::model::history::HistoryKind;
use crate::secrets::vaults::passkey::signals::{
    AcceptedEntry, DismissEntry, DismissKind, RenameEntry, SignalEntry, UnknownEntry,
};
use crate::secrets::vaults::sync::crdt::{
    CausalState, CausalStore, Mint, MvRegister, OrMap, OrderKey, Policy, PolicyKind, ReplicaId,
    WriteId,
};
use crate::secrets::vaults::sync::model::{
    FolderValue, HistoryValue, KeyId, Placement, PublicKey, RecoveryRecipient, Removal,
    ReplicaKeys, SecretText, SectionValue, SyncCredential, SyncItem, SyncState, TrashValue,
    WebsiteValue,
};

fn policy<T, P: Policy>(_: &MvRegister<T, P>) -> PolicyKind {
    P::KIND
}

fn entry_policy<K, T: PartialEq, P: Policy>(_: &OrMap<K, MvRegister<T, P>>) -> PolicyKind {
    P::KIND
}

#[test]
fn each_register_has_policy_of_plan() {
    use PolicyKind::*;

    let SyncState {
        name,
        replica_names,
        replica_keys,
        removed,
        left,
        recovery,
        folders,
        signals,
        items: _,
        credentials: _,
    } = &SyncState::default();
    let state = [
        policy(name),
        entry_policy(replica_names),
        entry_policy(replica_keys),
        entry_policy(removed),
        entry_policy(left),
        entry_policy(recovery),
        entry_policy(folders),
        entry_policy(signals),
    ];
    assert_eq!(state, [Ask, Own, Stop, Rotation, Own, Order, Order, Merge]);

    let SyncItem {
        title,
        category,
        key,
        folder,
        sections,
        websites,
        username,
        password,
        totp,
        created_at,
        trashed,
    } = &SyncItem::default();
    let item = [
        policy(title),
        policy(category),
        policy(key),
        policy(folder),
        entry_policy(sections),
        entry_policy(websites),
        policy(username),
        policy(password),
        policy(totp),
        policy(created_at),
        policy(trashed),
    ];
    assert_eq!(
        item,
        [
            Ask, Ask, Ask, Order, Order, Order, Ask, Ask, Ask, Order, Trash
        ]
    );

    let SyncCredential {
        item,
        title,
        kind,
        key,
        placement,
        value,
        history,
        last_used_day_at,
        created_at,
        trashed,
    } = &SyncCredential::default();
    let credential = [
        policy(item),
        policy(title),
        policy(kind),
        policy(key),
        policy(placement),
        policy(value),
        entry_policy(history),
        entry_policy(last_used_day_at),
        policy(created_at),
        policy(trashed),
    ];
    assert_eq!(
        credential,
        [Order, Ask, Ask, Ask, Order, Ask, Order, Own, Order, Trash]
    );
}

/// Write to one register of `S`, with the first value or, if `alt`, a second
/// value that differs from it.
type Write<S> = (&'static str, fn(&mut S, &Mint, bool));

fn text(alt: bool) -> String {
    if alt { "B" } else { "A" }.to_string()
}

fn signal(alt: bool) -> SignalEntry {
    SignalEntry::Unknown(UnknownEntry {
        rp_id: "example.com".to_string(),
        credential_id: "AQID".to_string(),
        at: NOW + i64::from(alt),
    })
}

/// `value-updated` history value holding `value`, at `NOW`.
fn value_updated(value: &str) -> HistoryValue {
    HistoryValue {
        at: NOW,
        kind: HistoryKind::ValueUpdated,
        value: Some(SecretText::new(value)),
    }
}

fn trash(alt: bool) -> Option<TrashValue> {
    Some(TrashValue {
        deleted_at: NOW + i64::from(alt),
        role: alt.then_some(Role::Password),
    })
}

fn slot(alt: bool) -> Option<uuid::Uuid> {
    Some(id(20 + u128::from(alt)))
}

/// One write to every register and map of `SyncState`, in field order.
const STATE_WRITES: [Write<SyncState>; 10] = [
    ("name", |s, m, alt| s.name.write(m, Some(text(alt)))),
    ("replica_names", |s, m, alt| {
        s.replica_names.entry(ReplicaId(id(1))).write(m, text(alt));
    }),
    ("replica_keys", |s, m, alt| {
        let keys = ReplicaKeys {
            encryption: PublicKey(vec![u8::from(alt)]),
            signing: PublicKey(vec![2]),
        };
        s.replica_keys.entry(ReplicaId(id(1))).write(m, keys);
    }),
    ("removed", |s, m, alt| {
        let removal = Removal {
            key_id: KeyId(1 + u32::from(alt)),
        };
        s.removed.entry(ReplicaId(id(1))).write(m, removal);
    }),
    ("left", |s, m, alt| {
        s.left.entry(ReplicaId(id(1))).write(m, alt)
    }),
    ("recovery", |s, m, alt| {
        let recipient = RecoveryRecipient {
            key_id: KeyId(1),
            key_fingerprint: [u8::from(alt); 16],
            label: None,
        };
        s.recovery.entry("age1a".to_string()).write(m, recipient);
    }),
    ("folders", |s, m, alt| {
        let folder = FolderValue {
            title: text(alt),
            position: Some(0),
        };
        s.folders.entry(id(1)).write(m, folder);
    }),
    ("signals", |s, m, alt| {
        s.signals.entry(signal(false).key()).write(m, signal(alt));
    }),
    ("items", |s, m, alt| {
        s.items.entry(id(1)).title.write(m, text(alt));
    }),
    ("credentials", |s, m, alt| {
        s.credentials.entry(id(2)).title.write(m, text(alt));
    }),
];

/// One write to every register and map of `SyncItem`, in field order.
const ITEM_WRITES: [Write<SyncItem>; 11] = [
    ("title", |s, m, alt| s.title.write(m, text(alt))),
    ("category", |s, m, alt| s.category.write(m, Some(text(alt)))),
    ("key", |s, m, alt| s.key.write(m, text(alt))),
    ("folder", |s, m, alt| {
        s.folder.write(m, Some(id(1 + u128::from(alt))));
    }),
    ("sections", |s, m, alt| {
        let section = SectionValue {
            title: text(alt),
            position: Some(0),
        };
        s.sections.entry(id(10)).write(m, section);
    }),
    ("websites", |s, m, alt| {
        let website = WebsiteValue {
            match_kind: if alt {
                MatchKind::Host
            } else {
                MatchKind::Domain
            },
            position: 0,
        };
        s.websites
            .entry("https://a.com".to_string())
            .write(m, website);
    }),
    ("username", |s, m, alt| s.username.write(m, slot(alt))),
    ("password", |s, m, alt| s.password.write(m, slot(alt))),
    ("totp", |s, m, alt| s.totp.write(m, slot(alt))),
    ("created_at", |s, m, alt| {
        s.created_at.write(m, NOW + i64::from(alt));
    }),
    ("trashed", |s, m, alt| s.trashed.write(m, trash(alt))),
];

/// One write to every register and map of `SyncCredential`, in field order.
const CREDENTIAL_WRITES: [Write<SyncCredential>; 10] = [
    ("item", |s, m, alt| s.item.write(m, id(1 + u128::from(alt)))),
    ("title", |s, m, alt| s.title.write(m, text(alt))),
    ("kind", |s, m, alt| {
        let kind = if alt {
            FieldKind::Email
        } else {
            FieldKind::Text(TextField::default())
        };
        s.kind.write(m, kind);
    }),
    ("key", |s, m, alt| s.key.write(m, text(alt))),
    ("placement", |s, m, alt| {
        let placement = Placement {
            section: Some(id(10)),
            position: Some(u32::from(alt)),
        };
        s.placement.write(m, placement);
    }),
    ("value", |s, m, alt| {
        s.value.write(m, SecretText::new(text(alt)))
    }),
    ("history", |s, m, alt| {
        s.history.entry(id(30)).write(m, value_updated(&text(alt)));
    }),
    ("last_used_day_at", |s, m, alt| {
        let day = NOW + i64::from(alt);
        s.last_used_day_at.entry(ReplicaId(id(1))).write(m, day);
    }),
    ("created_at", |s, m, alt| {
        s.created_at.write(m, NOW + i64::from(alt));
    }),
    ("trashed", |s, m, alt| s.trashed.write(m, trash(alt))),
];

fn all_write_ids(store: &impl CausalStore) -> BTreeSet<WriteId> {
    let mut ids = BTreeSet::new();
    store.each_value(&mut |id, _| {
        ids.insert(id);
    });
    ids
}

/// State with one value in each register of `writes`, each under its own
/// mint of replica `n`. Values are the second values if `alt`.
fn written<S: CausalStore>(n: u128, writes: &[Write<S>], alt: bool) -> (CausalState<S>, Vec<Mint>) {
    let mut session = session(n);
    let mut state = CausalState::<S>::default();
    let mints = writes
        .iter()
        .map(|(_, write)| {
            let m = session.mint(&mut state, NOW);
            write(&mut state.store, &m, alt);
            m
        })
        .collect();
    (state, mints)
}

/// Check that `each_value`, `find_duplicate_write_id`, and `join` reach the
/// register of each write.
fn check_every_field<S: CausalStore + Clone + Debug + PartialEq>(writes: &[Write<S>]) {
    let (full, mints) = written(1, writes, false);

    let mut seen = Vec::new();
    full.store
        .each_value(&mut |write_id, counter| seen.push(OrderKey { counter, write_id }));
    let expected: Vec<_> = mints.iter().map(Mint::order_key).collect();
    assert_eq!(seen, expected);

    for ((name, write), m) in writes.iter().zip(&mints) {
        let mut changed = full.store.clone();
        write(&mut changed, m, true);
        let found = full.store.find_duplicate_write_id(&changed);
        assert_eq!(found, Some(m.write_id), "{name}");
    }

    let mut state = CausalState::<S>::default();
    state.join(full.clone());
    assert_eq!(state, full);

    // Concurrent writes of a second replica coexist in every register.
    let (other, other_mints) = written(2, writes, true);
    state.join(other);
    let expected: BTreeSet<_> = mints
        .iter()
        .chain(&other_mints)
        .map(|m| m.write_id)
        .collect();
    assert_eq!(all_write_ids(&state.store), expected);
}

#[test]
fn sync_state_store_reaches_every_field() {
    check_every_field(&STATE_WRITES);
}

#[test]
fn sync_item_store_reaches_every_field() {
    check_every_field(&ITEM_WRITES);
}

#[test]
fn sync_credential_store_reaches_every_field() {
    check_every_field(&CREDENTIAL_WRITES);
}

/// Remove of one entry of `SyncState`.
type Remove = (&'static str, fn(&mut SyncState));

#[test]
fn removal_only_mint_advances_context_and_join_applies_removal() {
    let mut a = session(1);
    let mut base = CausalState::<SyncState>::default();
    let m = a.mint(&mut base, NOW);
    let store = &mut base.store;
    store.items.entry(id(1)).title.write(&m, text(false));
    store.items.entry(id(4)).title.write(&m, text(false));
    let credential = store.credentials.entry(id(2));
    credential.title.write(&m, text(false));
    credential
        .history
        .entry(id(3))
        .write(&m, value_updated("old"));
    store.credentials.entry(id(5)).title.write(&m, text(false));
    store
        .signals
        .entry(signal(false).key())
        .write(&m, signal(false));

    let removals: [Remove; 4] = [
        ("item", |s| {
            s.items.remove(&id(1));
        }),
        ("credential", |s| {
            s.credentials.remove(&id(5));
        }),
        ("history entry", |s| {
            s.credentials.entry(id(2)).history.remove(&id(3));
        }),
        ("signal", |s| {
            s.signals.remove(&signal(false).key());
        }),
    ];
    for (name, remove) in removals {
        let mut b = session(2);
        let mut removed = base.clone();
        let m = b.mint(&mut removed, NOW);
        remove(&mut removed.store);

        assert_ne!(removed.store, base.store, "{name}");
        assert!(!base.context.covers(m.write_id), "{name}");
        assert!(removed.context.covers(m.write_id), "{name}");
        assert!(
            !all_write_ids(&removed.store).contains(&m.write_id),
            "{name}"
        );

        let mut state = base.clone();
        state.join(removed.clone());

        assert_eq!(state, removed, "{name}");
    }
}

#[test]
fn secret_text_compares_by_value_and_debug_shows_no_value() {
    assert_eq!(SecretText::new("hunter2"), SecretText::new("hunter2"));
    assert_ne!(SecretText::new("hunter2"), SecretText::new("hunter3"));

    let history = value_updated("hunter2");
    let debug = format!("{history:?}");
    assert!(!debug.contains("hunter2"), "{debug}");
    assert!(debug.contains("SecretText"), "{debug}");
}

#[test]
fn signal_entry_key_of_each_kind_matches_state_file_format() {
    // A new entry kind fails to compile here until it has a case below.
    let _ = |entry: &SignalEntry| match entry {
        SignalEntry::Unknown(_)
        | SignalEntry::Accepted(_)
        | SignalEntry::Rename(_)
        | SignalEntry::Dismissed(_) => {},
    };
    let rp_id = || "example.com".to_string();
    let dismissed = |kind| {
        SignalEntry::Dismissed(DismissEntry {
            rp_id: rp_id(),
            credential_id: "AQID".to_string(),
            kind,
            at: NOW,
        })
    };
    let cases = [
        (
            SignalEntry::Unknown(UnknownEntry {
                rp_id: rp_id(),
                credential_id: "AQID".to_string(),
                at: NOW,
            }),
            "unknown:example.com:AQID",
        ),
        (
            SignalEntry::Accepted(AcceptedEntry {
                rp_id: rp_id(),
                user_handle: "CQ".to_string(),
                credential_ids: vec!["AQID".to_string()],
                at: NOW,
            }),
            "accepted:example.com:CQ",
        ),
        (
            SignalEntry::Rename(RenameEntry {
                rp_id: rp_id(),
                user_handle: "CQ".to_string(),
                name: "ada".to_string(),
                at: NOW,
            }),
            "renames:example.com:CQ",
        ),
        (
            dismissed(DismissKind::Rejection),
            "dismissed:rejection:example.com:AQID",
        ),
        (
            dismissed(DismissKind::Rename),
            "dismissed:rename:example.com:AQID",
        ),
    ];
    for (entry, key) in cases {
        assert_eq!(entry.key(), key);
    }

    // The kind in a dismissal key is the serde form of the kind.
    for kind in [DismissKind::Rejection, DismissKind::Rename] {
        let serde_kind = serde_json::to_value(kind).unwrap();
        let key = dismissed(kind).key();
        let segment = key.split(':').nth(1).unwrap();
        assert_eq!(serde_kind, segment);
    }
}
