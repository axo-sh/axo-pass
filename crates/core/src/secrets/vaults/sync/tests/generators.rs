//! Random sync states for the round trip tests.
//!
//! A state comes from 2 or 3 sessions. Session 1 writes a shared base. Each
//! session then writes random registers and removes random entries on its own
//! copy of the base, and the copies are joined. Entries come from small id
//! pools, so concurrent writes conflict, purges meet concurrent edits, and
//! references dangle. Keys include duplicates, keys that need normalizing, and
//! keys that fail `validate_key`. A base can hold more than 500 entries in one
//! signal list.

use proptest::collection::vec;
use proptest::option;
use proptest::prelude::*;
use proptest::sample::select;
use uuid::Uuid;

use super::view::State;
use super::{NOW, session};
use crate::secrets::vaults::autofill::item::{MatchKind, Role};
use crate::secrets::vaults::model::fields::{FieldKind, TextField};
use crate::secrets::vaults::model::history::HistoryKind;
use crate::secrets::vaults::passkey::signals::{
    AcceptedEntry, DismissEntry, DismissKind, RenameEntry, SignalEntry, UnknownEntry,
};
use crate::secrets::vaults::sync::crdt::{Mint, ReplicaId, Session};
use crate::secrets::vaults::sync::model::{
    FolderValue, HistoryValue, Placement, SecretText, SectionValue, SyncState, TrashValue,
    WebsiteValue,
};

/// Folders written, by index from 1. Folder 0 is never written.
const FOLDERS: u8 = 3;
/// Items written, by index from 1. Item 0 is never written, so a credential
/// in it is shown in a recovered item.
const ITEMS: u8 = 3;
/// Sections of each item, by index from 1. Section 0 is never written.
const SECTIONS: u8 = 2;
/// Credentials written, by index from 1. Credential 0 is never written.
const CREDENTIALS: u8 = 5;
/// History entries of each credential.
const HISTORY: u8 = 2;
/// Signal entries of [`Write::signal`].
const SIGNALS: u8 = 6;

/// Keys that are valid, duplicated, in need of normalizing, or invalid after
/// normalizing.
const KEYS: &[&str] = &["mail", "bank", "mail", " Mail ", "My Item", "!!!", "a", ""];
const TITLES: &[&str] = &["Mail", "Bank", " Padded ", ""];
const NAMES: &[&str] = &["Work", " Home "];
const VALUES: &[&str] = &["", "one", "two"];
const URLS: &[&str] = &["https://a.com", "https://b.com", "c.com"];
const CATEGORIES: &[&str] = &["login", "note"];
const TIMES: &[i64] = &[100, 200];

/// Ids of the entries of generated states.
pub(super) struct Ids;

impl Ids {
    /// Odd multiplier that spreads small numbers over the 128 bits, so the
    /// key suffixes of different ids differ.
    const SPREAD: u128 = 0x9e37_79b9_7f4a_7c15_f39c_c060_5ced_c835;

    fn of(kind: u128, n: u128) -> Uuid {
        Uuid::from_u128(((kind << 16) | n).wrapping_mul(Self::SPREAD))
    }

    pub(super) fn folder(n: u8) -> Uuid {
        Self::of(1, n.into())
    }

    pub(super) fn item(n: u8) -> Uuid {
        Self::of(2, n.into())
    }

    /// Section `n` of item `item`.
    pub(super) fn section(item: u8, n: u8) -> Uuid {
        Self::of(3, (u128::from(item) << 8) | u128::from(n))
    }

    pub(super) fn credential(n: u8) -> Uuid {
        Self::of(4, n.into())
    }

    /// History entry `n` of credential `credential`.
    pub(super) fn history(credential: u8, n: u8) -> Uuid {
        Self::of(5, (u128::from(credential) << 8) | u128::from(n))
    }
}

/// Register write of a generated mint.
#[derive(Clone, Debug)]
pub(super) enum Write {
    Name(Option<&'static str>),
    Folder {
        folder: u8,
        title: &'static str,
        position: Option<u32>,
    },
    /// Title and key of an item.
    NewItem {
        item: u8,
        title: &'static str,
        key: &'static str,
    },
    ItemTitle(u8, &'static str),
    Category(u8, Option<&'static str>),
    ItemKey(u8, &'static str),
    /// `None` unfiles the item.
    ItemFolder(u8, Option<u8>),
    Section {
        item: u8,
        section: u8,
        title: &'static str,
        position: Option<u32>,
    },
    Website {
        item: u8,
        url: &'static str,
        match_kind: MatchKind,
        position: u32,
    },
    Slot {
        item: u8,
        role: Role,
        credential: Option<u8>,
    },
    ItemTrashed(u8, Option<TrashValue>),
    /// Item, title, key, and value of a credential.
    NewCredential {
        credential: u8,
        item: u8,
        title: &'static str,
        key: &'static str,
        value: &'static str,
    },
    /// Move of a credential to another item.
    CredentialItem(u8, u8),
    CredentialTitle(u8, &'static str),
    Kind(u8, FieldKind),
    CredentialKey(u8, &'static str),
    /// Section as item and section index. A section of another item dangles.
    Placement {
        credential: u8,
        section: Option<(u8, u8)>,
        position: Option<u32>,
    },
    Value(u8, &'static str),
    History {
        credential: u8,
        entry: u8,
        value: &'static str,
        replaced_at: i64,
    },
    /// Last used time in the register of the writing replica.
    LastUsed(u8, i64),
    CredentialTrashed(u8, Option<TrashValue>),
    Signal(u8),
}

impl Write {
    pub(super) fn strategy() -> impl Strategy<Value = Self> {
        prop_oneof![
            1 => Self::vault_strategy(),
            3 => Self::item_strategy(),
            4 => Self::credential_strategy(),
        ]
    }

    /// Writes that create items and credentials.
    fn create_strategy() -> impl Strategy<Value = Self> {
        prop_oneof![
            (1..=ITEMS, select(TITLES), select(KEYS))
                .prop_map(|(item, title, key)| Self::NewItem { item, title, key }),
            (
                1..=CREDENTIALS,
                0..=ITEMS,
                select(TITLES),
                select(KEYS),
                select(VALUES)
            )
                .prop_map(|(credential, item, title, key, value)| {
                    Self::NewCredential {
                        credential,
                        item,
                        title,
                        key,
                        value,
                    }
                }),
        ]
    }

    fn vault_strategy() -> impl Strategy<Value = Self> {
        prop_oneof![
            option::of(select(NAMES)).prop_map(Self::Name),
            (1..=FOLDERS, select(TITLES), Self::position()).prop_map(
                |(folder, title, position)| Self::Folder {
                    folder,
                    title,
                    position
                }
            ),
            (0..SIGNALS).prop_map(Self::Signal),
        ]
    }

    fn item_strategy() -> impl Strategy<Value = Self> {
        prop_oneof![
            Self::create_strategy(),
            (1..=ITEMS, select(TITLES)).prop_map(|(item, title)| Self::ItemTitle(item, title)),
            (1..=ITEMS, option::of(select(CATEGORIES)))
                .prop_map(|(item, category)| Self::Category(item, category)),
            (1..=ITEMS, select(KEYS)).prop_map(|(item, key)| Self::ItemKey(item, key)),
            (1..=ITEMS, option::of(0..=FOLDERS))
                .prop_map(|(item, folder)| Self::ItemFolder(item, folder)),
            (1..=ITEMS, 1..=SECTIONS, select(TITLES), Self::position()).prop_map(
                |(item, section, title, position)| Self::Section {
                    item,
                    section,
                    title,
                    position
                }
            ),
            (1..=ITEMS, select(URLS), Self::match_kind(), 0u32..3).prop_map(
                |(item, url, match_kind, position)| Self::Website {
                    item,
                    url,
                    match_kind,
                    position
                }
            ),
            (1..=ITEMS, Self::role(), option::of(0..=CREDENTIALS)).prop_map(
                |(item, role, credential)| Self::Slot {
                    item,
                    role,
                    credential
                }
            ),
            (1..=ITEMS, option::of(Self::trash(Just(None))))
                .prop_map(|(item, trashed)| Self::ItemTrashed(item, trashed)),
        ]
    }

    fn credential_strategy() -> impl Strategy<Value = Self> {
        prop_oneof![
            Self::create_strategy(),
            (1..=CREDENTIALS, 0..=ITEMS).prop_map(|(c, item)| Self::CredentialItem(c, item)),
            (1..=CREDENTIALS, select(TITLES))
                .prop_map(|(c, title)| Self::CredentialTitle(c, title)),
            (1..=CREDENTIALS, Self::kind()).prop_map(|(c, kind)| Self::Kind(c, kind)),
            (1..=CREDENTIALS, select(KEYS)).prop_map(|(c, key)| Self::CredentialKey(c, key)),
            (
                1..=CREDENTIALS,
                option::of((0..=ITEMS, 0..=SECTIONS)),
                Self::position()
            )
                .prop_map(|(credential, section, position)| Self::Placement {
                    credential,
                    section,
                    position
                }),
            (1..=CREDENTIALS, select(VALUES)).prop_map(|(c, value)| Self::Value(c, value)),
            (1..=CREDENTIALS, 1..=HISTORY, select(VALUES), select(TIMES)).prop_map(
                |(credential, entry, value, replaced_at)| Self::History {
                    credential,
                    entry,
                    value,
                    replaced_at
                }
            ),
            (1..=CREDENTIALS, select(TIMES)).prop_map(|(c, at)| Self::LastUsed(c, at)),
            (
                1..=CREDENTIALS,
                option::of(Self::trash(option::of(Self::role())))
            )
                .prop_map(|(c, trashed)| Self::CredentialTrashed(c, trashed)),
        ]
    }

    /// Position of a folder, section, or credential. Small, so positions tie.
    fn position() -> impl Strategy<Value = Option<u32>> {
        option::of(0u32..3)
    }

    fn role() -> impl Strategy<Value = Role> {
        select(&[Role::Username, Role::Password, Role::Totp][..])
    }

    fn match_kind() -> impl Strategy<Value = MatchKind> {
        select(&[MatchKind::Domain, MatchKind::Host, MatchKind::Never][..])
    }

    fn kind() -> impl Strategy<Value = FieldKind> {
        select(vec![
            FieldKind::default(),
            FieldKind::Text(TextField::default()),
            FieldKind::Email,
            FieldKind::Totp,
            FieldKind::Passkey,
        ])
    }

    /// Trash value with a role from `role`.
    fn trash(role: impl Strategy<Value = Option<Role>>) -> impl Strategy<Value = TrashValue> {
        (select(TIMES), role).prop_map(|(deleted_at, role)| TrashValue { deleted_at, role })
    }

    /// Signal entry `n`. Entries 0 and 1, and entries 2 and 3, are about one
    /// report each.
    fn signal(n: u8) -> SignalEntry {
        let rp_id = "example.com".to_string();
        match n {
            0 | 1 => SignalEntry::Rename(RenameEntry {
                rp_id,
                user_handle: "CQ".to_string(),
                name: if n == 0 { "Ann" } else { "Bob" }.to_string(),
                at: 10 + i64::from(n),
            }),
            2 | 3 => SignalEntry::Unknown(UnknownEntry {
                rp_id,
                credential_id: "AQ".to_string(),
                at: 20 + i64::from(n),
            }),
            4 => SignalEntry::Dismissed(DismissEntry {
                rp_id,
                credential_id: "AQ".to_string(),
                kind: DismissKind::Rejection,
                at: 30,
            }),
            _ => SignalEntry::Accepted(AcceptedEntry {
                rp_id,
                user_handle: "CQ".to_string(),
                credential_ids: vec!["AQ".to_string()],
                at: 40,
            }),
        }
    }

    fn apply(&self, s: &mut SyncState, m: &Mint, replica: ReplicaId) {
        match self.clone() {
            Self::Name(name) => s.name.write(m, name.map(str::to_string)),
            Self::Folder {
                folder,
                title,
                position,
            } => {
                let value = FolderValue {
                    title: title.to_string(),
                    position,
                };
                s.folders.entry(Ids::folder(folder)).write(m, value);
            },
            Self::NewItem { item, title, key } => {
                let entry = s.items.entry(Ids::item(item));
                entry.title.write(m, title.to_string());
                entry.key.write(m, key.to_string());
            },
            Self::ItemTitle(item, title) => {
                s.items
                    .entry(Ids::item(item))
                    .title
                    .write(m, title.to_string());
            },
            Self::Category(item, category) => {
                let category = category.map(str::to_string);
                s.items.entry(Ids::item(item)).category.write(m, category);
            },
            Self::ItemKey(item, key) => {
                s.items.entry(Ids::item(item)).key.write(m, key.to_string());
            },
            Self::ItemFolder(item, folder) => {
                let folder = folder.map(Ids::folder);
                s.items.entry(Ids::item(item)).folder.write(m, folder);
            },
            Self::Section {
                item,
                section,
                title,
                position,
            } => {
                let value = SectionValue {
                    title: title.to_string(),
                    position,
                };
                let sections = &mut s.items.entry(Ids::item(item)).sections;
                sections.entry(Ids::section(item, section)).write(m, value);
            },
            Self::Website {
                item,
                url,
                match_kind,
                position,
            } => {
                let value = WebsiteValue {
                    match_kind,
                    position,
                };
                let websites = &mut s.items.entry(Ids::item(item)).websites;
                websites.entry(url.to_string()).write(m, value);
            },
            Self::Slot {
                item,
                role,
                credential,
            } => {
                let entry = s.items.entry(Ids::item(item));
                let slot = match role {
                    Role::Username => &mut entry.username,
                    Role::Password => &mut entry.password,
                    Role::Totp => &mut entry.totp,
                };
                slot.write(m, credential.map(Ids::credential));
            },
            Self::ItemTrashed(item, trashed) => {
                s.items.entry(Ids::item(item)).trashed.write(m, trashed);
            },
            Self::NewCredential {
                credential,
                item,
                title,
                key,
                value,
            } => {
                let entry = s.credentials.entry(Ids::credential(credential));
                entry.item.write(m, Ids::item(item));
                entry.title.write(m, title.to_string());
                entry.key.write(m, key.to_string());
                entry.value.write(m, SecretText::new(value));
            },
            Self::CredentialItem(credential, item) => {
                let entry = s.credentials.entry(Ids::credential(credential));
                entry.item.write(m, Ids::item(item));
            },
            Self::CredentialTitle(credential, title) => {
                let entry = s.credentials.entry(Ids::credential(credential));
                entry.title.write(m, title.to_string());
            },
            Self::Kind(credential, kind) => {
                s.credentials
                    .entry(Ids::credential(credential))
                    .kind
                    .write(m, kind);
            },
            Self::CredentialKey(credential, key) => {
                let entry = s.credentials.entry(Ids::credential(credential));
                entry.key.write(m, key.to_string());
            },
            Self::Placement {
                credential,
                section,
                position,
            } => {
                let placement = Placement {
                    section: section.map(|(item, n)| Ids::section(item, n)),
                    position,
                };
                let entry = s.credentials.entry(Ids::credential(credential));
                entry.placement.write(m, placement);
            },
            Self::Value(credential, value) => {
                let entry = s.credentials.entry(Ids::credential(credential));
                entry.value.write(m, SecretText::new(value));
            },
            Self::History {
                credential,
                entry,
                value,
                replaced_at,
            } => {
                let value = HistoryValue {
                    at: replaced_at,
                    kind: HistoryKind::ValueUpdated,
                    value: Some(SecretText::new(value)),
                };
                let history = &mut s.credentials.entry(Ids::credential(credential)).history;
                history
                    .entry(Ids::history(credential, entry))
                    .write(m, value);
            },
            Self::LastUsed(credential, at) => {
                let last_used = &mut s
                    .credentials
                    .entry(Ids::credential(credential))
                    .last_used_day_at;
                last_used.entry(replica).write(m, at);
            },
            Self::CredentialTrashed(credential, trashed) => {
                let entry = s.credentials.entry(Ids::credential(credential));
                entry.trashed.write(m, trashed);
            },
            Self::Signal(n) => {
                let entry = Self::signal(n);
                s.signals.entry(entry.key()).write(m, entry);
            },
        }
    }
}

/// Map entry that a generated remove drops. A remove of an item or a
/// credential is a purge.
#[derive(Clone, Copy, Debug)]
pub(super) enum Remove {
    Folder(u8),
    Item(u8),
    Section(u8, u8),
    Website(u8, &'static str),
    Credential(u8),
    History(u8, u8),
    Signal(u8),
}

impl Remove {
    fn strategy() -> impl Strategy<Value = Self> {
        prop_oneof![
            (1..=FOLDERS).prop_map(Self::Folder),
            (1..=ITEMS).prop_map(Self::Item),
            (1..=ITEMS, 1..=SECTIONS).prop_map(|(item, n)| Self::Section(item, n)),
            (1..=ITEMS, select(URLS)).prop_map(|(item, url)| Self::Website(item, url)),
            (1..=CREDENTIALS).prop_map(Self::Credential),
            (1..=CREDENTIALS, 1..=HISTORY).prop_map(|(c, n)| Self::History(c, n)),
            (0..SIGNALS).prop_map(Self::Signal),
        ]
    }

    fn apply(self, s: &mut SyncState) {
        match self {
            Self::Folder(folder) => {
                s.folders.remove(&Ids::folder(folder));
            },
            Self::Item(item) => {
                s.items.remove(&Ids::item(item));
            },
            Self::Section(item, n) => {
                if s.items.get(&Ids::item(item)).is_some() {
                    let sections = &mut s.items.entry(Ids::item(item)).sections;
                    sections.remove(&Ids::section(item, n));
                }
            },
            Self::Website(item, url) => {
                if s.items.get(&Ids::item(item)).is_some() {
                    let websites = &mut s.items.entry(Ids::item(item)).websites;
                    websites.remove(&url.to_string());
                }
            },
            Self::Credential(credential) => {
                s.credentials.remove(&Ids::credential(credential));
            },
            Self::History(credential, n) => {
                if s.credentials.get(&Ids::credential(credential)).is_some() {
                    let history = &mut s.credentials.entry(Ids::credential(credential)).history;
                    history.remove(&Ids::history(credential, n));
                }
            },
            Self::Signal(n) => {
                s.signals.remove(&Write::signal(n).key());
            },
        }
    }
}

/// Write or remove of a generated mint.
#[derive(Clone, Debug)]
pub(super) enum Edit {
    Write(Write),
    Remove(Remove),
}

impl Edit {
    fn strategy() -> impl Strategy<Value = Self> {
        prop_oneof![
            4 => Write::strategy().prop_map(Self::Write),
            1 => Remove::strategy().prop_map(Self::Remove),
        ]
    }

    fn apply(&self, s: &mut SyncState, m: &Mint, replica: ReplicaId) {
        match self {
            Self::Write(write) => write.apply(s, m, replica),
            Self::Remove(remove) => remove.apply(s),
        }
    }
}

/// Writes of a shared base and the mints of 2 or 3 sessions on copies of it.
#[derive(Clone, Debug)]
pub(super) struct Script {
    /// Written by session 1 in one mint.
    base: Vec<Write>,
    /// Number of entries added to the unknown list of the base, if any.
    flood: Option<u32>,
    /// Mints of each session after the base, each a list of edits.
    sessions: Vec<Vec<Vec<Edit>>>,
}

impl Script {
    /// Entries of a flood. More than the 500 that `SignalStore::record`
    /// keeps.
    const FLOOD: std::ops::RangeInclusive<u32> = 501..=520;

    pub(super) fn strategy() -> impl Strategy<Value = Self> {
        let base = (
            vec(Write::create_strategy(), 4..10),
            vec(Write::strategy(), 0..12),
        )
            .prop_map(|(mut created, writes)| {
                created.extend(writes);
                created
            });
        let sessions =
            (2usize..=3).prop_flat_map(|n| vec(vec(vec(Edit::strategy(), 1..5), 1..3), n));
        (base, option::of(Self::FLOOD), sessions).prop_map(|(base, flood, sessions)| Self {
            base,
            flood,
            sessions,
        })
    }

    /// Joined state of every session.
    pub(super) fn play(&self) -> State {
        let mut sessions: Vec<Session> = (1..=self.sessions.len() as u128).map(session).collect();

        let mut base = State::default();
        let first = &mut sessions[0];
        let m = first.mint(&mut base, NOW);
        for write in &self.base {
            write.apply(&mut base.store, &m, first.replica);
        }
        for n in 0..self.flood.unwrap_or(0) {
            let entry = SignalEntry::Unknown(UnknownEntry {
                rp_id: "flood.com".to_string(),
                credential_id: format!("c{n}"),
                at: i64::from(n),
            });
            base.store.signals.entry(entry.key()).write(&m, entry);
        }

        let mut joined = State::default();
        for (session, mints) in sessions.iter_mut().zip(&self.sessions) {
            let mut state = base.clone();
            for edits in mints {
                let m = session.mint(&mut state, NOW);
                for edit in edits {
                    edit.apply(&mut state.store, &m, session.replica);
                }
            }
            joined.join(state);
        }
        joined
    }
}
