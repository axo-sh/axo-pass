//! Local edits: the differences between a decrypted vault and the view of its
//! sync state.
//!
//! Entries are compared by id. Keys are compared with the shown keys, so a
//! suffixed key in the vault is not an edit. Lists are compared as order, so
//! stored positions with gaps or ties are not an edit. Folders, sections, and
//! role slots are compared resolved against the entries the vault holds. An
//! entry in the view that the vault lacks is removed.

use std::collections::{BTreeMap, BTreeSet};

use secrecy::ExposeSecret;
use thiserror::Error;
use uuid::Uuid;

use super::crdt::{Ask, CausalState, Mint, MvRegister, ReplicaId, Session, WriteId};
use super::model::{
    CredentialId, FolderId, FolderValue, HistoryId, HistoryValue, ItemId, Placement, SecretText,
    SectionId, SectionValue, SyncCredential, SyncItem, SyncState, TrashValue, WebsiteValue,
};
use super::view::{VaultView, list_order};
use crate::secrets::vaults::Error;
use crate::secrets::vaults::autofill::item::Website;
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::model::{
    DeletedInfo, SyncCredentialEntry, SyncEntries, SyncItemEntry, Vault,
};
use crate::secrets::vaults::passkey::signals::SignalEntry;

/// Register writes and entry removes of one transaction, found by
/// [`LocalEdits::find`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LocalEdits {
    edits: Vec<Edit>,
}

/// Failure of [`LocalEdits::find`].
#[derive(Debug, Error)]
pub enum DiffError {
    /// The sync model holds one website per URL.
    #[error("item {item} has two websites with the URL {url}")]
    DuplicateWebsite { item: ItemId, url: String },
    #[error(transparent)]
    Vault(#[from] Error),
}

/// One register write or entry remove.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Edit {
    Name(Option<String>),
    Folder(FolderId, FolderValue),
    RemoveFolder(FolderId),
    Signal(String, SignalEntry),
    RemoveSignal(String),
    Item(ItemId, ItemWrite),
    RemoveItem(ItemId),
    Section(ItemId, SectionId, SectionValue),
    RemoveSection(ItemId, SectionId),
    Website(ItemId, String, WebsiteValue),
    RemoveWebsite(ItemId, String),
    Credential(CredentialId, CredentialWrite),
    RemoveCredential(CredentialId),
    History(CredentialId, HistoryId, HistoryValue),
    RemoveHistory(CredentialId, HistoryId),
    /// Write to the register of one replica.
    LastUsed(CredentialId, ReplicaId, i64),
}

/// Write to one register of an item.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ItemWrite {
    Title(String),
    Category(Option<String>),
    Key(String),
    Folder(Option<FolderId>),
    Username(Option<CredentialId>),
    Password(Option<CredentialId>),
    Totp(Option<CredentialId>),
    Trashed(Option<TrashValue>),
}

/// Write to one register of a credential.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum CredentialWrite {
    Item(ItemId),
    Title(String),
    Kind(FieldKind),
    Key(String),
    Placement(Placement),
    Value(SecretText),
    Trashed(Option<TrashValue>),
}

impl LocalEdits {
    /// Edits that make the view of `state` show `vault`.
    ///
    /// `replica` is the local replica. A last used time is written to its
    /// register, and only if it is later than the shown time. Fails if an
    /// item of `vault` has two websites with one URL. Mints nothing.
    pub fn find(
        state: &CausalState<SyncState>,
        vault: &Vault,
        replica: ReplicaId,
    ) -> Result<Self, DiffError> {
        let view = VaultView::of(state);
        let entries = vault.sync_entries()?;
        let mut diff = Diff::new(&state.store, &view, &entries, replica);
        diff.name();
        diff.folders();
        diff.signals();
        diff.items()?;
        diff.credentials();
        Ok(Self { edits: diff.edits })
    }

    /// Whether no register changes.
    pub fn is_empty(&self) -> bool {
        self.edits.is_empty()
    }

    pub(crate) fn edits(&self) -> &[Edit] {
        &self.edits
    }

    /// Record the edits in `state` at `now`, in Unix seconds.
    ///
    /// Mints one write id if the edits are not empty, and writes every changed
    /// register with it. Returns the write id.
    pub fn record(
        self,
        state: &mut CausalState<SyncState>,
        session: &mut Session,
        now: i64,
    ) -> Option<WriteId> {
        if self.is_empty() {
            return None;
        }
        let mint = session.mint(state, now);
        for edit in self.edits {
            edit.record(&mut state.store, &mint);
        }
        Some(mint.write_id)
    }
}

impl Edit {
    /// Write or remove in `store`. A map entry is created only to write into
    /// it.
    fn record(self, store: &mut SyncState, mint: &Mint) {
        match self {
            Self::Name(name) => store.name.write(mint, name),
            Self::Folder(id, value) => store.folders.entry(id).write(mint, value),
            Self::RemoveFolder(id) => {
                store.folders.remove(&id);
            },
            Self::Signal(key, entry) => store.signals.entry(key).write(mint, entry),
            Self::RemoveSignal(key) => {
                store.signals.remove(&key);
            },
            Self::Item(id, write) => write.record(store.items.entry(id), mint),
            Self::RemoveItem(id) => {
                store.items.remove(&id);
            },
            Self::Section(item, id, value) => {
                let sections = &mut store.items.entry(item).sections;
                sections.entry(id).write(mint, value);
            },
            Self::RemoveSection(item, id) => {
                if store.items.get(&item).is_some() {
                    store.items.entry(item).sections.remove(&id);
                }
            },
            Self::Website(item, url, value) => {
                let websites = &mut store.items.entry(item).websites;
                websites.entry(url).write(mint, value);
            },
            Self::RemoveWebsite(item, url) => {
                if store.items.get(&item).is_some() {
                    store.items.entry(item).websites.remove(&url);
                }
            },
            Self::Credential(id, write) => write.record(store.credentials.entry(id), mint),
            Self::RemoveCredential(id) => {
                store.credentials.remove(&id);
            },
            Self::History(credential, id, value) => {
                let history = &mut store.credentials.entry(credential).history;
                history.entry(id).write(mint, value);
            },
            Self::RemoveHistory(credential, id) => {
                if store.credentials.get(&credential).is_some() {
                    store.credentials.entry(credential).history.remove(&id);
                }
            },
            Self::LastUsed(credential, replica, at) => {
                let last_used = &mut store.credentials.entry(credential).last_used_day_at;
                last_used.entry(replica).write(mint, at);
            },
        }
    }
}

impl ItemWrite {
    fn record(self, item: &mut SyncItem, mint: &Mint) {
        match self {
            Self::Title(title) => item.title.write(mint, title),
            Self::Category(category) => item.category.write(mint, category),
            Self::Key(key) => item.key.write(mint, key),
            Self::Folder(folder) => item.folder.write(mint, folder),
            Self::Username(slot) => item.username.write(mint, slot),
            Self::Password(slot) => item.password.write(mint, slot),
            Self::Totp(slot) => item.totp.write(mint, slot),
            Self::Trashed(trashed) => item.trashed.write(mint, trashed),
        }
    }
}

impl CredentialWrite {
    fn record(self, credential: &mut SyncCredential, mint: &Mint) {
        match self {
            Self::Item(item) => credential.item.write(mint, item),
            Self::Title(title) => credential.title.write(mint, title),
            Self::Kind(kind) => credential.kind.write(mint, kind),
            Self::Key(key) => credential.key.write(mint, key),
            Self::Placement(placement) => credential.placement.write(mint, placement),
            Self::Value(value) => credential.value.write(mint, value),
            Self::Trashed(trashed) => credential.trashed.write(mint, trashed),
        }
    }
}

impl TrashValue {
    /// Trash value of a vault entry, field by field.
    fn of(info: &DeletedInfo) -> Self {
        let DeletedInfo { deleted_at, role } = info;
        Self {
            deleted_at: *deleted_at,
            role: *role,
        }
    }
}

/// Comparison of a vault with a view.
struct Diff<'a> {
    store: &'a SyncState,
    view: &'a VaultView,
    vault: &'a SyncEntries<'a>,
    items: BTreeMap<ItemId, &'a SyncItemEntry<'a>>,
    credentials: BTreeMap<CredentialId, &'a SyncCredentialEntry<'a>>,
    replica: ReplicaId,
    edits: Vec<Edit>,
}

impl<'a> Diff<'a> {
    fn new(
        store: &'a SyncState,
        view: &'a VaultView,
        vault: &'a SyncEntries<'a>,
        replica: ReplicaId,
    ) -> Self {
        Self {
            store,
            view,
            vault,
            items: vault.items.iter().map(|i| (i.overview.id, i)).collect(),
            credentials: vault
                .credentials
                .iter()
                .map(|c| (c.overview.id, c))
                .collect(),
            replica,
            edits: Vec::new(),
        }
    }

    fn name(&mut self) {
        if self.vault.name != self.view.name.as_deref() {
            let name = self.vault.name.map(str::to_string);
            self.edits.push(Edit::Name(name));
        }
    }

    fn folders(&mut self) {
        let shown: BTreeMap<FolderId, FolderValue> = self
            .view
            .folders
            .iter()
            .map(|f| {
                let value = FolderValue {
                    title: f.title.clone(),
                    position: f.position,
                };
                (f.id, value)
            })
            .collect();
        for id in shown.keys() {
            if !self.vault.folders.contains_key(id) {
                self.edits.push(Edit::RemoveFolder(*id));
            }
        }

        let positions = Listed::positions(
            self.vault
                .folders
                .values()
                .map(|f| Listed {
                    id: f.id,
                    title: &f.title,
                    stored: f.position,
                    shown: shown.get(&f.id).map(|value| value.position),
                })
                .collect(),
        );
        for folder in self.vault.folders.values() {
            let value = FolderValue {
                title: folder.title.clone(),
                position: positions[&folder.id],
            };
            if shown.get(&folder.id) != Some(&value) {
                self.edits.push(Edit::Folder(folder.id, value));
            }
        }
    }

    /// Signals compared by report key. The list order is not compared.
    fn signals(&mut self) {
        let shown: BTreeMap<String, SignalEntry> =
            self.view.signals.entries().map(|e| (e.key(), e)).collect();
        let stored: BTreeMap<String, SignalEntry> = self
            .vault
            .passkey_signals
            .entries()
            .map(|e| (e.key(), e))
            .collect();
        for key in shown.keys() {
            if !stored.contains_key(key) {
                self.edits.push(Edit::RemoveSignal(key.clone()));
            }
        }
        for (key, entry) in stored {
            if shown.get(&key) != Some(&entry) {
                self.edits.push(Edit::Signal(key, entry));
            }
        }
    }

    fn items(&mut self) -> Result<(), DiffError> {
        for id in self.view.items.keys() {
            if !self.items.contains_key(id) {
                self.edits.push(Edit::RemoveItem(*id));
            }
        }
        for entry in &self.vault.items {
            self.item(entry)?;
        }
        Ok(())
    }

    /// Item registers, sections, and websites. Every register of an item the
    /// view lacks is written.
    fn item(&mut self, entry: &SyncItemEntry<'a>) -> Result<(), DiffError> {
        let item = entry.overview;
        let id = item.id;
        let shown = self.view.items.get(&id);
        let mut writes = Vec::new();

        if shown.map(|s| &s.title) != Some(&item.title) {
            writes.push(ItemWrite::Title(item.title.clone()));
        }
        if shown.map(|s| &s.category) != Some(&item.category) {
            writes.push(ItemWrite::Category(item.category.clone()));
        }
        if shown.map(|s| &s.key) != Some(&item.key) {
            writes.push(ItemWrite::Key(item.key.clone()));
        }

        let folder = item.folder.filter(|f| self.vault.folders.contains_key(f));
        if shown.map(|_| self.shown_folder(id)) != Some(folder) {
            writes.push(ItemWrite::Folder(folder));
        }

        let autofill = &item.autofill;
        let slots = [autofill.username, autofill.password, autofill.totp]
            .map(|slot| self.resolved_slot(id, slot));
        let shown_slots = shown.map(|_| self.shown_slots(id));
        let [username, password, totp] = slots;
        if shown_slots.map(|s| s[0]) != Some(username) {
            writes.push(ItemWrite::Username(username));
        }
        if shown_slots.map(|s| s[1]) != Some(password) {
            writes.push(ItemWrite::Password(password));
        }
        if shown_slots.map(|s| s[2]) != Some(totp) {
            writes.push(ItemWrite::Totp(totp));
        }

        let trashed = entry.trashed.as_ref().map(TrashValue::of);
        if shown.map(|s| &s.trashed) != Some(&trashed) {
            writes.push(ItemWrite::Trashed(trashed));
        }
        self.edits
            .extend(writes.into_iter().map(|write| Edit::Item(id, write)));

        self.sections(entry);
        self.websites(id, &autofill.websites)
    }

    fn sections(&mut self, entry: &SyncItemEntry<'a>) {
        let item = entry.overview;
        let shown: BTreeMap<SectionId, SectionValue> = self
            .view
            .items
            .get(&item.id)
            .into_iter()
            .flat_map(|i| &i.sections)
            .map(|s| {
                let value = SectionValue {
                    title: s.title.clone(),
                    position: s.position,
                };
                (s.id, value)
            })
            .collect();
        for id in shown.keys() {
            if !item.sections.contains_key(id) {
                self.edits.push(Edit::RemoveSection(item.id, *id));
            }
        }

        let positions = Listed::positions(
            item.sections
                .values()
                .map(|s| Listed {
                    id: s.id,
                    title: &s.title,
                    stored: s.position,
                    shown: shown.get(&s.id).map(|value| value.position),
                })
                .collect(),
        );
        for section in item.sections.values() {
            let value = SectionValue {
                title: section.title.clone(),
                position: positions[&section.id],
            };
            if shown.get(&section.id) != Some(&value) {
                self.edits.push(Edit::Section(item.id, section.id, value));
            }
        }
    }

    /// Websites by URL, with their order. Fails on two websites with one URL.
    fn websites(&mut self, item: ItemId, websites: &[Website]) -> Result<(), DiffError> {
        let mut urls = BTreeSet::new();
        if let Some(website) = websites.iter().find(|w| !urls.insert(w.url.as_str())) {
            return Err(DiffError::DuplicateWebsite {
                item,
                url: website.url.clone(),
            });
        }

        let shown: BTreeMap<&str, WebsiteValue> = self
            .view
            .items
            .get(&item)
            .into_iter()
            .flat_map(|i| &i.websites)
            .map(|w| {
                let value = WebsiteValue {
                    match_kind: w.match_kind,
                    position: w.position,
                };
                (w.url.as_str(), value)
            })
            .collect();
        for url in shown.keys() {
            if !urls.contains(url) {
                self.edits.push(Edit::RemoveWebsite(item, url.to_string()));
            }
        }

        // Shown position of each website the view holds. A new website takes
        // the position after the website before it.
        let mut previous: Option<u32> = None;
        let candidates: Vec<u32> = websites
            .iter()
            .map(|w| {
                let position = match shown.get(w.url.as_str()) {
                    Some(value) => value.position,
                    None => previous.map_or(0, |p| p.saturating_add(1)),
                };
                previous = Some(position);
                position
            })
            .collect();
        let mut by_candidate: Vec<(u32, &str)> = candidates
            .iter()
            .zip(websites)
            .map(|(position, w)| (*position, w.url.as_str()))
            .collect();
        by_candidate.sort();
        let same_order = by_candidate
            .iter()
            .map(|(_, url)| *url)
            .eq(websites.iter().map(|w| w.url.as_str()));

        for (index, (website, candidate)) in websites.iter().zip(candidates).enumerate() {
            let position = if same_order {
                candidate
            } else {
                u32::try_from(index).unwrap_or(u32::MAX)
            };
            let value = WebsiteValue {
                match_kind: website.match_kind,
                position,
            };
            if shown.get(website.url.as_str()) != Some(&value) {
                self.edits
                    .push(Edit::Website(item, website.url.clone(), value));
            }
        }
        Ok(())
    }

    fn credentials(&mut self) {
        for id in self.view.credentials.keys() {
            if !self.credentials.contains_key(id) {
                self.edits.push(Edit::RemoveCredential(*id));
            }
        }

        // Lists of credentials that are not trashed, by item and section. A
        // trashed credential keeps its stored position.
        let mut lists: BTreeMap<(ItemId, Option<SectionId>), Vec<Listed>> = BTreeMap::new();
        let mut positions: BTreeMap<CredentialId, Option<u32>> = BTreeMap::new();
        for entry in &self.vault.credentials {
            let credential = entry.overview;
            if entry.trashed.is_some() {
                positions.insert(credential.id, credential.position);
                continue;
            }
            let shown = self.view.credentials.get(&credential.id);
            lists
                .entry((entry.item, self.resolved_section(entry)))
                .or_default()
                .push(Listed {
                    id: credential.id,
                    title: &credential.title,
                    stored: credential.position,
                    shown: shown.map(|c| c.position),
                });
        }
        for list in lists.into_values() {
            positions.extend(Listed::positions(list));
        }

        for entry in &self.vault.credentials {
            let position = positions[&entry.overview.id];
            self.credential(entry, position);
        }
    }

    /// Credential registers and history. Every register of a credential the
    /// view lacks is written.
    fn credential(&mut self, entry: &SyncCredentialEntry<'a>, position: Option<u32>) {
        let credential = entry.overview;
        let id = credential.id;
        let shown = self.view.credentials.get(&id);
        let mut writes = Vec::new();

        if shown.map(|s| s.item) != Some(entry.item) {
            writes.push(CredentialWrite::Item(entry.item));
        }
        if shown.map(|s| &s.title) != Some(&credential.title) {
            writes.push(CredentialWrite::Title(credential.title.clone()));
        }
        if shown.map(|s| &s.kind) != Some(&credential.kind) {
            writes.push(CredentialWrite::Kind(credential.kind.clone()));
        }
        if shown.map(|s| &s.key) != Some(&credential.key) {
            writes.push(CredentialWrite::Key(credential.key.clone()));
        }

        let placement = Placement {
            section: self.resolved_section(entry),
            position,
        };
        let shown_placement = shown.map(|s| Placement {
            section: self.shown_section(entry),
            position: s.position,
        });
        if shown_placement.as_ref() != Some(&placement) {
            writes.push(CredentialWrite::Placement(placement));
        }

        let value = entry.value.expose_secret();
        if shown.map(|s| s.value.0.as_str()) != Some(value.as_str()) {
            writes.push(CredentialWrite::Value(SecretText::new(value.as_str())));
        }

        let trashed = entry.trashed.as_ref().map(TrashValue::of);
        if shown.map(|s| &s.trashed) != Some(&trashed) {
            writes.push(CredentialWrite::Trashed(trashed));
        }
        self.edits
            .extend(writes.into_iter().map(|write| Edit::Credential(id, write)));

        let shown_history: BTreeMap<HistoryId, HistoryValue> = shown
            .into_iter()
            .flat_map(|s| &s.history)
            .map(|h| {
                let value = HistoryValue {
                    value: h.value.clone(),
                    replaced_at: h.replaced_at,
                };
                (h.id, value)
            })
            .collect();
        let stored: BTreeSet<HistoryId> = entry.history.iter().map(|h| h.id).collect();
        for history_id in shown_history.keys() {
            if !stored.contains(history_id) {
                self.edits.push(Edit::RemoveHistory(id, *history_id));
            }
        }
        for previous in &entry.history {
            let value = HistoryValue {
                value: SecretText::new(previous.value.expose_secret().as_str()),
                replaced_at: previous.replaced_at,
            };
            if shown_history.get(&previous.id) != Some(&value) {
                self.edits.push(Edit::History(id, previous.id, value));
            }
        }

        // No local action clears or lowers the last used time.
        if let Some(at) = credential.last_used_day_at
            && shown
                .and_then(|s| s.last_used_day_at)
                .is_none_or(|shown| at > shown)
        {
            self.edits.push(Edit::LastUsed(id, self.replica, at));
        }
    }

    /// Section of a vault credential, `None` if its item lacks the section.
    fn resolved_section(&self, entry: &SyncCredentialEntry<'a>) -> Option<SectionId> {
        entry
            .overview
            .section
            .filter(|s| self.has_section(entry.item, *s))
    }

    /// Section of the shown placement register value, resolved against the
    /// item of the vault credential.
    fn shown_section(&self, entry: &SyncCredentialEntry<'a>) -> Option<SectionId> {
        self.store
            .credentials
            .get(&entry.overview.id)
            .and_then(|c| c.placement.shown())
            .and_then(|p| p.section)
            .filter(|s| self.has_section(entry.item, *s))
    }

    fn has_section(&self, item: ItemId, section: SectionId) -> bool {
        self.items
            .get(&item)
            .is_some_and(|i| i.overview.sections.contains_key(&section))
    }

    /// Shown folder register value, resolved against the vault folders.
    fn shown_folder(&self, item: ItemId) -> Option<FolderId> {
        self.store
            .items
            .get(&item)
            .and_then(|i| i.folder.shown().copied().flatten())
            .filter(|f| self.vault.folders.contains_key(f))
    }

    /// Slot that names a credential of `item` that is not trashed in the
    /// vault. Otherwise `None`.
    fn resolved_slot(&self, item: ItemId, slot: Option<CredentialId>) -> Option<CredentialId> {
        slot.filter(|c| {
            self.credentials
                .get(c)
                .is_some_and(|entry| entry.item == item && entry.trashed.is_none())
        })
    }

    /// Shown username, password, and TOTP slot register values, resolved
    /// against the vault. If the username and password slots resolve to one
    /// credential, the slot whose value has the lower order key is empty, and
    /// the username slot if the order keys are equal.
    fn shown_slots(&self, item: ItemId) -> [Option<CredentialId>; 3] {
        let Some(entry) = self.store.items.get(&item) else {
            return [None; 3];
        };
        let resolve = |register: &MvRegister<Option<CredentialId>, Ask>| {
            register
                .ordered()
                .pop()
                .map(|(key, v)| (key, self.resolved_slot(item, v.value)))
        };
        let totp = resolve(&entry.totp).and_then(|(_, slot)| slot);
        match (resolve(&entry.username), resolve(&entry.password)) {
            (Some((u_key, Some(u))), Some((p_key, Some(p)))) if u == p => {
                if u_key <= p_key {
                    [None, Some(p), totp]
                } else {
                    [Some(u), None, totp]
                }
            },
            (username, password) => [
                username.and_then(|(_, slot)| slot),
                password.and_then(|(_, slot)| slot),
                totp,
            ],
        }
    }
}

/// Vault entry of a list of folders, sections, or credentials.
struct Listed<'a> {
    id: Uuid,
    title: &'a str,
    /// Position stored in the vault.
    stored: Option<u32>,
    /// Shown position. `None` if the view lacks the entry.
    shown: Option<Option<u32>>,
}

impl Listed<'_> {
    /// Position to write for each entry.
    ///
    /// Each entry takes its shown position, or its stored position if the view
    /// lacks it. If these give the vault order, they are kept. Otherwise each
    /// entry takes its index in the vault order.
    fn positions(mut list: Vec<Self>) -> BTreeMap<Uuid, Option<u32>> {
        let candidate = |e: &Self| e.shown.unwrap_or(e.stored);
        list.sort_by(|a, b| {
            list_order(a.stored, a.title, a.id).cmp(&list_order(b.stored, b.title, b.id))
        });
        let mut by_candidate: Vec<&Self> = list.iter().collect();
        by_candidate.sort_by(|a, b| {
            list_order(candidate(a), a.title, a.id).cmp(&list_order(candidate(b), b.title, b.id))
        });
        let same_order = by_candidate
            .iter()
            .map(|e| e.id)
            .eq(list.iter().map(|e| e.id));
        list.iter()
            .enumerate()
            .map(|(index, e)| {
                let position = if same_order {
                    candidate(e)
                } else {
                    Some(u32::try_from(index).unwrap_or(u32::MAX))
                };
                (e.id, position)
            })
            .collect()
    }
}
