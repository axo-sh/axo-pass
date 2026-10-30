//! View of a sync state: the values the vault shows.
//!
//! Each register shows one value by its policy. References to missing entries
//! are resolved, and equal-value collapse runs on the resolved values. Lists
//! are in the order the vault shows them.

use std::collections::BTreeMap;

use uuid::Uuid;

use super::crdt::{
    Ask, CausalState, CausalStore, MvRegister, OrMap, Order, OrderKey, Policy, ReplicaId, Trash,
};
use super::model::{
    CredentialId, FolderId, FolderValue, HistoryId, ItemId, RecoveryRecipient, Removal,
    ReplicaKeys, SecretText, SectionId, SyncCredential, SyncItem, SyncState, TrashValue,
};
use crate::secrets::vaults::autofill::item::MatchKind;
use crate::secrets::vaults::model::display_order;
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::passkey::signals::SignalStore;

/// Version of the view rules. Changes with any rule that can change the vault
/// a view produces.
pub const VIEW_VERSION: u32 = 1;

/// Values the vault shows for one sync state, by id.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct VaultView {
    pub name: Option<String>,
    /// In list order.
    pub folders: Vec<FolderView>,
    /// Live and trashed items.
    pub items: BTreeMap<ItemId, ItemView>,
    /// Live and trashed credentials.
    pub credentials: BTreeMap<CredentialId, CredentialView>,
    /// Each list ordered by report time, then report id.
    pub signals: SignalStore,
    pub replica_names: BTreeMap<ReplicaId, String>,
    pub left: BTreeMap<ReplicaId, bool>,
    pub replica_keys: BTreeMap<ReplicaId, ReplicaKeys>,
    pub removed: BTreeMap<ReplicaId, Removal>,
    pub recovery: BTreeMap<String, RecoveryRecipient>,
    conflicts: Vec<Conflict>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct FolderView {
    pub id: FolderId,
    pub title: String,
    pub position: Option<u32>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ItemView {
    pub id: ItemId,
    /// Empty if the register holds no value.
    pub title: String,
    pub category: Option<String>,
    /// Key register value. Empty if the register holds no value.
    pub key: String,
    /// `None` if the register names a missing folder.
    pub folder: Option<FolderId>,
    /// In list order.
    pub sections: Vec<SectionView>,
    /// In list order.
    pub websites: Vec<WebsiteView>,
    /// Role slots. A slot that names a missing or trashed credential, or a
    /// credential of another item, is `None`.
    pub username: Option<CredentialId>,
    pub password: Option<CredentialId>,
    pub totp: Option<CredentialId>,
    pub trashed: Option<TrashValue>,
    /// Live and trashed credentials of the item. Default section first, then
    /// each section in list order. List order within each section.
    pub credentials: Vec<CredentialId>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SectionView {
    pub id: SectionId,
    pub title: String,
    pub position: Option<u32>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct WebsiteView {
    pub url: String,
    pub match_kind: MatchKind,
    pub position: u32,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct CredentialView {
    pub id: CredentialId,
    /// `None` if the register holds no value.
    pub item: Option<ItemId>,
    /// Empty if the register holds no value.
    pub title: String,
    pub kind: FieldKind,
    /// Key register value. Empty if the register holds no value.
    pub key: String,
    /// `None` for the default section, and for a placement in a section the
    /// item lacks.
    pub section: Option<SectionId>,
    pub position: Option<u32>,
    /// Empty if the register holds no value.
    pub value: SecretText,
    /// Ordered by `replaced_at`, then entry id.
    pub history: Vec<HistoryView>,
    /// Latest time across replicas.
    pub last_used_day_at: Option<i64>,
    pub trashed: Option<TrashValue>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct HistoryView {
    pub id: HistoryId,
    pub value: SecretText,
    pub replaced_at: i64,
}

/// Ask register with more than one resolved value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Conflict {
    pub entity: Entity,
    pub register: AskRegister,
}

/// Entity that holds a register.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Entity {
    Vault,
    Item(ItemId),
    Credential(CredentialId),
}

/// Ask register of an entity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AskRegister {
    Name,
    Title,
    Category,
    Key,
    Username,
    Password,
    Totp,
    Kind,
    Value,
}

impl VaultView {
    /// View of `state`.
    pub fn of(state: &CausalState<SyncState>) -> Self {
        let SyncState {
            name,
            replica_names,
            replica_keys,
            removed,
            left,
            recovery,
            folders,
            signals,
            items,
            credentials,
        } = &state.store;
        let mut conflicts = Vec::new();

        let name = Asks::new(Entity::Vault, &mut conflicts).value(AskRegister::Name, name);

        let mut folder_views: Vec<FolderView> = folders
            .iter()
            .filter_map(|(id, register)| {
                let folder = register.shown()?;
                Some(FolderView {
                    id: *id,
                    title: folder.title.clone(),
                    position: folder.position,
                })
            })
            .collect();
        folder_views.sort_by(|a, b| {
            list_order(a.position, &a.title, a.id).cmp(&list_order(b.position, &b.title, b.id))
        });

        let mut signal_store = SignalStore::default();
        for (_, register) in signals.iter() {
            for (_, entry) in register.ordered() {
                signal_store.add_untrimmed(&entry.value);
            }
        }
        signal_store.sort_lists();

        let credential_views: BTreeMap<_, _> = credentials
            .iter()
            .filter(|(_, credential)| !credential.is_empty())
            .map(|(id, credential)| {
                let view = CredentialView::of(*id, credential, items, &mut conflicts);
                (*id, view)
            })
            .collect();

        let item_views = items
            .iter()
            .filter(|(_, item)| !item.is_empty())
            .map(|(id, item)| {
                let view = ItemView::of(*id, item, folders, &credential_views, &mut conflicts);
                (*id, view)
            })
            .collect();

        Self {
            name,
            folders: folder_views,
            items: item_views,
            credentials: credential_views,
            signals: signal_store,
            replica_names: shown_by_key(replica_names),
            left: shown_by_key(left),
            replica_keys: shown_by_key(replica_keys),
            removed: shown_by_key(removed),
            recovery: shown_by_key(recovery),
            conflicts,
        }
    }

    /// Ask registers with more than one resolved value.
    pub fn conflicts(&self) -> &[Conflict] {
        &self.conflicts
    }
}

impl ItemView {
    fn of(
        id: ItemId,
        item: &SyncItem,
        folders: &OrMap<FolderId, MvRegister<FolderValue, Order>>,
        credentials: &BTreeMap<CredentialId, CredentialView>,
        conflicts: &mut Vec<Conflict>,
    ) -> Self {
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
            trashed,
        } = item;
        let mut asks = Asks::new(Entity::Item(id), conflicts);

        let folder = folder
            .shown()
            .copied()
            .flatten()
            .filter(|f| folders.get(f).is_some_and(|r| r.shown().is_some()));

        let mut section_views: Vec<SectionView> = sections
            .iter()
            .filter_map(|(id, register)| {
                let section = register.shown()?;
                Some(SectionView {
                    id: *id,
                    title: section.title.clone(),
                    position: section.position,
                })
            })
            .collect();
        section_views.sort_by(|a, b| {
            list_order(a.position, &a.title, a.id).cmp(&list_order(b.position, &b.title, b.id))
        });

        let mut website_views: Vec<WebsiteView> = websites
            .iter()
            .filter_map(|(url, register)| {
                let website = register.shown()?;
                Some(WebsiteView {
                    url: url.clone(),
                    match_kind: website.match_kind,
                    position: website.position,
                })
            })
            .collect();
        website_views.sort_by(|a, b| (a.position, &a.url).cmp(&(b.position, &b.url)));

        // A slot reads as empty unless it names a live credential of this item.
        let resolve = |slot: &Option<CredentialId>| {
            slot.filter(|c| {
                credentials
                    .get(c)
                    .is_some_and(|view| view.item == Some(id) && view.trashed.is_none())
            })
        };
        let username = asks.resolved(AskRegister::Username, username, resolve);
        let password = asks.resolved(AskRegister::Password, password, resolve);
        let totp = asks
            .resolved(AskRegister::Totp, totp, resolve)
            .and_then(|(_, slot)| slot);

        // One credential in both slots. The slot whose shown value has the
        // lower order key reads as empty. The username slot reads as empty if
        // the order keys are equal.
        let (username, password) = match (username, password) {
            (Some((u_key, Some(u))), Some((p_key, Some(p)))) if u == p => {
                if u_key <= p_key {
                    (None, Some(p))
                } else {
                    (Some(u), None)
                }
            },
            (username, password) => (
                username.and_then(|(_, slot)| slot),
                password.and_then(|(_, slot)| slot),
            ),
        };

        let rank = |section: Option<SectionId>| {
            section
                .and_then(|s| section_views.iter().position(|v| v.id == s))
                .map_or(0, |index| index + 1)
        };
        let mut item_credentials: Vec<&CredentialView> = credentials
            .values()
            .filter(|c| c.item == Some(id))
            .collect();
        item_credentials.sort_by(|a, b| {
            (rank(a.section), list_order(a.position, &a.title, a.id))
                .cmp(&(rank(b.section), list_order(b.position, &b.title, b.id)))
        });
        let item_credentials = item_credentials.into_iter().map(|c| c.id).collect();

        Self {
            id,
            title: asks.value(AskRegister::Title, title),
            category: asks.value(AskRegister::Category, category),
            key: asks.value(AskRegister::Key, key),
            folder,
            sections: section_views,
            websites: website_views,
            username,
            password,
            totp,
            trashed: trashed.shown_trash(),
            credentials: item_credentials,
        }
    }
}

impl CredentialView {
    fn of(
        id: CredentialId,
        credential: &SyncCredential,
        items: &OrMap<ItemId, SyncItem>,
        conflicts: &mut Vec<Conflict>,
    ) -> Self {
        let SyncCredential {
            item,
            title,
            kind,
            key,
            placement,
            value,
            history,
            last_used_day_at,
            trashed,
        } = credential;
        let mut asks = Asks::new(Entity::Credential(id), conflicts);

        let item = item.shown().copied();
        let placement = placement.shown().cloned().unwrap_or_default();
        // A placement in a section the item lacks reads as the default section.
        let section = placement.section.filter(|s| {
            item.and_then(|i| items.get(&i))
                .and_then(|i| i.sections.get(s))
                .is_some_and(|r| r.shown().is_some())
        });

        let mut history_views: Vec<HistoryView> = history
            .iter()
            .filter_map(|(id, register)| {
                let entry = register.shown()?;
                Some(HistoryView {
                    id: *id,
                    value: entry.value.clone(),
                    replaced_at: entry.replaced_at,
                })
            })
            .collect();
        history_views.sort_by_key(|h| (h.replaced_at, h.id));

        let last_used_day_at = last_used_day_at
            .iter()
            .filter_map(|(_, register)| register.shown().copied())
            .max();

        Self {
            id,
            item,
            title: asks.value(AskRegister::Title, title),
            kind: asks.value(AskRegister::Kind, kind),
            key: asks.value(AskRegister::Key, key),
            section,
            position: placement.position,
            value: asks.value(AskRegister::Value, value),
            history: history_views,
            last_used_day_at,
            trashed: trashed.shown_trash(),
        }
    }
}

/// Shown values of the Ask registers of one entity, with their conflicts.
struct Asks<'a> {
    entity: Entity,
    conflicts: &'a mut Vec<Conflict>,
}

impl<'a> Asks<'a> {
    fn new(entity: Entity, conflicts: &'a mut Vec<Conflict>) -> Self {
        Self { entity, conflicts }
    }

    /// Resolved value with the highest order key, and its order key. Records
    /// a conflict if the register holds more than one resolved value.
    fn resolved<T, R: PartialEq>(
        &mut self,
        register: AskRegister,
        values: &MvRegister<T, Ask>,
        resolve: impl Fn(&T) -> R,
    ) -> Option<(OrderKey, R)> {
        let mut resolved: Vec<(OrderKey, R)> = values
            .ordered()
            .into_iter()
            .map(|(key, v)| (key, resolve(&v.value)))
            .collect();
        let shown = resolved.pop()?;
        if resolved.iter().any(|(_, value)| *value != shown.1) {
            self.conflicts.push(Conflict {
                entity: self.entity,
                register,
            });
        }
        Some(shown)
    }

    /// Value with the highest order key, or the default if the register holds
    /// no value. Records a conflict if the register holds more than one
    /// value.
    fn value<T: Clone + Default + PartialEq>(
        &mut self,
        register: AskRegister,
        values: &MvRegister<T, Ask>,
    ) -> T {
        self.resolved(register, values, T::clone)
            .map(|(_, value)| value)
            .unwrap_or_default()
    }
}

impl<T, P: Policy> MvRegister<T, P> {
    /// Value with the highest order key.
    fn shown(&self) -> Option<&T> {
        self.ordered().pop().map(|(_, v)| &v.value)
    }
}

impl MvRegister<Option<TrashValue>, Trash> {
    /// Trashed if any value is `Some`, with the value of the latest
    /// `deleted_at`. The order key breaks a tie.
    fn shown_trash(&self) -> Option<TrashValue> {
        self.ordered()
            .into_iter()
            .filter_map(|(key, v)| Some((v.value.as_ref()?, key)))
            .max_by_key(|(trash, key)| (trash.deleted_at, *key))
            .map(|(trash, _)| trash.clone())
    }
}

/// Value with the highest order key of each entry of `map`.
fn shown_by_key<K: Ord + Clone, T: Clone + PartialEq, P: Policy>(
    map: &OrMap<K, MvRegister<T, P>>,
) -> BTreeMap<K, T> {
    map.iter()
        .filter_map(|(key, register)| Some((key.clone(), register.shown()?.clone())))
        .collect()
}

/// Sort key of folders, sections, and the credentials of one section.
/// Position, with no position last, then title, then id.
fn list_order(position: Option<u32>, title: &str, id: Uuid) -> ((u32, &str), Uuid) {
    (display_order(position, title), id)
}
