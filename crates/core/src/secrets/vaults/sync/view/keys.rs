//! Shown keys of items and credentials.
//!
//! Each shown key passes `validate_key`, and no two live entries of one group
//! show one key. A group is the items of the vault with trashed items left
//! out, or the credentials of one item with trashed credentials left out,
//! whatever the trash state of the item. The `key` registers keep the values
//! as written.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;
use uuid::Uuid;

use super::{Entity, VaultView};
use crate::secrets::vaults::storage::handle::normalized_key;
use crate::secrets::vaults::sync::crdt::OrderKey;
use crate::secrets::vaults::sync::model::ItemId;

/// Key prefix of an item with no valid key.
pub const ITEM_KEY_PREFIX: &str = "item";
/// Key prefix of a credential with no valid key.
pub const CREDENTIAL_KEY_PREFIX: &str = "field";

/// Suffix lengths, in base32 characters, tried in order.
const SUFFIX_LENGTHS: [usize; 3] = [4, 6, 8];

/// Key register value the view chose, with its order key.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct StoredKey {
    pub(super) order: OrderKey,
    pub(super) value: String,
}

impl StoredKey {
    /// Normalized value, or `None` if it fails `validate_key` after
    /// normalizing.
    fn normalized(&self) -> Option<String> {
        normalized_key(&self.value)
    }
}

/// Entries whose keys must differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyGroup {
    /// Live items of the vault.
    Items,
    /// Live credentials of one item.
    Credentials(ItemId),
}

/// Key refused by [`VaultView::check_key`].
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("key {key} is stored by {entries:?}")]
pub struct KeyTaken {
    /// Normalized key.
    pub key: String,
    /// Live entries of the group that store the key, in order key order.
    pub entries: Vec<Entity>,
}

impl VaultView {
    /// Check the key of a rename of `entry`, or of a new entry, in `group`.
    ///
    /// Refuses `key` if it equals the stored key of another live entry of the
    /// group, including an entry shown with a suffix. Stored keys and `key`
    /// are compared normalized.
    pub fn check_key(&self, group: KeyGroup, entry: Uuid, key: &str) -> Result<(), KeyTaken> {
        let key = normalized_key(key).unwrap_or_else(|| key.to_string());
        let stores = |stored: &Option<StoredKey>| {
            stored
                .as_ref()
                .is_some_and(|s| s.value == key || s.normalized().as_ref() == Some(&key))
        };
        let mut holders: Vec<(OrderKey, Entity)> = match group {
            KeyGroup::Items => self
                .items
                .values()
                .filter(|i| i.id != entry && i.trashed.is_none() && stores(&i.stored_key))
                .filter_map(|i| Some((i.stored_key.as_ref()?.order, Entity::Item(i.id))))
                .collect(),
            KeyGroup::Credentials(item) => self
                .credentials
                .values()
                .filter(|c| c.item == item && c.id != entry && c.trashed.is_none())
                .filter(|c| stores(&c.stored_key))
                .filter_map(|c| Some((c.stored_key.as_ref()?.order, Entity::Credential(c.id))))
                .collect(),
        };
        if holders.is_empty() {
            return Ok(());
        }
        holders.sort();
        Err(KeyTaken {
            key,
            entries: holders.into_iter().map(|(_, entity)| entity).collect(),
        })
    }

    /// Entries whose stored key fails `validate_key` after normalizing, live
    /// and trashed. Each is shown with a suffixed key.
    pub fn key_notices(&self) -> Vec<Entity> {
        let items = self
            .items
            .values()
            .filter(|i| i.key_notice)
            .map(|i| Entity::Item(i.id));
        let credentials = self
            .credentials
            .values()
            .filter(|c| c.key_notice)
            .map(|c| Entity::Credential(c.id));
        items.chain(credentials).collect()
    }

    /// Set the shown key and the key notice of every item and credential from
    /// the stored keys.
    pub(super) fn assign_keys(&mut self) {
        let mut items = KeyClaims::new(ITEM_KEY_PREFIX);
        for item in self.items.values().filter(|i| i.trashed.is_none()) {
            items.add(item.id, item.stored_key.as_ref());
        }
        let items = items.shown();

        let mut credentials: BTreeMap<ItemId, KeyClaims> = BTreeMap::new();
        for credential in self.credentials.values().filter(|c| c.trashed.is_none()) {
            credentials
                .entry(credential.item)
                .or_insert_with(|| KeyClaims::new(CREDENTIAL_KEY_PREFIX))
                .add(credential.id, credential.stored_key.as_ref());
        }
        let credentials: BTreeMap<Uuid, String> = credentials
            .into_values()
            .flat_map(|claims| claims.shown())
            .collect();

        for item in self.items.values_mut() {
            item.key_notice = KeyClaims::needs_notice(item.stored_key.as_ref());
            item.key = match items.get(&item.id) {
                Some(key) => key.clone(),
                None => KeyClaims::alone(ITEM_KEY_PREFIX, item.id, item.stored_key.as_ref()),
            };
        }
        for credential in self.credentials.values_mut() {
            credential.key_notice = KeyClaims::needs_notice(credential.stored_key.as_ref());
            credential.key = match credentials.get(&credential.id) {
                Some(key) => key.clone(),
                None => KeyClaims::alone(
                    CREDENTIAL_KEY_PREFIX,
                    credential.id,
                    credential.stored_key.as_ref(),
                ),
            };
        }
    }
}

/// Stored keys of the live entries of one group.
struct KeyClaims<'a> {
    /// Prefix of an entry with no valid key.
    prefix: &'static str,
    entries: Vec<(Uuid, Option<&'a StoredKey>)>,
}

impl<'a> KeyClaims<'a> {
    fn new(prefix: &'static str) -> Self {
        Self {
            prefix,
            entries: Vec::new(),
        }
    }

    fn add(&mut self, id: Uuid, stored: Option<&'a StoredKey>) {
        self.entries.push((id, stored));
    }

    /// Whether `stored` is marked for a key notice.
    fn needs_notice(stored: Option<&StoredKey>) -> bool {
        stored.is_some_and(|s| s.normalized().is_none())
    }

    /// Shown key of an entry outside every group. The normalized stored key,
    /// or the prefix with a 4 character suffix.
    fn alone(prefix: &str, id: Uuid, stored: Option<&StoredKey>) -> String {
        stored
            .and_then(StoredKey::normalized)
            .unwrap_or_else(|| Suffix::key(prefix, id, SUFFIX_LENGTHS[0]))
    }

    /// Shown key of each entry.
    ///
    /// Entries are grouped by normalized stored key. In each group, the entry
    /// with the lowest order key, then the lowest id, is shown with the bare
    /// key. Every other entry, and every entry with no valid key, is shown
    /// with a suffix, in order key order.
    fn shown(&self) -> BTreeMap<Uuid, String> {
        let mut taken: BTreeSet<String> = BTreeSet::new();
        let mut by_key: BTreeMap<String, Vec<(OrderKey, Uuid)>> = BTreeMap::new();
        let mut suffixed: Vec<(Option<OrderKey>, Uuid, String)> = Vec::new();
        for (id, stored) in &self.entries {
            let Some(stored) = stored else {
                suffixed.push((None, *id, self.prefix.to_string()));
                continue;
            };
            taken.insert(stored.value.clone());
            match stored.normalized() {
                Some(key) => {
                    taken.insert(key.clone());
                    by_key.entry(key).or_default().push((stored.order, *id));
                },
                None => suffixed.push((Some(stored.order), *id, self.prefix.to_string())),
            }
        }

        let mut shown = BTreeMap::new();
        for (key, mut claims) in by_key {
            claims.sort();
            let mut claims = claims.into_iter();
            if let Some((_, id)) = claims.next() {
                shown.insert(id, key.clone());
            }
            suffixed.extend(claims.map(|(order, id)| (Some(order), id, key.clone())));
        }

        suffixed.sort();
        for (_, id, base) in suffixed {
            let key = Suffix::free_key(&base, id, &taken);
            taken.insert(key.clone());
            shown.insert(id, key);
        }
        shown
    }
}

/// Id suffix of a shown key.
pub struct Suffix;

impl Suffix {
    /// Lowercase RFC 4648 base32 alphabet.
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

    /// Lowercase RFC 4648 base32 of `bytes`, without padding.
    pub fn base32(bytes: &[u8]) -> String {
        let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
        let mut buffer: u32 = 0;
        let mut bits = 0;
        for byte in bytes {
            buffer = (buffer << 8) | u32::from(*byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(char::from(Self::ALPHABET[((buffer >> bits) & 31) as usize]));
            }
            buffer &= (1 << bits) - 1;
        }
        if bits > 0 {
            out.push(char::from(
                Self::ALPHABET[((buffer << (5 - bits)) & 31) as usize],
            ));
        }
        out
    }

    /// `{base}-{suffix}` with the first `length` characters of the base32 of
    /// `id`.
    pub fn key(base: &str, id: Uuid, length: usize) -> String {
        let suffix = Self::base32(id.as_bytes());
        format!("{base}-{}", &suffix[..length])
    }

    /// First suffixed key of `id` that is not in `taken`, with a suffix of 4,
    /// 6, or 8 characters.
    ///
    /// If all three are taken, which needs ids that share 40 bits or a forged
    /// stored key, the full 26 character suffix is used, followed by a counter
    /// if that is taken too.
    fn free_key(base: &str, id: Uuid, taken: &BTreeSet<String>) -> String {
        let full = Self::base32(id.as_bytes());
        SUFFIX_LENGTHS
            .iter()
            .map(|length| Self::key(base, id, *length))
            .chain([format!("{base}-{full}")])
            .chain((2u64..).map(|n| format!("{base}-{full}-{n}")))
            .find(|key| !taken.contains(key))
            .unwrap_or_default()
    }
}
