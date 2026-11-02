//! Observed-remove map.

use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use super::CausalStore;
use super::context::CausalContext;
use super::ids::WriteId;

/// Observed-remove map. A remove does not delete a concurrent write inside the
/// entry.
///
/// Entry write ids are the write ids of the values inside the entry. They are
/// not stored.
///
/// Remove of an entry with a concurrent write. The entry is kept with the
/// write.
///
/// ```text
/// a = b = { "a.com": [w1] }
/// a.remove("a.com")        // a = { }
/// b["a.com"].write(w2)     // b = { "a.com": [w2] }, a has not seen w2
/// a.join(b)                // a = { "a.com": [w2] }
/// ```
///
/// Remove of an entry with no concurrent write. The entry is removed.
///
/// ```text
/// a = b = { "a.com": [w1] }
/// a.remove("a.com")        // a = { }, a has seen w1
/// a.join(b)                // a = { }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrMap<K, V: CausalStore> {
    entries: BTreeMap<K, V>,
}

impl<K: Ord, V: CausalStore> OrMap<K, V> {
    /// Entry at `key`.
    pub fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key)
    }

    /// Entry at `key`, created empty if missing. An entry left empty is
    /// dropped by the next join.
    pub fn entry(&mut self, key: K) -> &mut V {
        self.entries.entry(key).or_default()
    }

    /// Remove the entry at `key`. A join with a state that holds a write in
    /// the entry not seen here brings the entry back.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.entries.remove(key)
    }

    /// Entries in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.entries.iter()
    }
}

impl<K: Ord, V: CausalStore> CausalStore for OrMap<K, V> {
    fn is_empty(&self) -> bool {
        self.entries.values().all(V::is_empty)
    }

    fn each_value(&self, f: &mut dyn FnMut(WriteId, u64)) {
        for value in self.entries.values() {
            value.each_value(f);
        }
    }

    /// Compare the entries at each key that both maps hold.
    fn find_duplicate_write_id(&self, other: &Self) -> Option<WriteId> {
        self.entries.iter().find_map(|(key, value)| {
            let other_value = other.entries.get(key)?;
            value.find_duplicate_write_id(other_value)
        })
    }

    /// Join each key of either side, with an empty entry for a missing side.
    /// Drop each entry that is empty after the join.
    fn join(&mut self, ctx: &CausalContext, other: Self, other_ctx: &CausalContext) {
        let mut other_entries = other.entries;
        self.entries.retain(|key, value| {
            let other_value = other_entries.remove(key).unwrap_or_default();
            value.join(ctx, other_value, other_ctx);
            !value.is_empty()
        });
        for (key, other_value) in other_entries {
            let mut value = V::default();
            value.join(ctx, other_value, other_ctx);
            if !value.is_empty() {
                self.entries.insert(key, value);
            }
        }
    }
}

impl<K, V: CausalStore> Default for OrMap<K, V> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }
}

/// Serde form: a map of key to entry.
impl<K: Serialize, V: CausalStore + Serialize> Serialize for OrMap<K, V> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(&self.entries)
    }
}

/// A key listed twice fails.
impl<'de, K, V> Deserialize<'de> for OrMap<K, V>
where
    K: Ord + Deserialize<'de>,
    V: CausalStore + Deserialize<'de>,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let entries = UniqueMap::deserialize(deserializer)?;
        Ok(Self { entries })
    }
}

/// Serde form of a map that refuses a repeated key. A map deserialized as a
/// `BTreeMap` takes the last value of a repeated key.
pub(super) struct UniqueMap;

impl UniqueMap {
    pub(super) fn deserialize<'de, D, K, V>(deserializer: D) -> Result<BTreeMap<K, V>, D::Error>
    where
        D: Deserializer<'de>,
        K: Ord + Deserialize<'de>,
        V: Deserialize<'de>,
    {
        deserializer.deserialize_map(UniqueMapVisitor(PhantomData))
    }
}

/// Visitor of [`UniqueMap`].
struct UniqueMapVisitor<K, V>(PhantomData<fn() -> (K, V)>);

impl<'de, K, V> de::Visitor<'de> for UniqueMapVisitor<K, V>
where
    K: Ord + Deserialize<'de>,
    V: Deserialize<'de>,
{
    type Value = BTreeMap<K, V>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a map with unique keys")
    }

    fn visit_map<A: de::MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut map = BTreeMap::new();
        while let Some((key, value)) = access.next_entry()? {
            if map.insert(key, value).is_some() {
                return Err(de::Error::custom("map holds a key twice"));
            }
        }
        Ok(map)
    }
}
