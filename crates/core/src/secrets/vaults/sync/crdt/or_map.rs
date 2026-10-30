//! Observed-remove map.

use std::collections::BTreeMap;

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
