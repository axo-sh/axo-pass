use uuid::Uuid;

use super::*;

mod checks;
mod failures;
mod histories;
mod join;
mod minting;
mod properties;
mod publish;
mod simulator;

/// Test store shaped like `SyncItem`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Item {
    title: MvRegister<&'static str, Ask>,
    folder: MvRegister<Option<u32>, Order>,
    websites: OrMap<&'static str, MvRegister<u32, Order>>,
    trashed: MvRegister<Option<i64>, Trash>,
    history: OrMap<u32, MvRegister<&'static str, Order>>,
}

impl CausalStore for Item {
    fn is_empty(&self) -> bool {
        self.title.is_empty()
            && self.folder.is_empty()
            && self.websites.is_empty()
            && self.trashed.is_empty()
            && self.history.is_empty()
    }

    fn each_value(&self, f: &mut dyn FnMut(WriteId, u64)) {
        self.title.each_value(f);
        self.folder.each_value(f);
        self.websites.each_value(f);
        self.trashed.each_value(f);
        self.history.each_value(f);
    }

    fn find_duplicate_write_id(&self, other: &Self) -> Option<WriteId> {
        self.title
            .find_duplicate_write_id(&other.title)
            .or_else(|| self.folder.find_duplicate_write_id(&other.folder))
            .or_else(|| self.websites.find_duplicate_write_id(&other.websites))
            .or_else(|| self.trashed.find_duplicate_write_id(&other.trashed))
            .or_else(|| self.history.find_duplicate_write_id(&other.history))
    }

    fn join(&mut self, ctx: &CausalContext, other: Self, other_ctx: &CausalContext) {
        self.title.join(ctx, other.title, other_ctx);
        self.folder.join(ctx, other.folder, other_ctx);
        self.websites.join(ctx, other.websites, other_ctx);
        self.trashed.join(ctx, other.trashed, other_ctx);
        self.history.join(ctx, other.history, other_ctx);
    }
}

/// Test store shaped like `SyncState`, without the context and actors.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Vault {
    name: MvRegister<&'static str, Ask>,
    items: OrMap<u32, Item>,
    signals: OrMap<u32, MvRegister<i64, Merge>>,
}

impl CausalStore for Vault {
    fn is_empty(&self) -> bool {
        self.name.is_empty() && self.items.is_empty() && self.signals.is_empty()
    }

    fn each_value(&self, f: &mut dyn FnMut(WriteId, u64)) {
        self.name.each_value(f);
        self.items.each_value(f);
        self.signals.each_value(f);
    }

    fn find_duplicate_write_id(&self, other: &Self) -> Option<WriteId> {
        self.name
            .find_duplicate_write_id(&other.name)
            .or_else(|| self.items.find_duplicate_write_id(&other.items))
            .or_else(|| self.signals.find_duplicate_write_id(&other.signals))
    }

    fn join(&mut self, ctx: &CausalContext, other: Self, other_ctx: &CausalContext) {
        self.name.join(ctx, other.name, other_ctx);
        self.items.join(ctx, other.items, other_ctx);
        self.signals.join(ctx, other.signals, other_ctx);
    }
}

type State = CausalState<Vault>;

/// Time of every mint in the tests, except the mints of a replica whose clock
/// is behind.
const NOW: i64 = 1_000;

/// Session of replica `n` with seeded actor ids. Actor `k` of replica `n` is
/// `n << 64 | k`, with `k` from 1.
fn session(n: u128) -> Session {
    let mut next = n << 64;
    Session::with_actor_ids(ReplicaId(Uuid::from_u128(n)), move || {
        next += 1;
        Uuid::from_u128(next)
    })
}

fn actor(n: u128, k: u128) -> ActorId {
    ActorId(Uuid::from_u128(n << 64 | k))
}

fn joined(left: &State, right: &State) -> State {
    let mut state = left.clone();
    state.join(right.clone());
    state
}

/// Register values in write id order.
fn values<T: Copy, P: Policy>(register: &MvRegister<T, P>) -> Vec<T> {
    register.values().map(|(_, v)| v.value).collect()
}

fn write_ids(store: &impl CausalStore) -> Vec<WriteId> {
    let mut ids = Vec::new();
    store.each_value(&mut |id, _| ids.push(id));
    ids
}

/// Order keys of every value in `store`.
fn order_keys(store: &impl CausalStore) -> Vec<OrderKey> {
    let mut keys = Vec::new();
    store.each_value(&mut |write_id, counter| keys.push(OrderKey { counter, write_id }));
    keys
}
