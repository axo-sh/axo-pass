use uuid::Uuid;

use super::*;

mod checks;
mod histories;
mod properties;
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

#[test]
fn value_whose_write_id_is_in_both_sides_is_kept() {
    let (mut a, mut b) = (session(1), session(2));
    let mut left = State::default();
    let m = a.mint(&mut left, NOW);
    left.store.name.write(&m, "Work");
    let mut right = left.clone();
    let m = b.mint(&mut right, NOW);
    right.store.items.entry(1).title.write(&m, "Mail");

    let state = joined(&left, &right);

    assert_eq!(values(&state.store.name), ["Work"]);
    assert_eq!(state, joined(&right, &left));
}

#[test]
fn value_not_covered_by_other_context_is_kept() {
    let (mut a, mut b) = (session(1), session(2));
    let mut left = State::default();
    let m = a.mint(&mut left, NOW);
    left.store.name.write(&m, "Work");
    let mut right = State::default();
    let m = b.mint(&mut right, NOW);
    right.store.items.entry(1).title.write(&m, "Mail");

    let state = joined(&left, &right);

    assert_eq!(values(&state.store.name), ["Work"]);
    assert_eq!(values(&state.store.items.get(&1).unwrap().title), ["Mail"]);
    assert_eq!(state, joined(&right, &left));
}

#[test]
fn value_covered_by_other_context_is_dropped() {
    let (mut a, mut b) = (session(1), session(2));
    let mut left = State::default();
    let m = a.mint(&mut left, NOW);
    left.store.name.write(&m, "Work");
    let mut right = left.clone();
    let m = b.mint(&mut right, NOW);
    right.store.name.write(&m, "Home");

    let state = joined(&left, &right);

    assert_eq!(values(&state.store.name), ["Home"]);
    assert_eq!(state, joined(&right, &left));
}

#[test]
fn write_concurrent_with_remove_of_its_entry_is_kept() {
    let (mut a, mut b) = (session(1), session(2));
    let mut base = State::default();
    let m = a.mint(&mut base, NOW);
    base.store
        .items
        .entry(1)
        .websites
        .entry("a.com")
        .write(&m, 0);
    let mut left = base.clone();
    let m = a.mint(&mut left, NOW);
    left.store
        .items
        .entry(1)
        .websites
        .entry("a.com")
        .write(&m, 1);
    let mut right = base.clone();
    b.mint(&mut right, NOW);
    right.store.items.entry(1).websites.remove(&"a.com");

    let state = joined(&left, &right);

    let websites = &state.store.items.get(&1).unwrap().websites;
    assert_eq!(values(websites.get(&"a.com").unwrap()), [1]);
    assert_eq!(state, joined(&right, &left));
}

#[test]
fn remove_after_seeing_every_write_id_drops_entry() {
    let (mut a, mut b) = (session(1), session(2));
    let mut left = State::default();
    let m = a.mint(&mut left, NOW);
    let item = left.store.items.entry(1);
    item.title.write(&m, "Mail");
    item.websites.entry("a.com").write(&m, 0);
    item.websites.entry("b.com").write(&m, 1);
    let mut right = left.clone();
    b.mint(&mut right, NOW);
    right.store.items.entry(1).websites.remove(&"a.com");

    let state = joined(&left, &right);

    let websites = &state.store.items.get(&1).unwrap().websites;
    assert!(websites.get(&"a.com").is_none());
    assert_eq!(values(websites.get(&"b.com").unwrap()), [1]);
    assert_eq!(state, joined(&right, &left));
}

#[test]
fn entry_empty_after_join_is_absent() {
    let (mut a, mut b) = (session(1), session(2));
    let mut left = State::default();
    let m = a.mint(&mut left, NOW);
    let item = left.store.items.entry(1);
    item.title.write(&m, "Mail");
    item.websites.entry("a.com").write(&m, 0);
    let mut right = left.clone();
    b.mint(&mut right, NOW);
    right.store.items.remove(&1);
    // Entry with no value, as left by an entry lookup with no write.
    left.store.items.entry(2);

    let state = joined(&left, &right);

    assert!(state.store.items.get(&1).is_none());
    assert!(state.store.items.get(&2).is_none());
    assert_eq!(state.store.items.iter().count(), 0);
    assert_eq!(state, joined(&right, &left));
}

#[test]
fn nested_store_joins_per_field() {
    let (mut a, mut b) = (session(1), session(2));
    let mut base = State::default();
    let m = a.mint(&mut base, NOW);
    let item = base.store.items.entry(1);
    item.title.write(&m, "Mail");
    item.folder.write(&m, None);
    let mut left = base.clone();
    let m = a.mint(&mut left, NOW);
    left.store.items.entry(1).title.write(&m, "Email");
    let mut right = base.clone();
    let m = b.mint(&mut right, NOW);
    let item = right.store.items.entry(1);
    item.title.write(&m, "Post");
    item.folder.write(&m, Some(3));
    item.websites.entry("b.com").write(&m, 0);

    let state = joined(&left, &right);

    let item = state.store.items.get(&1).unwrap();
    assert_eq!(values(&item.title), ["Email", "Post"]);
    assert_eq!(values(&item.folder), [Some(3)]);
    assert_eq!(values(item.websites.get(&"b.com").unwrap()), [0]);
    assert!(item.trashed.is_empty());
    assert_eq!(state, joined(&right, &left));
}

#[test]
fn removal_only_write_id_advances_context_and_join_applies_removal() {
    let (mut a, mut b) = (session(1), session(2));
    let mut left = State::default();
    let m = a.mint(&mut left, NOW);
    left.store
        .items
        .entry(1)
        .websites
        .entry("a.com")
        .write(&m, 0);
    let mut right = left.clone();
    let m = b.mint(&mut right, NOW);
    right.store.items.entry(1).websites.remove(&"a.com");

    assert!(!left.context.covers(m.write_id));
    assert!(right.context.covers(m.write_id));
    assert!(!write_ids(&right.store).contains(&m.write_id));

    left.join(right);

    assert!(left.store.items.get(&1).is_none());
    assert!(left.context.covers(m.write_id));
}

#[test]
fn actors_are_union_of_both_sides() {
    let (mut a, mut b) = (session(1), session(2));
    let mut left = State::default();
    let m = a.mint(&mut left, NOW);
    left.store.name.write(&m, "Work");
    let mut right = State::default();
    let m = b.mint(&mut right, NOW);
    right.store.name.write(&m, "Home");

    let state = joined(&left, &right);

    let mut expected = left.actors.clone();
    expected.extend(right.actors.clone());
    assert_eq!(expected.len(), 2);
    assert_eq!(state.actors, expected);
    assert_eq!(state, joined(&right, &left));
}

#[test]
fn write_replaces_every_value_of_register() {
    let (mut a, mut b) = (session(1), session(2));
    let mut left = State::default();
    let m = a.mint(&mut left, NOW);
    left.store.name.write(&m, "Work");
    let mut right = State::default();
    let m = b.mint(&mut right, NOW);
    right.store.name.write(&m, "Home");
    left.join(right);
    assert_eq!(left.store.name.values().count(), 2);

    let m = a.mint(&mut left, NOW);
    left.store.name.write(&m, "Office");

    assert_eq!(values(&left.store.name), ["Office"]);
    let written = left.store.name.get(m.write_id).unwrap();
    assert_eq!(
        (written.counter, written.written_at),
        (m.counter, m.written_at)
    );
}

#[test]
fn each_value_visits_every_value_of_nested_store() {
    let (mut a, mut b) = (session(1), session(2));
    let mut state = State::default();
    let m1 = a.mint(&mut state, NOW);
    state.store.name.write(&m1, "Work");
    let m2 = b.mint(&mut state, NOW);
    let item = state.store.items.entry(1);
    item.title.write(&m2, "Mail");
    item.websites.entry("a.com").write(&m2, 0);

    let mut seen = Vec::new();
    state
        .store
        .each_value(&mut |id, counter| seen.push((id, counter)));

    let expected = [
        (m1.write_id, m1.counter),
        (m2.write_id, m2.counter),
        (m2.write_id, m2.counter),
    ];
    assert_eq!(seen, expected);
}

/// States from one shared history of three replicas, with concurrent edits,
/// removes, and joins.
fn history() -> Vec<State> {
    let (mut a, mut b, mut c) = (session(1), session(2), session(3));

    let mut base = State::default();
    let m = a.mint(&mut base, NOW);
    base.store.name.write(&m, "Work");
    let item = base.store.items.entry(1);
    item.title.write(&m, "Mail");
    item.websites.entry("a.com").write(&m, 0);

    // b renames item 1 and adds item 2.
    let mut renamed = base.clone();
    let m = b.mint(&mut renamed, NOW);
    renamed.store.items.entry(1).title.write(&m, "Email");
    renamed.store.items.entry(2).title.write(&m, "Bank");

    // c removes the website and renames item 1, concurrent with b.
    let mut removed = base.clone();
    let m = c.mint(&mut removed, NOW);
    let item = removed.store.items.entry(1);
    item.websites.remove(&"a.com");
    item.title.write(&m, "Post");

    // a joins b, removes item 2, and trashes item 1, concurrent with c.
    let mut trashed = joined(&base, &renamed);
    let m = a.mint(&mut trashed, NOW);
    trashed.store.items.remove(&2);
    trashed.store.items.entry(1).trashed.write(&m, Some(1_000));

    // c joins a and adds a website.
    let mut added = joined(&removed, &trashed);
    let m = c.mint(&mut added, NOW);
    added
        .store
        .items
        .entry(1)
        .websites
        .entry("c.com")
        .write(&m, 1);

    vec![State::default(), base, renamed, removed, trashed, added]
}

#[test]
fn join_is_commutative_on_fixed_states() {
    let states = history();
    for x in &states {
        for y in &states {
            assert_eq!(joined(x, y), joined(y, x));
        }
    }
}

#[test]
fn join_is_associative_on_fixed_states() {
    let states = history();
    for x in &states {
        for y in &states {
            for z in &states {
                assert_eq!(joined(&joined(x, y), z), joined(x, &joined(y, z)));
            }
        }
    }
}

#[test]
fn join_is_idempotent_on_fixed_states() {
    for x in &history() {
        assert_eq!(&joined(x, x), x);
    }
}

/// Order keys of every value in `store`.
fn order_keys(store: &impl CausalStore) -> Vec<OrderKey> {
    let mut keys = Vec::new();
    store.each_value(&mut |write_id, counter| keys.push(OrderKey { counter, write_id }));
    keys
}

/// Values of `register` in order of their order keys.
fn ordered<T: Copy, P: Policy>(register: &MvRegister<T, P>) -> Vec<(u64, T)> {
    register
        .ordered()
        .into_iter()
        .map(|(key, v)| (key.counter, v.value))
        .collect()
}

#[test]
fn session_that_mints_nothing_adds_no_actor() {
    let (mut a, b) = (session(1), session(2));
    let mut peer = State::default();
    let m = a.mint(&mut peer, NOW);
    peer.store.name.write(&m, "Work");
    let mut state = State::default();

    state.join(peer);

    assert_eq!(b.actor(), None);
    let actors: Vec<_> = state.actors.keys().copied().collect();
    assert_eq!(actors, [actor(1, 1)]);
}

#[test]
fn first_mint_creates_actor_and_later_mints_continue_it() {
    let mut a = session(1);
    let mut state = State::default();

    let m1 = a.mint(&mut state, NOW);
    let m2 = a.mint(&mut state, NOW + 5);

    let first = WriteId {
        actor: actor(1, 1),
        seq: 1,
    };
    assert_eq!(m1.write_id, first);
    assert_eq!(m2.write_id, WriteId { seq: 2, ..first });
    assert_eq!(a.last_write(), Some(m2.write_id));
    assert_eq!(state.context.get(actor(1, 1)), 2);
    let info = ActorInfo {
        replica: a.replica,
        started_at: NOW,
    };
    assert_eq!(state.actors.len(), 1);
    assert_eq!(state.actors[&actor(1, 1)], info);
}

#[test]
fn removal_only_transaction_mints_write_id_only_context_holds() {
    let mut a = session(1);
    let mut state = State::default();
    let m = a.mint(&mut state, NOW);
    state.store.items.entry(1).title.write(&m, "Mail");
    let before = state.context.clone();

    let m = a.mint(&mut state, NOW);
    state.store.items.remove(&1);

    assert!(!before.covers(m.write_id));
    assert!(state.context.covers(m.write_id));
    assert!(state.context.is_ahead_of(&before));
    assert!(write_ids(&state.store).is_empty());
}

#[test]
fn one_mint_is_written_into_every_changed_register() {
    let mut a = session(1);
    let mut state = State::default();

    let m = a.mint(&mut state, NOW);
    state.store.name.write(&m, "Work");
    let item = state.store.items.entry(1);
    item.title.write(&m, "Mail");
    item.folder.write(&m, Some(3));
    item.websites.entry("a.com").write(&m, 0);

    assert_eq!(order_keys(&state.store), [m.order_key(); 4]);
    assert_eq!(state.context.get(m.write_id.actor), 1);
}

#[test]
fn replaced_state_starts_new_actor_at_next_mint() {
    let mut a = session(1);
    let mut state = State::default();
    let m = a.mint(&mut state, NOW);
    state.store.name.write(&m, "Work");
    let backup = state.clone();
    let m = a.mint(&mut state, NOW);
    state.store.name.write(&m, "Home");

    // Backup lacks write 2 of the actor.
    let mut state = backup;
    let m = a.mint(&mut state, NOW + 10);

    let write_id = WriteId {
        actor: actor(1, 2),
        seq: 1,
    };
    assert_eq!(m.write_id, write_id);
    assert_eq!(a.actor(), Some(actor(1, 2)));
    assert_eq!(state.actors.len(), 2);
    assert_eq!(state.actors[&actor(1, 2)].started_at, NOW + 10);
}

#[test]
fn state_with_higher_context_entry_of_actor_starts_new_actor() {
    let mut a = session(1);
    let mut state = State::default();
    let m = a.mint(&mut state, NOW);
    state.store.name.write(&m, "Work");

    // Context entry above the session, as in a copied sync state.
    state.context.record(WriteId {
        actor: actor(1, 1),
        seq: 5,
    });
    let m = a.mint(&mut state, NOW);

    assert_eq!(m.write_id.actor, actor(1, 2));
    assert_eq!(m.write_id.seq, 1);
    assert_eq!(state.context.get(actor(1, 1)), 5);
}

#[test]
fn end_starts_new_actor_at_next_mint() {
    let mut a = session(1);
    let mut state = State::default();
    a.mint(&mut state, NOW);

    a.end();
    assert_eq!(a.actor(), None);
    let m = a.mint(&mut state, NOW);

    assert_eq!(m.write_id.actor, actor(1, 2));
    assert_eq!(m.write_id.seq, 1);
    assert_eq!(state.context.get(actor(1, 1)), 1);
}

#[test]
fn mint_counter_is_one_above_highest_and_at_least_2() {
    let (mut a, mut b) = (session(1), session(2));
    let mut state = State::default();

    let m = a.mint(&mut state, NOW);
    assert_eq!(m.counter, 2);
    state.store.name.write(&m, "Work");
    let m = b.mint(&mut state, NOW);
    assert_eq!(m.counter, 3);

    // Store with only a value at 1.
    let mut state = State::default();
    let m = a.mint(&mut state, NOW);
    state.store.name.write(&Mint { counter: 1, ..m }, "Old");
    let m = a.mint(&mut state, NOW);
    assert_eq!(m.counter, 2);
}

#[test]
fn write_after_join_orders_above_every_joined_value() {
    let (mut a, mut b) = (session(1), session(2));
    let mut left = State::default();
    for title in ["Mail", "Email", "Post"] {
        let m = a.mint(&mut left, NOW);
        left.store.items.entry(1).title.write(&m, title);
    }
    let mut right = State::default();
    for (key, title) in [(2, "Bank"), (3, "Shop"), (4, "Gym"), (5, "Car")] {
        let m = b.mint(&mut right, NOW);
        right.store.items.entry(key).title.write(&m, title);
    }
    left.join(right);
    let joined = order_keys(&left.store);

    let m = a.mint(&mut left, NOW);

    assert_eq!(joined.len(), 5);
    assert!(joined.iter().all(|key| *key < m.order_key()));
    assert!(m.counter < MAX_COUNTER);
}

#[test]
fn later_mints_saturate_at_max_counter() {
    let (mut a, mut b) = (session(1), session(2));
    let mut peer = State::default();
    let m = b.mint(&mut peer, NOW);
    let high = Mint {
        counter: MAX_COUNTER - 1,
        ..m
    };
    peer.store.name.write(&high, "Work");
    let mut state = State::default();
    state.join(peer);

    let m1 = a.mint(&mut state, NOW);
    state.store.name.write(&m1, "Home");
    let m2 = a.mint(&mut state, NOW);
    state.store.name.write(&m2, "Office");
    let m3 = a.mint(&mut state, NOW);

    assert_eq!([m1.counter, m2.counter, m3.counter], [MAX_COUNTER; 3]);
    assert!(m1.order_key() < m2.order_key());
    assert!(m2.order_key() < m3.order_key());
}

#[test]
fn mint_after_counter_above_max_counter_takes_max_counter() {
    let (mut a, mut b) = (session(1), session(2));
    let mut peer = State::default();
    let m = b.mint(&mut peer, NOW);
    let forged = Mint {
        counter: u64::MAX,
        ..m
    };
    peer.store.name.write(&forged, "Work");
    let mut state = State::default();
    state.join(peer);

    let m = a.mint(&mut state, NOW);

    assert_eq!(m.counter, MAX_COUNTER);
}

#[test]
fn concurrent_values_with_equal_counters_order_by_actor() {
    let (mut a, mut b) = (session(1), session(2));
    let mut left = State::default();
    let m = b.mint(&mut left, NOW);
    left.store.name.write(&m, "Home");
    let mut right = State::default();
    let m = a.mint(&mut right, NOW);
    right.store.name.write(&m, "Work");

    left.join(right);

    assert_eq!(ordered(&left.store.name), [(2, "Work"), (2, "Home")]);
}

#[test]
fn order_key_orders_by_counter_then_actor_then_seq() {
    let key = |counter, n, seq| OrderKey {
        counter,
        write_id: WriteId {
            actor: actor(n, 1),
            seq,
        },
    };
    let mut keys = vec![key(3, 1, 1), key(2, 2, 1), key(2, 1, 2), key(2, 1, 1)];

    keys.sort();

    let expected = [key(2, 1, 1), key(2, 1, 2), key(2, 2, 1), key(3, 1, 1)];
    assert_eq!(keys, expected);
}

#[test]
fn repair_value_orders_below_every_value_in_its_register() {
    let (mut a, mut b) = (session(1), session(2));
    let mut left = State::default();
    for name in ["Work", "Home", "Office"] {
        let m = a.mint(&mut left, NOW);
        left.store.name.write(&m, name);
    }
    let mut right = State::default();
    for name in ["Bank", "Shop", "Gym", "Car"] {
        let m = b.mint(&mut right, NOW);
        right.store.name.write(&m, name);
    }
    left.join(right);

    let m = a.mint(&mut left, NOW);
    left.store.name.write_repair(&m, "Old");

    let expected = [(3, "Old"), (4, "Office"), (5, "Car")];
    assert_eq!(ordered(&left.store.name), expected);
    assert_eq!(m.counter, 6);
}

#[test]
fn repair_value_counter_is_at_least_1() {
    let (mut a, mut b) = (session(1), session(2));
    let mut state = State::default();
    let m = a.mint(&mut state, NOW);
    state.store.name.write(&m, "Work");

    let m = b.mint(&mut state, NOW);
    state.store.name.write_repair(&m, "Old");
    let m = a.mint(&mut state, NOW);
    state.store.name.write_repair(&m, "Older");

    // Tied repair values are ordered by actor.
    let expected = [(1, "Older"), (1, "Old"), (2, "Work")];
    assert_eq!(ordered(&state.store.name), expected);
}

#[test]
fn repair_value_in_empty_register_takes_mint_counter() {
    let mut a = session(1);
    let mut state = State::default();
    let m = a.mint(&mut state, NOW);
    state.store.name.write(&m, "Work");

    let m = a.mint(&mut state, NOW);
    state.store.items.entry(1).title.write_repair(&m, "Mail");

    let title = &state.store.items.get(&1).unwrap().title;
    assert_eq!(ordered(title), [(3, "Mail")]);
    assert_eq!(m.counter, 3);
}

fn own_file(hash: &'static str, state: OwnFileState) -> OwnFile<&'static str> {
    OwnFile { hash, state }
}

#[test]
fn publishes_if_context_is_ahead_of_published_context() {
    let mut a = session(1);
    let mut state = State::default();
    a.mint(&mut state, NOW);
    let published = state.context.clone();
    let files = [own_file("h1", OwnFileState::Joined)];

    assert!(
        !state
            .context
            .should_publish(&published, Some(&"h1"), &files)
    );

    a.mint(&mut state, NOW);

    assert!(
        state
            .context
            .should_publish(&published, Some(&"h1"), &files)
    );
}

#[test]
fn republish_after_join_ends_once_contexts_are_equal() {
    let mut a = session(1);
    let mut left = State::default();
    let m = a.mint(&mut left, NOW);
    left.store.name.write(&m, "Work");
    let left_published = left.context.clone();
    let left_files = [own_file("a1", OwnFileState::Joined)];
    let mut right = State::default();
    let right_published = right.context.clone();
    let right_files = [own_file("b1", OwnFileState::Joined)];

    // Right joins a write it had not published, and publishes.
    right.join(left.clone());
    assert!(
        right
            .context
            .should_publish(&right_published, Some(&"b1"), &right_files)
    );

    // Left joins the republished state and finds its context covers it.
    left.join(right);
    assert!(
        !left
            .context
            .should_publish(&left_published, Some(&"a1"), &left_files)
    );
}

#[test]
fn publishes_if_last_published_file_is_missing() {
    let mut a = session(1);
    let mut state = State::default();
    a.mint(&mut state, NOW);
    let published = state.context.clone();
    let ctx = &state.context;

    let other = [own_file("h0", OwnFileState::Joined)];
    assert!(ctx.should_publish(&published, Some(&"h1"), &other));
    assert!(ctx.should_publish::<&str>(&published, Some(&"h1"), &[]));

    let present = [
        OwnFileState::Joined,
        OwnFileState::Remote,
        OwnFileState::NotJoined,
    ];
    for state in present {
        let files = [own_file("h1", state)];
        assert!(!ctx.should_publish(&published, Some(&"h1"), &files));
    }
}

#[test]
fn without_recorded_publish_only_context_decides() {
    let mut a = session(1);
    let mut state = State::default();
    let empty = CausalContext::default();

    assert!(!state.context.should_publish::<&str>(&empty, None, &[]));

    a.mint(&mut state, NOW);

    assert!(state.context.should_publish::<&str>(&empty, None, &[]));
}

#[test]
fn publish_deletes_only_joined_older_own_files() {
    let joined = own_file("h1", OwnFileState::Joined);
    let remote = own_file("h2", OwnFileState::Remote);
    let not_joined = own_file("h3", OwnFileState::NotJoined);
    let published = own_file("h4", OwnFileState::Joined);

    assert!(joined.should_delete(&"h4"));
    assert!(!remote.should_delete(&"h4"));
    assert!(!not_joined.should_delete(&"h4"));
    assert!(!published.should_delete(&"h4"));
}
