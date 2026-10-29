use uuid::Uuid;

use super::*;

/// Test store shaped like `SyncItem`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Item {
    title: MvRegister<&'static str, Ask>,
    folder: MvRegister<Option<u32>, Order>,
    websites: OrMap<&'static str, MvRegister<u32, Order>>,
    trashed: MvRegister<Option<i64>, Trash>,
}

impl CausalStore for Item {
    fn is_empty(&self) -> bool {
        self.title.is_empty()
            && self.folder.is_empty()
            && self.websites.is_empty()
            && self.trashed.is_empty()
    }

    fn each_value(&self, f: &mut dyn FnMut(WriteId, u64)) {
        self.title.each_value(f);
        self.folder.each_value(f);
        self.websites.each_value(f);
        self.trashed.each_value(f);
    }

    fn join(&mut self, ctx: &CausalContext, other: Self, other_ctx: &CausalContext) {
        self.title.join(ctx, other.title, other_ctx);
        self.folder.join(ctx, other.folder, other_ctx);
        self.websites.join(ctx, other.websites, other_ctx);
        self.trashed.join(ctx, other.trashed, other_ctx);
    }
}

/// Test store shaped like `SyncState`, without the context and actors.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Vault {
    name: MvRegister<&'static str, Ask>,
    items: OrMap<u32, Item>,
}

impl CausalStore for Vault {
    fn is_empty(&self) -> bool {
        self.name.is_empty() && self.items.is_empty()
    }

    fn each_value(&self, f: &mut dyn FnMut(WriteId, u64)) {
        self.name.each_value(f);
        self.items.each_value(f);
    }

    fn join(&mut self, ctx: &CausalContext, other: Self, other_ctx: &CausalContext) {
        self.name.join(ctx, other.name, other_ctx);
        self.items.join(ctx, other.items, other_ctx);
    }
}

type State = CausalState<Vault>;

/// Actor of one replica. Stands in for the session of 4.2.
struct Writer {
    replica: ReplicaId,
    actor: ActorId,
}

impl Writer {
    fn new(n: u128) -> Self {
        Self {
            replica: ReplicaId(Uuid::from_u128(n)),
            actor: ActorId(Uuid::from_u128(0x100 + n)),
        }
    }

    /// Next write id of the actor in `state`. Recorded in the context and in
    /// `actors`.
    fn mint(&self, state: &mut State) -> Mint {
        let seq = state.context.get(self.actor) + 1;
        let write_id = WriteId {
            actor: self.actor,
            seq,
        };
        state.context.record(write_id);
        state.actors.entry(self.actor).or_insert(ActorInfo {
            replica: self.replica,
            started_at: 1_000,
        });
        Mint {
            write_id,
            counter: seq + 1,
            written_at: 1_000 + seq as i64,
        }
    }
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
    let (a, b) = (Writer::new(1), Writer::new(2));
    let mut left = State::default();
    let m = a.mint(&mut left);
    left.store.name.write(&m, "Work");
    let mut right = left.clone();
    let m = b.mint(&mut right);
    right.store.items.entry(1).title.write(&m, "Mail");

    let state = joined(&left, &right);

    assert_eq!(values(&state.store.name), ["Work"]);
    assert_eq!(state, joined(&right, &left));
}

#[test]
fn value_not_covered_by_other_context_is_kept() {
    let (a, b) = (Writer::new(1), Writer::new(2));
    let mut left = State::default();
    let m = a.mint(&mut left);
    left.store.name.write(&m, "Work");
    let mut right = State::default();
    let m = b.mint(&mut right);
    right.store.items.entry(1).title.write(&m, "Mail");

    let state = joined(&left, &right);

    assert_eq!(values(&state.store.name), ["Work"]);
    assert_eq!(values(&state.store.items.get(&1).unwrap().title), ["Mail"]);
    assert_eq!(state, joined(&right, &left));
}

#[test]
fn value_covered_by_other_context_is_dropped() {
    let (a, b) = (Writer::new(1), Writer::new(2));
    let mut left = State::default();
    let m = a.mint(&mut left);
    left.store.name.write(&m, "Work");
    let mut right = left.clone();
    let m = b.mint(&mut right);
    right.store.name.write(&m, "Home");

    let state = joined(&left, &right);

    assert_eq!(values(&state.store.name), ["Home"]);
    assert_eq!(state, joined(&right, &left));
}

#[test]
fn write_concurrent_with_remove_of_its_entry_is_kept() {
    let (a, b) = (Writer::new(1), Writer::new(2));
    let mut base = State::default();
    let m = a.mint(&mut base);
    base.store
        .items
        .entry(1)
        .websites
        .entry("a.com")
        .write(&m, 0);
    let mut left = base.clone();
    let m = a.mint(&mut left);
    left.store
        .items
        .entry(1)
        .websites
        .entry("a.com")
        .write(&m, 1);
    let mut right = base.clone();
    b.mint(&mut right);
    right.store.items.entry(1).websites.remove(&"a.com");

    let state = joined(&left, &right);

    let websites = &state.store.items.get(&1).unwrap().websites;
    assert_eq!(values(websites.get(&"a.com").unwrap()), [1]);
    assert_eq!(state, joined(&right, &left));
}

#[test]
fn remove_after_seeing_every_write_id_drops_entry() {
    let (a, b) = (Writer::new(1), Writer::new(2));
    let mut left = State::default();
    let m = a.mint(&mut left);
    let item = left.store.items.entry(1);
    item.title.write(&m, "Mail");
    item.websites.entry("a.com").write(&m, 0);
    item.websites.entry("b.com").write(&m, 1);
    let mut right = left.clone();
    b.mint(&mut right);
    right.store.items.entry(1).websites.remove(&"a.com");

    let state = joined(&left, &right);

    let websites = &state.store.items.get(&1).unwrap().websites;
    assert!(websites.get(&"a.com").is_none());
    assert_eq!(values(websites.get(&"b.com").unwrap()), [1]);
    assert_eq!(state, joined(&right, &left));
}

#[test]
fn entry_empty_after_join_is_absent() {
    let (a, b) = (Writer::new(1), Writer::new(2));
    let mut left = State::default();
    let m = a.mint(&mut left);
    let item = left.store.items.entry(1);
    item.title.write(&m, "Mail");
    item.websites.entry("a.com").write(&m, 0);
    let mut right = left.clone();
    b.mint(&mut right);
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
    let (a, b) = (Writer::new(1), Writer::new(2));
    let mut base = State::default();
    let m = a.mint(&mut base);
    let item = base.store.items.entry(1);
    item.title.write(&m, "Mail");
    item.folder.write(&m, None);
    let mut left = base.clone();
    let m = a.mint(&mut left);
    left.store.items.entry(1).title.write(&m, "Email");
    let mut right = base.clone();
    let m = b.mint(&mut right);
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
    let (a, b) = (Writer::new(1), Writer::new(2));
    let mut left = State::default();
    let m = a.mint(&mut left);
    left.store
        .items
        .entry(1)
        .websites
        .entry("a.com")
        .write(&m, 0);
    let mut right = left.clone();
    let m = b.mint(&mut right);
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
    let (a, b) = (Writer::new(1), Writer::new(2));
    let mut left = State::default();
    let m = a.mint(&mut left);
    left.store.name.write(&m, "Work");
    let mut right = State::default();
    let m = b.mint(&mut right);
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
    let (a, b) = (Writer::new(1), Writer::new(2));
    let mut left = State::default();
    let m = a.mint(&mut left);
    left.store.name.write(&m, "Work");
    let mut right = State::default();
    let m = b.mint(&mut right);
    right.store.name.write(&m, "Home");
    left.join(right);
    assert_eq!(left.store.name.values().count(), 2);

    let m = a.mint(&mut left);
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
    let (a, b) = (Writer::new(1), Writer::new(2));
    let mut state = State::default();
    let m1 = a.mint(&mut state);
    state.store.name.write(&m1, "Work");
    let m2 = b.mint(&mut state);
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
    let (a, b, c) = (Writer::new(1), Writer::new(2), Writer::new(3));

    let mut base = State::default();
    let m = a.mint(&mut base);
    base.store.name.write(&m, "Work");
    let item = base.store.items.entry(1);
    item.title.write(&m, "Mail");
    item.websites.entry("a.com").write(&m, 0);

    // b renames item 1 and adds item 2.
    let mut renamed = base.clone();
    let m = b.mint(&mut renamed);
    renamed.store.items.entry(1).title.write(&m, "Email");
    renamed.store.items.entry(2).title.write(&m, "Bank");

    // c removes the website and renames item 1, concurrent with b.
    let mut removed = base.clone();
    let m = c.mint(&mut removed);
    let item = removed.store.items.entry(1);
    item.websites.remove(&"a.com");
    item.title.write(&m, "Post");

    // a joins b, removes item 2, and trashes item 1, concurrent with c.
    let mut trashed = joined(&base, &renamed);
    let m = a.mint(&mut trashed);
    trashed.store.items.remove(&2);
    trashed.store.items.entry(1).trashed.write(&m, Some(1_000));

    // c joins a and adds a website.
    let mut added = joined(&removed, &trashed);
    let m = c.mint(&mut added);
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
