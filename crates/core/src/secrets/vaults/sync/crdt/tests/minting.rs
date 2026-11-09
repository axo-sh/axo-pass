use super::*;

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
fn one_mint_written_into_every_changed_register() {
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
