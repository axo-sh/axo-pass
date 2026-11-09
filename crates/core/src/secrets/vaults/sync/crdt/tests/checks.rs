//! Tests of the context checks, the causal closure check, the duplicate write
//! id check, and the covered skip.

use super::*;

/// Mint of `actor` at `seq` with `counter`, made outside any session.
fn forged(actor: ActorId, seq: u64, counter: u64) -> Mint {
    Mint {
        write_id: WriteId { actor, seq },
        counter,
        written_at: NOW,
    }
}

/// State of replica 1 with one write by `a`.
fn local(a: &mut Session) -> (State, Mint) {
    let mut state = State::default();
    let m = a.mint(&mut state, NOW);
    state.store.name.write(&m, "Work");
    (state, m)
}

#[test]
fn state_with_counter_above_max_counter_refused() {
    let (mut a, mut b) = (session(1), session(2));
    let (mut state, m_a) = local(&mut a);
    let mut peer = State::default();
    let m = b.mint(&mut peer, NOW);
    let above = Mint {
        counter: MAX_COUNTER + 1,
        ..m
    };
    peer.store.name.write(&above, "Home");
    let before = state.clone();

    let err = state.try_join(peer, &mut a).unwrap_err();

    let expected = JoinError::CounterAboveMax {
        write_id: m.write_id,
        counter: MAX_COUNTER + 1,
    };
    assert_eq!(err, expected);
    assert_eq!(err.action(), JoinAction::Refuse);
    assert_eq!(state, before);
    assert_eq!(a.last_write(), Some(m_a.write_id));
}

#[test]
fn state_with_counter_at_max_counter_joined() {
    let (mut a, mut b) = (session(1), session(2));
    let (mut state, _) = local(&mut a);
    let mut peer = State::default();
    let m = b.mint(&mut peer, NOW);
    let at = Mint {
        counter: MAX_COUNTER,
        ..m
    };
    peer.store.name.write(&at, "Home");

    let outcome = state.try_join(peer, &mut a);

    assert_eq!(outcome, Ok(JoinOutcome::Joined));
    assert_eq!(values(&state.store.name), ["Work", "Home"]);
    assert_eq!(a.mint(&mut state, NOW).counter, MAX_COUNTER);
}

#[test]
fn context_entry_claim_on_session_actor_refused_and_session_starts_new_actor() {
    let (mut a, mut b) = (session(1), session(2));
    let (mut state, m_a) = local(&mut a);
    let mut peer = state.clone();
    let claim = WriteId {
        actor: actor(1, 1),
        seq: 5,
    };
    peer.context.record(claim);
    b.mint(&mut peer, NOW);
    let before = state.clone();

    let err = state.try_join(peer, &mut a).unwrap_err();

    let expected = JoinError::SessionActorClaimed {
        claim,
        last: m_a.write_id,
    };
    assert_eq!(err, expected);
    assert_eq!(err.action(), JoinAction::Refuse);
    assert_eq!(state, before);
    assert_eq!(a.actor(), None);
    let m = a.mint(&mut state, NOW);
    let write_id = WriteId {
        actor: actor(1, 2),
        seq: 1,
    };
    assert_eq!(m.write_id, write_id);
}

#[test]
fn write_id_claim_on_session_actor_refused_and_session_starts_new_actor() {
    let (mut a, mut b) = (session(1), session(2));
    let (mut state, m_a) = local(&mut a);
    let mut peer = state.clone();
    let claim = forged(actor(1, 1), 2, 3);
    peer.store.items.entry(1).title.write(&claim, "Mail");
    peer.context.record(claim.write_id);
    b.mint(&mut peer, NOW);

    let err = state.try_join(peer, &mut a).unwrap_err();

    let expected = JoinError::SessionActorClaimed {
        claim: claim.write_id,
        last: m_a.write_id,
    };
    assert_eq!(err, expected);
    assert_eq!(a.actor(), None);
    assert_eq!(a.mint(&mut state, NOW).write_id.actor, actor(1, 2));
}

#[test]
fn claim_on_session_actor_refused_before_closure_check() {
    let (mut a, mut b) = (session(1), session(2));
    let (mut state, _) = local(&mut a);
    let mut peer = state.clone();
    // Write id of the session's actor that the peer context does not cover.
    let claim = forged(actor(1, 1), 2, 3);
    peer.store.items.entry(1).title.write(&claim, "Mail");
    b.mint(&mut peer, NOW);

    let err = state.try_join(peer, &mut a).unwrap_err();

    assert!(matches!(err, JoinError::SessionActorClaimed { .. }));
    assert_eq!(err.action(), JoinAction::Refuse);
}

#[test]
fn state_at_session_sequence_number_joined() {
    let mut a = session(1);
    let (mut state, _) = local(&mut a);
    let backup = state.clone();
    let m = a.mint(&mut state, NOW);
    state.store.items.entry(1).title.write(&m, "Mail");
    let own = state;

    // State replaced by a backup that lacks write 2. The session still holds
    // write 2 as its last write.
    let mut state = backup;
    let outcome = state.try_join(own, &mut a);

    assert_eq!(outcome, Ok(JoinOutcome::Joined));
    assert_eq!(a.last_write(), Some(m.write_id));
    let title = &state.store.items.get(&1).unwrap().title;
    assert_eq!(values(title), ["Mail"]);
    let next = a.mint(&mut state, NOW);
    assert_eq!(
        next.write_id,
        WriteId {
            seq: 3,
            ..m.write_id
        }
    );
}

#[test]
fn earlier_actor_write_ids_above_context_joined() {
    let mut a = session(1);
    let (mut state, _) = local(&mut a);
    let backup = state.clone();
    let m = a.mint(&mut state, NOW);
    state.store.items.entry(1).title.write(&m, "Mail");
    let own = state;

    // Restore of the backup. The session ends and the next mint starts actor
    // 2 of replica 1.
    let mut state = backup;
    a.end();
    let m2 = a.mint(&mut state, NOW);
    state.store.name.write(&m2, "Home");
    let outcome = state.try_join(own, &mut a);

    assert_eq!(outcome, Ok(JoinOutcome::Joined));
    assert_eq!(a.actor(), Some(actor(1, 2)));
    assert_eq!(state.context.get(actor(1, 1)), 2);
    let title = &state.store.items.get(&1).unwrap().title;
    assert_eq!(values(title), ["Mail"]);
    assert_eq!(values(&state.store.name), ["Home"]);
}

#[test]
fn second_value_for_write_id_quarantines_state() {
    let (mut a, mut b, mut c) = (session(1), session(2), session(3));
    let (first, m) = local(&mut a);
    // Peer with a second value at the write id of the first.
    let mut second = first.clone();
    second.store.name.write(&m, "Home");
    let m2 = b.mint(&mut second, NOW);
    second.store.items.entry(1).title.write(&m2, "Mail");

    let mut state = State::default();
    assert_eq!(
        state.try_join(first.clone(), &mut c),
        Ok(JoinOutcome::Joined)
    );
    let before = state.clone();
    let err = state.try_join(second.clone(), &mut c).unwrap_err();

    let expected = JoinError::DuplicateWriteId {
        write_id: m.write_id,
    };
    assert_eq!(err, expected);
    assert_eq!(err.action(), JoinAction::Quarantine);
    assert_eq!(state, before);

    // Replica that met the second value first quarantines the first, though
    // its context covers it.
    let mut state = State::default();
    assert_eq!(state.try_join(second, &mut c), Ok(JoinOutcome::Joined));
    assert_eq!(state.try_join(first, &mut c), Err(expected));
}

#[test]
fn one_write_id_with_two_counters_quarantined() {
    let (mut a, mut b) = (session(1), session(2));
    let (first, m) = local(&mut a);
    let mut second = first.clone();
    second.store.name.write(&Mint { counter: 5, ..m }, "Work");
    b.mint(&mut second, NOW);

    let mut state = first;
    let err = state.try_join(second, &mut a).unwrap_err();

    let expected = JoinError::DuplicateWriteId {
        write_id: m.write_id,
    };
    assert_eq!(err, expected);
    assert_eq!(err.action(), JoinAction::Quarantine);
}

#[test]
fn actor_with_different_info_quarantined() {
    let (mut a, mut b) = (session(1), session(2));
    let (mut state, _) = local(&mut a);
    let mut peer = state.clone();
    let info = ActorInfo {
        replica: b.replica,
        started_at: NOW,
    };
    peer.actors.insert(actor(1, 1), info);
    b.mint(&mut peer, NOW);
    let before = state.clone();

    let err = state.try_join(peer, &mut a).unwrap_err();

    let expected = JoinError::DuplicateActorInfo { actor: actor(1, 1) };
    assert_eq!(err, expected);
    assert_eq!(err.action(), JoinAction::Quarantine);
    assert_eq!(state, before);
}

#[test]
fn state_not_covered_by_own_context_quarantined() {
    let (mut a, mut b) = (session(1), session(2));
    let (mut state, _) = local(&mut a);
    let mut peer = State::default();
    let m = b.mint(&mut peer, NOW);
    peer.store.name.write(&m, "Home");
    let uncovered = forged(actor(2, 1), 2, 3);
    peer.store.items.entry(1).title.write(&uncovered, "Mail");
    let before = state.clone();

    let err = state.try_join(peer, &mut a).unwrap_err();

    let expected = JoinError::NotCausallyClosed {
        write_id: uncovered.write_id,
    };
    assert_eq!(err, expected);
    assert_eq!(err.action(), JoinAction::Quarantine);
    assert_eq!(state, before);
}

#[test]
fn covered_state_skipped() {
    let (mut a, mut b) = (session(1), session(2));
    let (mut state, _) = local(&mut a);
    let mut peer = state.clone();
    let m = b.mint(&mut peer, NOW);
    peer.store.items.entry(1).title.write(&m, "Mail");

    // Peer shares a write id with equal values and is ahead.
    assert_eq!(
        state.try_join(peer.clone(), &mut a),
        Ok(JoinOutcome::Joined)
    );
    let m = a.mint(&mut state, NOW);
    state.store.name.write(&m, "Home");
    let before = state.clone();

    assert_eq!(
        state.try_join(peer.clone(), &mut a),
        Ok(JoinOutcome::Skipped)
    );
    assert_eq!(state, before);
    let copy = state.clone();
    assert_eq!(state.try_join(copy, &mut a), Ok(JoinOutcome::Skipped));
}
