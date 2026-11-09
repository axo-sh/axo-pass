//! Property tests of join and the checks, on states from random valid
//! histories. The histories are in `histories.rs`.

use proptest::prelude::*;
use proptest::sample::Index;
use uuid::Uuid;

use super::histories::{History, Run, Target};
use super::*;

/// Change that makes a state fail one check in `try_join`.
#[derive(Clone, Copy, Debug)]
enum Forgery {
    /// Value with a counter above [`MAX_COUNTER`].
    CounterAboveMax { target: Target, counter: u64 },
    /// Context entry of the session actor above its last sequence number.
    ContextClaim { above: u64 },
    /// Write id of the session actor above its last sequence number, which
    /// the context does not hold.
    WriteClaim { target: Target, above: u64 },
    /// Write id that the context of the state does not cover.
    NotClosed { target: Target },
    /// Second value at the write id of the local name value.
    DuplicateWriteId,
    /// Second info for the session actor.
    DuplicateActorInfo,
}

impl Forgery {
    fn strategy() -> impl Strategy<Value = Self> {
        prop_oneof![
            (Target::strategy(), MAX_COUNTER + 1..=u64::MAX)
                .prop_map(|(target, counter)| Self::CounterAboveMax { target, counter }),
            (1..=5u64).prop_map(|above| Self::ContextClaim { above }),
            (Target::strategy(), 1..=5u64)
                .prop_map(|(target, above)| Self::WriteClaim { target, above }),
            Target::strategy().prop_map(|target| Self::NotClosed { target }),
            Just(Self::DuplicateWriteId),
            Just(Self::DuplicateActorInfo),
        ]
    }

    /// Mint of an actor that no session holds.
    fn mint(counter: u64) -> Mint {
        Mint {
            write_id: WriteId {
                actor: actor(99, 1),
                seq: 1,
            },
            counter,
            written_at: NOW,
        }
    }

    /// Forge a state from `peer`. `local` is the state that receives it, and
    /// `last` the last mint of its session, which wrote the local name value.
    fn apply(self, mut peer: State, local: &State, last: &Mint) -> State {
        let claim = |above| WriteId {
            seq: last.write_id.seq + above,
            ..last.write_id
        };
        match self {
            Self::CounterAboveMax { target, counter } => {
                let mint = Self::mint(counter);
                target.write(&mut peer.store, &mint, 0, false);
                peer.context.record(mint.write_id);
            },
            Self::ContextClaim { above } => peer.context.record(claim(above)),
            Self::WriteClaim { target, above } => {
                let mint = Mint {
                    write_id: claim(above),
                    ..*last
                };
                target.write(&mut peer.store, &mint, 0, false);
            },
            Self::NotClosed { target } => {
                target.write(&mut peer.store, &Self::mint(2), 0, false);
            },
            Self::DuplicateWriteId => {
                peer = joined(local, &peer);
                peer.store.name.write(last, "Forged");
            },
            Self::DuplicateActorInfo => {
                peer = joined(local, &peer);
                let info = ActorInfo {
                    replica: ReplicaId(Uuid::from_u128(99)),
                    started_at: NOW,
                };
                peer.actors.insert(last.write_id.actor, info);
            },
        }
        peer
    }

    /// Whether `err` is the error of the check this forgery fails.
    fn matches(&self, err: &JoinError) -> bool {
        match self {
            Self::CounterAboveMax { .. } => matches!(err, JoinError::CounterAboveMax { .. }),
            Self::ContextClaim { .. } | Self::WriteClaim { .. } => {
                matches!(err, JoinError::SessionActorClaimed { .. })
            },
            Self::NotClosed { .. } => matches!(err, JoinError::NotCausallyClosed { .. }),
            Self::DuplicateWriteId => matches!(err, JoinError::DuplicateWriteId { .. }),
            Self::DuplicateActorInfo => matches!(err, JoinError::DuplicateActorInfo { .. }),
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn join_is_commutative_on_generated_states(
        history in History::strategy(),
        x in any::<Index>(),
        y in any::<Index>(),
    ) {
        let run = Run::play(&history);
        let states = run.states();
        let (x, y) = (x.get(&states), y.get(&states));

        prop_assert_eq!(joined(x, y), joined(y, x));
    }

    #[test]
    fn join_is_associative_on_generated_states(
        history in History::strategy(),
        x in any::<Index>(),
        y in any::<Index>(),
        z in any::<Index>(),
    ) {
        let run = Run::play(&history);
        let states = run.states();
        let (x, y, z) = (x.get(&states), y.get(&states), z.get(&states));

        prop_assert_eq!(joined(&joined(x, y), z), joined(x, &joined(y, z)));
    }

    #[test]
    fn join_is_idempotent_on_generated_states(
        history in History::strategy(),
        x in any::<Index>(),
    ) {
        let run = Run::play(&history);
        let x = *x.get(&run.states());

        prop_assert_eq!(&joined(x, x), x);
    }

    #[test]
    fn valid_histories_pass_every_check(history in History::strategy()) {
        // Each join of the history is checked as it is played.
        let mut run = Run::play(&history);

        // Every replica joins every version of every other replica.
        for n in 0..history.replicas {
            let peers: Vec<State> = run.others(n).into_iter().cloned().collect();
            let replica = &mut run.replicas[n];
            for peer in peers {
                let result = replica.state.try_join(peer, &mut replica.session);
                prop_assert!(result.is_ok(), "valid state failed a check: {result:?}");
            }
        }
    }

    #[test]
    fn write_after_join_orders_above_every_joined_value(
        history in History::strategy(),
        replica in any::<Index>(),
        version in any::<Index>(),
    ) {
        let mut run = Run::play(&history);
        let n = replica.index(history.replicas);
        let peer = (*version.get(&run.others(n))).clone();
        let replica = &mut run.replicas[n];

        let result = replica.state.try_join(peer, &mut replica.session);
        prop_assert!(result.is_ok(), "valid state failed a check: {result:?}");
        let keys = order_keys(&replica.state.store);
        let m = replica.mint();

        prop_assert!(keys.iter().all(|key| *key < m.order_key()));
        prop_assert!(m.counter < MAX_COUNTER);
    }

    #[test]
    fn refused_or_quarantined_state_leaves_local_state_unchanged(
        history in History::strategy(),
        replica in any::<Index>(),
        version in any::<Index>(),
        forgery in Forgery::strategy(),
    ) {
        let mut run = Run::play(&history);
        let n = replica.index(history.replicas);
        let base = (*version.get(&run.others(n))).clone();
        let replica = &mut run.replicas[n];
        // Local write, so the session has an actor and the name register a
        // value.
        let last = replica.mint();
        replica.state.store.name.write(&last, "Work");
        let peer = forgery.apply(base, &replica.state, &last);
        let before = replica.state.clone();

        let result = replica.state.try_join(peer, &mut replica.session);

        let Err(err) = result else {
            return Err(TestCaseError::fail(format!("{forgery:?} was {result:?}")));
        };
        prop_assert!(forgery.matches(&err), "{forgery:?} failed with {err:?}");
        prop_assert_eq!(&replica.state, &before);
    }

    #[test]
    fn state_holding_counter_above_max_counter_refused(
        history in History::strategy(),
        replica in any::<Index>(),
        version in any::<Index>(),
        target in Target::strategy(),
        counter in MAX_COUNTER + 1..=u64::MAX,
    ) {
        let mut run = Run::play(&history);
        let n = replica.index(history.replicas);
        let mut peer = (*version.get(&run.states())).clone();
        let mint = Forgery::mint(counter);
        target.write(&mut peer.store, &mint, 0, false);
        peer.context.record(mint.write_id);
        let replica = &mut run.replicas[n];
        let before = replica.state.clone();

        let result = replica.state.try_join(peer, &mut replica.session);

        let expected = JoinError::CounterAboveMax { write_id: mint.write_id, counter };
        prop_assert_eq!(result, Err(expected));
        prop_assert_eq!(expected.action(), JoinAction::Refuse);
        prop_assert_eq!(&replica.state, &before);
    }

    #[test]
    fn value_at_max_counter_joined_and_no_replica_refuses_another_afterwards(
        history in History::strategy(),
        at in any::<Index>(),
        holder in any::<Index>(),
    ) {
        let mut run = Run::new(history.replicas);
        let (before, after) = history.steps.split_at(at.index(history.steps.len() + 1));
        for step in before {
            run.apply(step);
        }
        // Name value at the cap. The name register is never removed, so each
        // state that joins the value holds a value at the cap from then on.
        let holder = &mut run.replicas[holder.index(history.replicas)];
        let m = holder.mint();
        holder.state.store.name.write(&Mint { counter: MAX_COUNTER, ..m }, "Work");
        holder.record();

        // Each join is checked as it is played.
        for step in after {
            let highest = run.replicas[step.replica()].state.store.highest_counter();
            let mint = run.apply(step);
            if let Some(m) = mint.filter(|_| highest == MAX_COUNTER) {
                prop_assert_eq!(m.counter, MAX_COUNTER);
            }
        }

        // Every replica joins the latest state of every other replica, then
        // mints at the cap.
        for n in 0..history.replicas {
            for from in (0..history.replicas).filter(|from| *from != n) {
                let peer = run.replicas[from].state.clone();
                let replica = &mut run.replicas[n];
                let result = replica.state.try_join(peer, &mut replica.session);
                prop_assert!(result.is_ok(), "state failed a check: {result:?}");
            }
        }
        for replica in &mut run.replicas {
            prop_assert_eq!(replica.mint().counter, MAX_COUNTER);
        }
    }
}
