//! Property tests of join and the checks, on states from random valid
//! histories.
//!
//! A history runs mints with writes and removes, repair writes, removal-only
//! mints, joins through `try_join`, and session ends across 2 to 4 replicas.
//! Every state a replica held is kept as a version, and a join takes any past
//! version of another replica.

use proptest::collection::vec;
use proptest::prelude::*;
use proptest::sample::{Index, select};
use uuid::Uuid;

use super::*;

/// Item keys of generated writes and removes.
const ITEMS: std::ops::RangeInclusive<u32> = 1..=3;
const SITES: &[&str] = &["a.com", "b.com"];
const NAMES: &[&str] = &["Work", "Home"];
const TITLES: &[&str] = &["Mail", "Bank", "Shop", "Gym"];

/// Register that a generated write sets.
#[derive(Clone, Copy, Debug)]
enum Target {
    Name,
    Title(u32),
    Folder(u32),
    Website(u32, &'static str),
    Trashed(u32),
}

impl Target {
    fn strategy() -> impl Strategy<Value = Self> {
        prop_oneof![
            Just(Self::Name),
            ITEMS.prop_map(Self::Title),
            ITEMS.prop_map(Self::Folder),
            (ITEMS, select(SITES)).prop_map(|(key, site)| Self::Website(key, site)),
            ITEMS.prop_map(Self::Trashed),
        ]
    }

    /// Write a value picked by `value` with `mint`. A repair write leaves the
    /// other values of the register.
    fn write(self, store: &mut Vault, mint: &Mint, value: u8, repair: bool) {
        let index = usize::from(value);
        let set = value % 2 == 1;
        match self {
            Self::Name => Self::put(&mut store.name, mint, NAMES[index % NAMES.len()], repair),
            Self::Title(key) => Self::put(
                &mut store.items.entry(key).title,
                mint,
                TITLES[index % TITLES.len()],
                repair,
            ),
            Self::Folder(key) => Self::put(
                &mut store.items.entry(key).folder,
                mint,
                set.then_some(u32::from(value)),
                repair,
            ),
            Self::Website(key, site) => Self::put(
                store.items.entry(key).websites.entry(site),
                mint,
                u32::from(value),
                repair,
            ),
            Self::Trashed(key) => Self::put(
                &mut store.items.entry(key).trashed,
                mint,
                set.then_some(i64::from(value)),
                repair,
            ),
        }
    }

    fn put<T, P: Policy>(register: &mut MvRegister<T, P>, mint: &Mint, value: T, repair: bool) {
        if repair {
            register.write_repair(mint, value);
        } else {
            register.write(mint, value);
        }
    }
}

/// Map entry that a generated remove drops.
#[derive(Clone, Copy, Debug)]
enum Entry {
    Item(u32),
    Website(u32, &'static str),
}

impl Entry {
    fn strategy() -> impl Strategy<Value = Self> {
        prop_oneof![
            ITEMS.prop_map(Self::Item),
            (ITEMS, select(SITES)).prop_map(|(key, site)| Self::Website(key, site)),
        ]
    }

    fn remove(self, store: &mut Vault) {
        match self {
            Self::Item(key) => {
                store.items.remove(&key);
            },
            Self::Website(key, site) => {
                store.items.entry(key).websites.remove(&site);
            },
        }
    }
}

/// Edit of a mint with writes.
#[derive(Clone, Copy, Debug)]
enum Edit {
    Write(Target, u8),
    Remove(Entry),
}

impl Edit {
    fn strategy() -> impl Strategy<Value = Self> {
        prop_oneof![
            3 => (Target::strategy(), any::<u8>()).prop_map(|(target, value)| Self::Write(target, value)),
            1 => Entry::strategy().prop_map(Self::Remove),
        ]
    }

    fn apply(self, store: &mut Vault, mint: &Mint) {
        match self {
            Self::Write(target, value) => target.write(store, mint, value, false),
            Self::Remove(entry) => entry.remove(store),
        }
    }
}

/// Step of a history. `replica` is the index of the replica that takes it.
#[derive(Clone, Debug)]
enum Step {
    /// One mint with writes and removes.
    Write { replica: usize, edits: Vec<Edit> },
    /// One mint with a repair write.
    Repair {
        replica: usize,
        target: Target,
        value: u8,
    },
    /// One mint whose write id goes into no register.
    RemovalOnly { replica: usize, entries: Vec<Entry> },
    /// Join of a past version of replica `from` through `try_join`.
    Join {
        replica: usize,
        from: usize,
        version: Index,
    },
    /// End of the session actor.
    End { replica: usize },
}

impl Step {
    fn strategy(replicas: usize) -> impl Strategy<Value = Self> {
        prop_oneof![
            4 => (0..replicas, vec(Edit::strategy(), 1..4))
                .prop_map(|(replica, edits)| Self::Write { replica, edits }),
            1 => (0..replicas, Target::strategy(), any::<u8>())
                .prop_map(|(replica, target, value)| Self::Repair { replica, target, value }),
            1 => (0..replicas, vec(Entry::strategy(), 0..3))
                .prop_map(|(replica, entries)| Self::RemovalOnly { replica, entries }),
            4 => (0..replicas, 1..replicas, any::<Index>()).prop_map(move |(replica, offset, version)| {
                let from = (replica + offset) % replicas;
                Self::Join { replica, from, version }
            }),
            1 => (0..replicas).prop_map(|replica| Self::End { replica }),
        ]
    }

    fn replica(&self) -> usize {
        match self {
            Self::Write { replica, .. }
            | Self::Repair { replica, .. }
            | Self::RemovalOnly { replica, .. }
            | Self::Join { replica, .. }
            | Self::End { replica } => *replica,
        }
    }
}

/// Random history of 2 to 4 replicas.
#[derive(Clone, Debug)]
struct History {
    replicas: usize,
    steps: Vec<Step>,
}

impl History {
    fn strategy() -> impl Strategy<Value = Self> {
        (2..=4usize).prop_flat_map(|replicas| {
            vec(Step::strategy(replicas), 0..24).prop_map(move |steps| Self { replicas, steps })
        })
    }
}

/// Replica of a history, with every state it held.
struct Replica {
    session: Session,
    state: State,
    versions: Vec<State>,
}

impl Replica {
    fn mint(&mut self) -> Mint {
        self.session.mint(&mut self.state, NOW)
    }

    /// Record the state as a version. Entries that a remove left empty are
    /// dropped first, as a join drops them.
    fn record(&mut self) {
        self.state.join(State::default());
        self.versions.push(self.state.clone());
    }
}

/// Replicas of a history as it is played.
struct Run {
    replicas: Vec<Replica>,
}

impl Run {
    /// Replicas 1 to `replicas`, each with the empty state as first version.
    fn new(replicas: usize) -> Self {
        let replicas = (1..=replicas as u128)
            .map(|n| Replica {
                session: session(n),
                state: State::default(),
                versions: vec![State::default()],
            })
            .collect();
        Self { replicas }
    }

    fn play(history: &History) -> Self {
        let mut run = Self::new(history.replicas);
        for step in &history.steps {
            run.apply(step);
        }
        run
    }

    /// Apply `step` and record the new version of its replica. Returns the
    /// mint of the step, if any.
    ///
    /// Panics if `try_join` refuses or quarantines a state, since every
    /// generated state is valid.
    fn apply(&mut self, step: &Step) -> Option<Mint> {
        let mint = match step {
            Step::Write { replica, edits } => {
                let replica = &mut self.replicas[*replica];
                let mint = replica.mint();
                for edit in edits {
                    edit.apply(&mut replica.state.store, &mint);
                }
                Some(mint)
            },
            Step::Repair {
                replica,
                target,
                value,
            } => {
                let replica = &mut self.replicas[*replica];
                let mint = replica.mint();
                target.write(&mut replica.state.store, &mint, *value, true);
                Some(mint)
            },
            Step::RemovalOnly { replica, entries } => {
                let replica = &mut self.replicas[*replica];
                let mint = replica.mint();
                for entry in entries {
                    entry.remove(&mut replica.state.store);
                }
                Some(mint)
            },
            Step::Join {
                replica,
                from,
                version,
            } => {
                let peer = version.get(&self.replicas[*from].versions).clone();
                let replica = &mut self.replicas[*replica];
                let result = replica.state.try_join(peer, &mut replica.session);
                assert!(result.is_ok(), "valid state failed a check: {result:?}");
                None
            },
            Step::End { replica } => {
                self.replicas[*replica].session.end();
                None
            },
        };
        self.replicas[step.replica()].record();
        mint
    }

    /// Every version of every replica.
    fn states(&self) -> Vec<&State> {
        self.replicas.iter().flat_map(|r| &r.versions).collect()
    }

    /// Every version of every replica other than `replica`.
    fn others(&self, replica: usize) -> Vec<&State> {
        self.replicas
            .iter()
            .enumerate()
            .filter(|(n, _)| *n != replica)
            .flat_map(|(_, r)| &r.versions)
            .collect()
    }
}

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
    fn state_holding_counter_above_max_counter_is_refused(
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
    fn value_at_max_counter_is_joined_and_no_replica_refuses_another_afterwards(
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
