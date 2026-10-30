//! Simulator of replicas that publish their states as files and join the
//! files of their peers.
//!
//! Replicas play a random valid history from `histories.rs`. Each step other
//! than a session end is one transaction. A join step is a delivery, which
//! hands the replica any past file of the peer, so files arrive in any order,
//! and some arrive twice or never. Every join goes through `try_join`. After
//! each transaction the replica publishes by `CausalContext::should_publish`
//! and deletes its older files by `OwnFile::should_delete`. A published file
//! is a clone of the state.

use std::collections::{BTreeMap, BTreeSet};

use proptest::collection::vec;
use proptest::prelude::*;
use proptest::sample::Index;

use super::histories::{Entry, History, Run, Step, Target};
use super::*;

/// Policy and order keys of one register, lowest key first.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Register {
    kind: PolicyKind,
    keys: Vec<OrderKey>,
}

impl Register {
    fn of<T, P: Policy>(register: &MvRegister<T, P>) -> Self {
        let keys = register.ordered().into_iter().map(|(key, _)| key).collect();
        Self {
            kind: P::KIND,
            keys,
        }
    }

    /// Every register of `store` that holds a value, by target.
    fn all(store: &Vault) -> BTreeMap<Target, Self> {
        let mut all = BTreeMap::new();
        let mut add = |target, register: Self| {
            if !register.keys.is_empty() {
                all.insert(target, register);
            }
        };
        add(Target::Name, Self::of(&store.name));
        for (&key, item) in store.items.iter() {
            add(Target::Title(key), Self::of(&item.title));
            add(Target::Folder(key), Self::of(&item.folder));
            add(Target::Trashed(key), Self::of(&item.trashed));
            for (&site, register) in item.websites.iter() {
                add(Target::Website(key, site), Self::of(register));
            }
            for (&entry, register) in item.history.iter() {
                add(Target::History(key, entry), Self::of(register));
            }
        }
        for (&key, register) in store.signals.iter() {
            add(Target::Signal(key), Self::of(register));
        }
        all
    }

    /// Every register value of `store`, by target and write id.
    fn values(store: &Vault) -> BTreeSet<(Target, WriteId)> {
        Self::all(store)
            .into_iter()
            .flat_map(|(target, register)| {
                register
                    .keys
                    .into_iter()
                    .map(move |key| (target, key.write_id))
            })
            .collect()
    }
}

/// Published files of one replica.
#[derive(Default)]
struct Files {
    /// Every file the replica published, oldest first. The index of a file
    /// is its content hash.
    published: Vec<State>,
    /// Files in the replica directory.
    directory: Vec<OwnFile<usize>>,
    /// Context of the last published file.
    published_context: CausalContext,
    /// Hash of the last published file.
    last_published: Option<usize>,
}

/// Replicas of a history, with their files and a record of every edit.
struct Sim {
    run: Run,
    files: Vec<Files>,
    /// Register values that edits added.
    written: BTreeSet<(Target, WriteId)>,
    /// Register values that edits replaced or removed on a replica that held
    /// them.
    superseded: BTreeSet<(Target, WriteId)>,
    /// Context of the state before each mint, by write id of the mint.
    observed: BTreeMap<WriteId, CausalContext>,
    /// Write ids of repair mints.
    repairs: BTreeSet<WriteId>,
}

impl Sim {
    /// Replicas 1 to `replicas`, with no published file.
    fn new(replicas: usize) -> Self {
        Self {
            run: Run::new(replicas),
            files: (0..replicas).map(|_| Files::default()).collect(),
            written: BTreeSet::new(),
            superseded: BTreeSet::new(),
            observed: BTreeMap::new(),
            repairs: BTreeSet::new(),
        }
    }

    fn play(history: &History) -> Self {
        let mut sim = Self::new(history.replicas);
        sim.apply_all(&history.steps);
        sim
    }

    fn apply_all(&mut self, steps: &[Step]) {
        for step in steps {
            self.apply(step);
        }
    }

    /// Apply `step` as one transaction of its replica. Returns whether the
    /// replica published.
    ///
    /// A join step delivers a past file of the peer, and does nothing if the
    /// peer has published no file. A session end is not a transaction.
    fn apply(&mut self, step: &Step) -> bool {
        match step {
            Step::End { .. } => {
                self.run.apply(step);
                false
            },
            Step::Join {
                replica,
                from,
                version,
            } => match self.files[*from].published.len() {
                0 => false,
                count => self.receive(*replica, *from, version.index(count)),
            },
            _ => self.edit(step),
        }
    }

    /// Run an edit step, record the register values it added and removed,
    /// and publish.
    fn edit(&mut self, step: &Step) -> bool {
        let n = step.replica();
        let state = &self.run.replicas[n].state;
        let context = state.context.clone();
        let before = Register::values(&state.store);
        let mint = self.run.apply(step).expect("edit step mints");
        let after = Register::values(&self.run.replicas[n].state.store);
        self.written.extend(after.difference(&before).copied());
        self.superseded.extend(before.difference(&after).copied());
        self.observed.insert(mint.write_id, context);
        if matches!(step, Step::Repair { .. }) {
            self.repairs.insert(mint.write_id);
        }
        self.publish(n)
    }

    /// Join file `hash` of replica `from` into replica `n` through
    /// `try_join`, and publish.
    ///
    /// Panics if `try_join` refuses or quarantines the file, since every file
    /// of a valid run is valid.
    fn receive(&mut self, n: usize, from: usize, hash: usize) -> bool {
        let file = self.files[from].published[hash].clone();
        let replica = &mut self.run.replicas[n];
        let result = replica.state.try_join(file, &mut replica.session);
        assert!(result.is_ok(), "valid file failed a check: {result:?}");
        replica.record();
        self.publish(n)
    }

    /// Publish the state of replica `n` if `should_publish` holds, then
    /// delete each own file that `should_delete` selects. Returns whether the
    /// replica published.
    fn publish(&mut self, n: usize) -> bool {
        let state = &self.run.replicas[n].state;
        let files = &mut self.files[n];
        let publish = state.context.should_publish(
            &files.published_context,
            files.last_published.as_ref(),
            &files.directory,
        );
        if publish {
            let hash = files.published.len();
            files.published.push(state.clone());
            // Local state holds every write of a file the replica published,
            // so each own file is joined.
            files.directory.push(OwnFile {
                hash,
                state: OwnFileState::Joined,
            });
            files.directory.retain(|file| !file.should_delete(&hash));
            files.published_context = state.context.clone();
            files.last_published = Some(hash);
        }
        publish
    }

    /// Deliver the latest file of every replica to every other replica, in
    /// rounds, until a round publishes nothing.
    ///
    /// Panics if publishing has not stopped after one round per replica and
    /// one more.
    fn converge(&mut self) {
        let replicas = self.files.len();
        for _ in 0..=replicas {
            let mut published = false;
            for n in 0..replicas {
                for from in (0..replicas).filter(|from| *from != n) {
                    if let Some(hash) = self.files[from].last_published {
                        published |= self.receive(n, from, hash);
                    }
                }
            }
            if !published {
                return;
            }
        }
        panic!("publishing did not stop after {} rounds", replicas + 1);
    }

    /// Replica other than `n`, picked by `offset`.
    fn peer(&self, n: usize, offset: Index) -> usize {
        let replicas = self.files.len();
        (n + 1 + offset.index(replicas - 1)) % replicas
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn valid_simulator_runs_pass_every_check(history in History::strategy()) {
        // Each delivery of the history is checked as it is played.
        let mut sim = Sim::play(&history);

        // Every replica receives every file of every other replica.
        for n in 0..history.replicas {
            for from in (0..history.replicas).filter(|from| *from != n) {
                for hash in 0..sim.files[from].published.len() {
                    sim.receive(n, from, hash);
                }
            }
        }
    }

    #[test]
    fn states_are_equal_once_every_replica_has_every_latest_file(
        history in History::strategy(),
    ) {
        let mut sim = Sim::play(&history);

        sim.converge();

        let mut all = State::default();
        for file in sim.files.iter().flat_map(|files| &files.published) {
            all.join(file.clone());
        }
        for replica in &sim.run.replicas {
            prop_assert_eq!(&replica.state, &all);
        }
    }

    #[test]
    fn no_write_is_lost_unless_write_that_observed_it_superseded_it(
        history in History::strategy(),
    ) {
        let mut sim = Sim::play(&history);

        sim.converge();

        let present = Register::values(&sim.run.replicas[0].state.store);
        for value in &sim.written {
            let kept = present.contains(value) || sim.superseded.contains(value);
            prop_assert!(kept, "{value:?} was lost");
        }
        for value in &sim.superseded {
            prop_assert!(!present.contains(value), "{value:?} was superseded and is present");
        }
    }

    #[test]
    fn removal_only_replica_publishes_and_every_replica_applies_removals(
        history in History::strategy(),
        replica in any::<Index>(),
        entries in vec(Entry::strategy(), 1..3),
    ) {
        let mut sim = Sim::play(&history);
        let n = replica.index(history.replicas);
        let before = Register::values(&sim.run.replicas[n].state.store);

        let published = sim.apply(&Step::RemovalOnly { replica: n, entries });

        let local = &sim.run.replicas[n];
        let after = Register::values(&local.state.store);
        let removed: BTreeSet<_> = before.difference(&after).copied().collect();
        let write_id = local.session.last_write().expect("removal-only step mints");
        prop_assert!(published);
        prop_assert!(after.iter().all(|(_, id)| *id != write_id));
        let file = sim.files[n].published.last().expect("replica published");
        prop_assert!(file.context.covers(write_id));

        sim.converge();

        for replica in &sim.run.replicas {
            prop_assert!(replica.state.context.covers(write_id));
            let values = Register::values(&replica.state.store);
            prop_assert!(values.is_disjoint(&removed), "removed value is present");
        }
    }

    #[test]
    fn each_replica_publishes_when_context_is_ahead_and_publishing_stops_without_edits(
        history in History::strategy(),
        deliveries in vec((any::<Index>(), any::<Index>(), any::<Index>()), 0..16),
    ) {
        let mut sim = Sim::new(history.replicas);
        for step in &history.steps {
            let n = step.replica();
            let before = sim.run.replicas[n].state.context.clone();

            let published = sim.apply(step);

            // Transaction that advanced the context published, including one
            // that only joined, and no other transaction published.
            let context = &sim.run.replicas[n].state.context;
            prop_assert_eq!(published, *context != before);
            prop_assert_eq!(&sim.files[n].published_context, context);
            // Older own files are deleted after each publish.
            let files = &sim.files[n];
            let hashes: Vec<_> = files.directory.iter().map(|file| file.hash).collect();
            prop_assert_eq!(hashes, Vec::from_iter(files.last_published));
        }

        // Converge panics if publishing does not stop.
        sim.converge();

        // Without edits, no delivery of any past file publishes.
        for (replica, offset, version) in deliveries {
            let n = replica.index(history.replicas);
            let from = sim.peer(n, offset);
            let count = sim.files[from].published.len();
            if count > 0 {
                prop_assert!(!sim.receive(n, from, version.index(count)));
            }
        }
        for (replica, files) in sim.run.replicas.iter().zip(&sim.files) {
            prop_assert_eq!(&files.published_context, &replica.state.context);
        }
    }

    #[test]
    fn replica_whose_clock_is_behind_does_not_win_order_register_against_joined_value(
        history in History::strategy(),
        slow in any::<Index>(),
        behind in 1..=NOW,
    ) {
        let n = slow.index(history.replicas);
        let mut sim = Sim::new(history.replicas);
        sim.run.replicas[n].now = NOW - behind;
        sim.apply_all(&history.steps);
        sim.converge();
        let mut on_time = Sim::play(&history);
        on_time.converge();

        // Clock changes no write id, counter, or order of any register.
        let state = &sim.run.replicas[0].state;
        let registers = Register::all(&state.store);
        prop_assert_eq!(&registers, &Register::all(&on_time.run.replicas[0].state.store));

        // No Order register shows a write of the slow replica above a value
        // of another replica that the write had observed. Repair values are
        // concurrent with the values of their register by definition, so
        // they are not checked.
        let replica = sim.run.replicas[n].session.replica;
        let slow_write = |id: WriteId| state.actors[&id.actor].replica == replica;
        for (target, register) in &registers {
            let top = register.keys.last().expect("register holds a value");
            let checked = register.kind == PolicyKind::Order
                && slow_write(top.write_id)
                && !sim.repairs.contains(&top.write_id);
            if !checked {
                continue;
            }
            let observed = &sim.observed[&top.write_id];
            for key in &register.keys {
                let joined = !slow_write(key.write_id) && observed.covers(key.write_id);
                prop_assert!(!joined, "{target:?}: {top:?} orders above joined {key:?}");
            }
        }
    }
}
