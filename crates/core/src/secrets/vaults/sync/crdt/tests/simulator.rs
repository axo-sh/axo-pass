//! Simulator of Macs that publish their states as files and join the files of
//! their peers.
//!
//! Each Mac holds one replica of a random valid history from `histories.rs`.
//! Each step other than a session end is one transaction. A transaction joins
//! the own files of the replica first, as step 1 of "Join" in the plan. A join
//! step is a delivery, which hands the Mac any past file of the peer, so files
//! arrive in any order, and some arrive twice or never. Every join goes
//! through `try_join`. After each transaction the Mac publishes by
//! `CausalContext::should_publish` and deletes its older files by
//! `OwnFile::should_delete`. A published file is a clone of the state.
//!
//! The failures of `failures.rs` change replica ids, replace sync states,
//! delete directories, and add torn and forged files.

use std::collections::{BTreeMap, BTreeSet};

use proptest::collection::vec;
use proptest::prelude::*;
use proptest::sample::Index;

use super::histories::{Entry, History, Run, Step, Target};
use super::*;

/// Policy and order keys of one register, lowest key first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Register {
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
    pub(super) fn values(store: &Vault) -> BTreeSet<(Target, WriteId)> {
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

/// File in the synced folder. Its index in [`Sim::files`] is its content
/// hash.
pub(super) struct File {
    /// Index of the Mac that wrote the file.
    pub(super) mac: usize,
    /// Directory of the file, the replica id it was published under.
    pub(super) replica: ReplicaId,
    /// State of the file. None for a torn file, which fails to decode.
    pub(super) state: Option<State>,
    /// Not in its directory. Its owner deleted it after a publish, or its
    /// directory was deleted.
    pub(super) removed: bool,
    /// Removed with its directory. A lost file is not delivered. A file its
    /// owner deleted is still delivered, as a stale copy.
    pub(super) lost: bool,
    /// Not downloaded on the Mac that wrote it.
    pub(super) remote: bool,
}

/// Local sync state of a Mac, as saved after a transaction.
#[derive(Clone)]
pub(super) struct Backup {
    pub(super) replica: ReplicaId,
    pub(super) state: State,
    pub(super) published_context: CausalContext,
    pub(super) last_published: Option<usize>,
    /// Number of files in the folder when the backup was saved.
    pub(super) files: usize,
}

/// Publish record and backups of one Mac.
pub(super) struct Mac {
    /// Context of the last published file.
    pub(super) published_context: CausalContext,
    /// Hash of the last published file.
    pub(super) last_published: Option<usize>,
    /// Local sync state after each transaction, oldest first.
    pub(super) backups: Vec<Backup>,
    /// Replica ids whose directory holds a file of this Mac.
    pub(super) directories: Vec<ReplicaId>,
    /// Directory of the last publish was deleted, so the next transaction
    /// must publish.
    pub(super) republish: bool,
}

/// Macs of a history, with the synced folder and a record of every edit.
pub(super) struct Sim {
    /// Session, state, and clock of each Mac.
    pub(super) run: Run,
    pub(super) macs: Vec<Mac>,
    pub(super) files: Vec<File>,
    /// Register values that edits added.
    pub(super) written: BTreeSet<(Target, WriteId)>,
    /// Register values that edits replaced or removed on a Mac that held
    /// them.
    pub(super) superseded: BTreeSet<(Target, WriteId)>,
    /// Context of the state before each mint, by write id of the mint.
    observed: BTreeMap<WriteId, CausalContext>,
    /// Write ids of repair mints.
    repairs: BTreeSet<WriteId>,
    /// Write id of every mint.
    minted: BTreeSet<WriteId>,
    /// Checks that files failed in `try_join`, with the receiving Mac and
    /// the file hash.
    pub(super) errors: Vec<(usize, usize, JoinError)>,
    /// Panic if a file fails a check. Set for valid runs.
    pub(super) strict: bool,
    /// Next replica id given to a Mac by a failure.
    pub(super) next_replica_id: u128,
}

impl Sim {
    /// Macs 1 to `macs`, with no file in the folder.
    pub(super) fn new(macs: usize) -> Self {
        let run = Run::new(macs);
        let macs = run
            .replicas
            .iter()
            .map(|replica| Mac {
                published_context: CausalContext::default(),
                last_published: None,
                backups: vec![Backup {
                    replica: replica.session.replica,
                    state: State::default(),
                    published_context: CausalContext::default(),
                    last_published: None,
                    files: 0,
                }],
                directories: Vec::new(),
                republish: false,
            })
            .collect();
        Self {
            run,
            macs,
            files: Vec::new(),
            written: BTreeSet::new(),
            superseded: BTreeSet::new(),
            observed: BTreeMap::new(),
            repairs: BTreeSet::new(),
            minted: BTreeSet::new(),
            errors: Vec::new(),
            strict: true,
            next_replica_id: 1_000,
        }
    }

    pub(super) fn play(history: &History) -> Self {
        let mut sim = Self::new(history.replicas);
        sim.apply_all(&history.steps);
        sim
    }

    fn apply_all(&mut self, steps: &[Step]) {
        for step in steps {
            self.apply(step);
        }
    }

    /// Current replica id of Mac `n`.
    pub(super) fn replica(&self, n: usize) -> ReplicaId {
        self.run.replicas[n].session.replica
    }

    /// Hashes of the files in the directory of `replica`.
    pub(super) fn directory(&self, replica: ReplicaId) -> Vec<usize> {
        (0..self.files.len())
            .filter(|hash| {
                let file = &self.files[*hash];
                file.replica == replica && !file.removed
            })
            .collect()
    }

    /// Hashes of the files of Mac `from` that can be delivered.
    pub(super) fn deliverable(&self, from: usize) -> Vec<usize> {
        (0..self.files.len())
            .filter(|hash| {
                let file = &self.files[*hash];
                file.mac == from && !file.lost
            })
            .collect()
    }

    /// Apply `step` as one transaction of its Mac. Returns whether the Mac
    /// published.
    ///
    /// A join step delivers a past file of the peer, and does nothing if the
    /// peer has no file. A session end is not a transaction.
    pub(super) fn apply(&mut self, step: &Step) -> bool {
        match step {
            Step::End { .. } => {
                self.run.apply(step);
                false
            },
            Step::Join {
                replica,
                from,
                version,
            } => {
                let files = self.deliverable(*from);
                match files.len() {
                    0 => false,
                    count => self.receive(*replica, files[version.index(count)]),
                }
            },
            _ => {
                let n = step.replica();
                let own = self.join_own_files(n);
                self.edit(step);
                self.publish(n, own)
            },
        }
    }

    /// Transaction of Mac `n` with no edit and no delivery.
    pub(super) fn transaction(&mut self, n: usize) -> bool {
        let own = self.join_own_files(n);
        self.run.replicas[n].record();
        self.publish(n, own)
    }

    /// Transaction of Mac `n` that receives file `hash`.
    pub(super) fn receive(&mut self, n: usize, hash: usize) -> bool {
        let own = self.join_own_files(n);
        self.join_file(n, hash);
        self.run.replicas[n].record();
        self.publish(n, own)
    }

    /// Join each own file of Mac `n` that is downloaded and decodes. Returns
    /// the own files as the publish rules take them.
    fn join_own_files(&mut self, n: usize) -> Vec<OwnFile<usize>> {
        let mut own = Vec::new();
        for hash in self.directory(self.replica(n)) {
            let file = &self.files[hash];
            let state = if file.remote {
                OwnFileState::Remote
            } else if file.state.is_some() && self.join_file(n, hash) {
                OwnFileState::Joined
            } else {
                OwnFileState::NotJoined
            };
            own.push(OwnFile { hash, state });
        }
        own
    }

    /// Join file `hash` into Mac `n` through `try_join`. Returns whether the
    /// file passed every check. A torn file fails to decode and is not joined.
    ///
    /// Panics on a failed check if the run is strict.
    fn join_file(&mut self, n: usize, hash: usize) -> bool {
        let Some(file) = self.files[hash].state.clone() else {
            return false;
        };
        let replica = &mut self.run.replicas[n];
        match replica.state.try_join(file, &mut replica.session) {
            Ok(_) => true,
            Err(err) => {
                assert!(!self.strict, "valid file failed a check: {err:?}");
                self.errors.push((n, hash, err));
                false
            },
        }
    }

    /// Run an edit step and record the register values it added and removed.
    ///
    /// Panics if the mint reuses a write id.
    fn edit(&mut self, step: &Step) {
        let n = step.replica();
        let state = &self.run.replicas[n].state;
        let context = state.context.clone();
        let before = Register::values(&state.store);
        let mint = self.run.apply(step).expect("edit step mints");
        let after = Register::values(&self.run.replicas[n].state.store);
        assert!(
            self.minted.insert(mint.write_id),
            "write id {:?} was minted twice",
            mint.write_id
        );
        self.written.extend(after.difference(&before).copied());
        self.superseded.extend(before.difference(&after).copied());
        self.observed.insert(mint.write_id, context);
        if matches!(step, Step::Repair { .. }) {
            self.repairs.insert(mint.write_id);
        }
    }

    /// Publish the state of Mac `n` if `should_publish` holds, then delete
    /// each own file that `should_delete` selects, and save a backup. Returns
    /// whether the Mac published.
    ///
    /// Panics if a Mac does not publish after its directory was deleted, or
    /// deletes an own file whose writes its state does not hold.
    fn publish(&mut self, n: usize, own: Vec<OwnFile<usize>>) -> bool {
        let replica = self.replica(n);
        let state = &self.run.replicas[n].state;
        let mac = &mut self.macs[n];
        let publish =
            state
                .context
                .should_publish(&mac.published_context, mac.last_published.as_ref(), &own);
        assert!(publish || !mac.republish, "Mac {n} did not republish");
        if publish {
            let hash = self.files.len();
            self.files.push(File {
                mac: n,
                replica,
                state: Some(state.clone()),
                removed: false,
                lost: false,
                remote: false,
            });
            for file in own.iter().filter(|file| file.should_delete(&hash)) {
                let deleted = &mut self.files[file.hash];
                let covered = deleted
                    .state
                    .as_ref()
                    .is_some_and(|joined| !joined.context.is_ahead_of(&state.context));
                assert!(
                    covered,
                    "own file {} deleted before it was joined",
                    file.hash
                );
                deleted.removed = true;
            }
            mac.published_context = state.context.clone();
            mac.last_published = Some(hash);
            mac.republish = false;
            if !mac.directories.contains(&replica) {
                mac.directories.push(replica);
            }
        }
        mac.backups.push(Backup {
            replica,
            state: state.clone(),
            published_context: mac.published_context.clone(),
            last_published: mac.last_published,
            files: self.files.len(),
        });
        publish
    }

    /// Every file in a directory that decodes. A directory can hold older
    /// files that its latest file does not cover, such as own files that
    /// were `Remote` at a publish.
    fn present_files(&self) -> Vec<usize> {
        (0..self.files.len())
            .filter(|hash| {
                let file = &self.files[*hash];
                !file.removed && file.state.is_some()
            })
            .collect()
    }

    /// Download every file, then run rounds until a round publishes nothing.
    /// A round runs a transaction with no edit on every Mac, as at an unlock,
    /// then delivers every file in every directory to every Mac of another
    /// replica.
    ///
    /// Panics if publishing has not stopped after one round per Mac and two
    /// more.
    pub(super) fn converge(&mut self) {
        for file in &mut self.files {
            file.remote = false;
        }
        let rounds = self.macs.len() + 2;
        for _ in 0..rounds {
            let mut published = false;
            for n in 0..self.macs.len() {
                published |= self.transaction(n);
            }
            for hash in self.present_files() {
                for n in 0..self.macs.len() {
                    if self.files[hash].replica != self.replica(n) {
                        published |= self.receive(n, hash);
                    }
                }
            }
            if !published {
                return;
            }
        }
        panic!("publishing did not stop after {rounds} rounds");
    }

    /// Mac other than `n`, picked by `offset`.
    pub(super) fn peer(&self, n: usize, offset: Index) -> usize {
        let macs = self.macs.len();
        (n + 1 + offset.index(macs - 1)) % macs
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
            for hash in 0..sim.files.len() {
                if sim.files[hash].mac != n {
                    sim.receive(n, hash);
                }
            }
        }
    }

    #[test]
    fn states_are_equal_once_every_replica_has_every_file(
        history in History::strategy(),
    ) {
        let mut sim = Sim::play(&history);

        sim.converge();

        let mut all = State::default();
        for file in sim.files.iter().filter_map(|file| file.state.as_ref()) {
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
        let hash = sim.macs[n].last_published.expect("replica published");
        let file = sim.files[hash].state.as_ref().expect("published file decodes");
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
            prop_assert_eq!(&sim.macs[n].published_context, context);
            // Older own files are deleted after each publish.
            let hashes = sim.directory(sim.replica(n));
            prop_assert_eq!(hashes, Vec::from_iter(sim.macs[n].last_published));
        }

        // Converge panics if publishing does not stop.
        sim.converge();

        // Without edits, no delivery of any past file publishes.
        for (replica, offset, version) in deliveries {
            let n = replica.index(history.replicas);
            let files = sim.deliverable(sim.peer(n, offset));
            if !files.is_empty() {
                prop_assert!(!sim.receive(n, files[version.index(files.len())]));
            }
        }
        for (replica, mac) in sim.run.replicas.iter().zip(&sim.macs) {
            prop_assert_eq!(&mac.published_context, &replica.state.context);
        }
    }

    #[test]
    fn lagging_clock_loses_to_joined_value(
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
        let replica = sim.replica(n);
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
