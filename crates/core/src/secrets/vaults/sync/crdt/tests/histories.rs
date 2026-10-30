//! Random valid histories and the runs that play them. Shared by the property
//! tests and the simulator.
//!
//! A history runs mints with writes and removes, repair writes, removal-only
//! mints, joins through `try_join`, and session ends across 2 to 4 replicas.
//! Every state a replica held is kept as a version, and a join takes any past
//! version of another replica.

use proptest::collection::vec;
use proptest::prelude::*;
use proptest::sample::{Index, select};

use super::*;

/// Item keys of generated writes and removes.
const ITEMS: std::ops::RangeInclusive<u32> = 1..=3;
/// History entry keys of an item.
const HISTORY: std::ops::RangeInclusive<u32> = 1..=2;
/// Signal keys of the vault.
const SIGNALS: std::ops::RangeInclusive<u32> = 1..=3;
const SITES: &[&str] = &["a.com", "b.com"];
const NAMES: &[&str] = &["Work", "Home"];
const TITLES: &[&str] = &["Mail", "Bank", "Shop", "Gym"];

/// Register that a generated write sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Target {
    Name,
    Title(u32),
    Folder(u32),
    Website(u32, &'static str),
    Trashed(u32),
    History(u32, u32),
    Signal(u32),
}

impl Target {
    pub(super) fn strategy() -> impl Strategy<Value = Self> {
        prop_oneof![
            Just(Self::Name),
            ITEMS.prop_map(Self::Title),
            ITEMS.prop_map(Self::Folder),
            (ITEMS, select(SITES)).prop_map(|(key, site)| Self::Website(key, site)),
            ITEMS.prop_map(Self::Trashed),
            (ITEMS, HISTORY).prop_map(|(key, entry)| Self::History(key, entry)),
            SIGNALS.prop_map(Self::Signal),
        ]
    }

    /// Write a value picked by `value` with `mint`. A repair write leaves the
    /// other values of the register.
    pub(super) fn write(self, store: &mut Vault, mint: &Mint, value: u8, repair: bool) {
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
            Self::History(key, entry) => Self::put(
                store.items.entry(key).history.entry(entry),
                mint,
                TITLES[index % TITLES.len()],
                repair,
            ),
            Self::Signal(key) => {
                Self::put(store.signals.entry(key), mint, i64::from(value), repair);
            },
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

/// Map entry that a generated remove drops. A purge removes an item, a
/// history purge a history entry, and a signal trim a signal.
#[derive(Clone, Copy, Debug)]
pub(super) enum Entry {
    Item(u32),
    Website(u32, &'static str),
    History(u32, u32),
    Signal(u32),
}

impl Entry {
    pub(super) fn strategy() -> impl Strategy<Value = Self> {
        prop_oneof![
            ITEMS.prop_map(Self::Item),
            (ITEMS, select(SITES)).prop_map(|(key, site)| Self::Website(key, site)),
            (ITEMS, HISTORY).prop_map(|(key, entry)| Self::History(key, entry)),
            SIGNALS.prop_map(Self::Signal),
        ]
    }

    pub(super) fn remove(self, store: &mut Vault) {
        match self {
            Self::Item(key) => {
                store.items.remove(&key);
            },
            Self::Website(key, site) => {
                store.items.entry(key).websites.remove(&site);
            },
            Self::History(key, entry) => {
                store.items.entry(key).history.remove(&entry);
            },
            Self::Signal(key) => {
                store.signals.remove(&key);
            },
        }
    }
}

/// Edit of a mint with writes.
#[derive(Clone, Copy, Debug)]
pub(super) enum Edit {
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
pub(super) enum Step {
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

    pub(super) fn replica(&self) -> usize {
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
pub(super) struct History {
    pub(super) replicas: usize,
    pub(super) steps: Vec<Step>,
}

impl History {
    pub(super) fn strategy() -> impl Strategy<Value = Self> {
        (2..=4usize).prop_flat_map(|replicas| {
            vec(Step::strategy(replicas), 0..24).prop_map(move |steps| Self { replicas, steps })
        })
    }
}

/// Replica of a history, with every state it held.
pub(super) struct Replica {
    pub(super) session: Session,
    pub(super) state: State,
    pub(super) versions: Vec<State>,
    /// Time of each mint, by the replica clock.
    pub(super) now: i64,
}

impl Replica {
    pub(super) fn mint(&mut self) -> Mint {
        self.session.mint(&mut self.state, self.now)
    }

    /// Record the state as a version. Entries that a remove left empty are
    /// dropped first, as a join drops them.
    pub(super) fn record(&mut self) {
        self.state.join(State::default());
        self.versions.push(self.state.clone());
    }
}

/// Replicas of a history as it is played.
pub(super) struct Run {
    pub(super) replicas: Vec<Replica>,
}

impl Run {
    /// Replicas 1 to `replicas`, each with the empty state as first version
    /// and its clock at `NOW`.
    pub(super) fn new(replicas: usize) -> Self {
        let replicas = (1..=replicas as u128)
            .map(|n| Replica {
                session: session(n),
                state: State::default(),
                versions: vec![State::default()],
                now: NOW,
            })
            .collect();
        Self { replicas }
    }

    pub(super) fn play(history: &History) -> Self {
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
    pub(super) fn apply(&mut self, step: &Step) -> Option<Mint> {
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
    pub(super) fn states(&self) -> Vec<&State> {
        self.replicas.iter().flat_map(|r| &r.versions).collect()
    }

    /// Every version of every replica other than `replica`.
    pub(super) fn others(&self, replica: usize) -> Vec<&State> {
        self.replicas
            .iter()
            .enumerate()
            .filter(|(n, _)| *n != replica)
            .flat_map(|(_, r)| &r.versions)
            .collect()
    }
}
