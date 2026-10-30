//! Simulator runs with failures: replaced sync states, own files that are
//! stale, remote, or missing, clocks set back, regenerated replica ids,
//! re-links, deleted directories, torn files, and forged states.
//!
//! A failure happens between two steps of a history and is not a
//! transaction. The simulator is in `simulator.rs`.

use std::collections::BTreeSet;

use proptest::collection::vec;
use proptest::prelude::*;
use proptest::sample::Index;
use uuid::Uuid;

use super::histories::{Edit, History, Step, Target};
use super::simulator::{File, Register, Sim};
use super::*;

/// Failure on the Mac at index `mac`.
#[derive(Clone, Debug)]
enum Fault {
    /// Replace the local sync state and publish record with a past backup.
    /// `detected` ends the session, as at a launch or a detected replacement.
    /// Otherwise the session continues. `remote` leaves the own files written
    /// after the backup not downloaded. `clock_back` sets the clock back by
    /// one hour.
    Restore {
        mac: usize,
        backup: Index,
        detected: bool,
        remote: bool,
        clock_back: bool,
    },
    /// Download every own file.
    Arrive { mac: usize },
    /// New replica id, with the sync state kept.
    Regenerate { mac: usize },
    /// Re-link under a new replica id, with an empty sync state.
    Relink { mac: usize },
    /// Delete one directory that holds a file of the Mac.
    DeleteDirectory { mac: usize, directory: Index },
    /// Torn file in the current directory of the Mac.
    Tear { mac: usize },
}

impl Fault {
    fn strategy(macs: usize) -> impl Strategy<Value = Self> {
        prop_oneof![
            4 => (0..macs, any::<Index>(), any::<bool>(), any::<bool>(), any::<bool>()).prop_map(
                |(mac, backup, detected, remote, clock_back)| Self::Restore {
                    mac,
                    backup,
                    detected,
                    remote,
                    clock_back,
                },
            ),
            2 => (0..macs).prop_map(|mac| Self::Arrive { mac }),
            1 => (0..macs).prop_map(|mac| Self::Regenerate { mac }),
            1 => (0..macs).prop_map(|mac| Self::Relink { mac }),
            1 => (0..macs, any::<Index>())
                .prop_map(|(mac, directory)| Self::DeleteDirectory { mac, directory }),
            1 => (0..macs).prop_map(|mac| Self::Tear { mac }),
        ]
    }
}

/// History with failures. A failure happens before the step at its
/// position, or after the last step.
#[derive(Clone, Debug)]
struct Scenario {
    history: History,
    faults: Vec<(Index, Fault)>,
}

impl Scenario {
    fn strategy() -> impl Strategy<Value = Self> {
        History::strategy().prop_flat_map(|history| {
            let faults = vec((any::<Index>(), Fault::strategy(history.replicas)), 0..6);
            (Just(history), faults).prop_map(|(history, faults)| Self { history, faults })
        })
    }

    /// Scenario with a torn file of the Mac picked by each pair, at the
    /// position picked by the pair.
    fn with_torn_files(mut self, torn: &[(Index, Index)]) -> Self {
        for (at, mac) in torn {
            let mac = mac.index(self.history.replicas);
            self.faults.push((*at, Fault::Tear { mac }));
        }
        self
    }
}

impl Sim {
    fn play_scenario(scenario: &Scenario) -> Self {
        let steps = &scenario.history.steps;
        let mut faults: Vec<_> = scenario
            .faults
            .iter()
            .map(|(at, fault)| (at.index(steps.len() + 1), fault))
            .collect();
        faults.sort_by_key(|(at, _)| *at);
        let mut faults = faults.into_iter().peekable();
        let mut sim = Self::new(scenario.history.replicas);
        for (n, step) in steps.iter().enumerate() {
            while let Some((_, fault)) = faults.next_if(|(at, _)| *at == n) {
                sim.fault(fault);
            }
            sim.apply(step);
        }
        for (_, fault) in faults {
            sim.fault(fault);
        }
        sim
    }

    fn fault(&mut self, fault: &Fault) {
        match *fault {
            Fault::Restore {
                mac,
                backup,
                detected,
                remote,
                clock_back,
            } => {
                let backup = backup.index(self.macs[mac].backups.len());
                self.restore(mac, backup, detected, remote, clock_back);
            },
            Fault::Arrive { mac } => {
                for file in self.files.iter_mut().filter(|file| file.mac == mac) {
                    file.remote = false;
                }
            },
            Fault::Regenerate { mac } => {
                let replica = self.new_replica_id();
                let session = &mut self.run.replicas[mac].session;
                session.end();
                session.replica = replica;
            },
            Fault::Relink { mac } => {
                let replica = self.new_replica_id();
                let local = &mut self.run.replicas[mac];
                local.session.end();
                local.session.replica = replica;
                local.state = State::default();
                let mac = &mut self.macs[mac];
                mac.published_context = CausalContext::default();
                mac.last_published = None;
                mac.republish = false;
            },
            Fault::DeleteDirectory { mac, directory } => {
                let directories = &self.macs[mac].directories;
                if !directories.is_empty() {
                    let replica = *directory.get(directories);
                    self.delete_directory(replica);
                }
            },
            Fault::Tear { mac } => {
                let replica = self.replica(mac);
                self.files.push(File {
                    mac,
                    replica,
                    state: None,
                    removed: false,
                    lost: false,
                    remote: false,
                });
                let directories = &mut self.macs[mac].directories;
                if !directories.contains(&replica) {
                    directories.push(replica);
                }
            },
        }
    }

    /// Replace the sync state and publish record of Mac `n` with backup
    /// `backup`. A backup of another replica id ends the session.
    fn restore(&mut self, n: usize, backup: usize, detected: bool, remote: bool, clock_back: bool) {
        let backup = self.macs[n].backups[backup].clone();
        let local = &mut self.run.replicas[n];
        if detected || local.session.replica != backup.replica {
            local.session.end();
        }
        local.session.replica = backup.replica;
        local.state = backup.state;
        if clock_back {
            local.now -= 3_600;
        }
        let mac = &mut self.macs[n];
        mac.published_context = backup.published_context;
        mac.last_published = backup.last_published;
        mac.republish = false;
        if remote {
            for file in self.files.iter_mut().skip(backup.files) {
                if file.mac == n && file.replica == backup.replica {
                    file.remote = true;
                }
            }
        }
    }

    /// Delete the directory of `replica`. The Mac that publishes under it
    /// must republish in its next transaction.
    fn delete_directory(&mut self, replica: ReplicaId) {
        for file in self.files.iter_mut().filter(|file| file.replica == replica) {
            file.removed = true;
            file.lost = true;
        }
        for n in 0..self.macs.len() {
            if self.replica(n) == replica && self.macs[n].last_published.is_some() {
                self.macs[n].republish = true;
            }
        }
    }

    fn new_replica_id(&mut self) -> ReplicaId {
        self.next_replica_id += 1;
        ReplicaId(Uuid::from_u128(self.next_replica_id))
    }

    /// File of Mac `n` that holds its state changed by `forge`, in its
    /// current directory. Returns the hash of the file.
    fn forge(&mut self, n: usize, forge: impl FnOnce(&mut State)) -> usize {
        let mut state = self.run.replicas[n].state.clone();
        forge(&mut state);
        self.files.push(File {
            mac: n,
            replica: self.replica(n),
            state: Some(state),
            removed: false,
            lost: false,
            remote: false,
        });
        self.files.len() - 1
    }

    /// Register values of every file that is not lost and of every Mac state.
    fn held(&self) -> BTreeSet<(Target, WriteId)> {
        let files = self
            .files
            .iter()
            .filter(|file| !file.lost)
            .filter_map(|file| file.state.as_ref());
        let states = self.run.replicas.iter().map(|replica| &replica.state);
        files
            .chain(states)
            .flat_map(|state| Register::values(&state.store))
            .collect()
    }

    /// Fail the case if a value of `held` is in no Mac state and was not
    /// replaced or removed by an edit on a Mac that held it.
    fn check_kept(&self, held: &BTreeSet<(Target, WriteId)>) -> Result<(), TestCaseError> {
        for replica in &self.run.replicas {
            let present = Register::values(&replica.state.store);
            for value in held {
                let kept = present.contains(value) || self.superseded.contains(value);
                prop_assert!(kept, "{value:?} was lost");
            }
        }
        Ok(())
    }

    /// Fail the case if two Macs hold different states.
    fn check_equal(&self) -> Result<(), TestCaseError> {
        let first = &self.run.replicas[0].state;
        for replica in &self.run.replicas {
            prop_assert_eq!(&replica.state, first);
        }
        Ok(())
    }

    /// Edit step of Mac `n` that writes the name register.
    fn write_name(&mut self, n: usize) -> bool {
        let edits = vec![Edit::Write(Target::Name, 0)];
        self.apply(&Step::Write { replica: n, edits })
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn valid_runs_with_failures_pass_every_check_and_reuse_no_write_id(
        scenario in Scenario::strategy(),
    ) {
        // The run is strict, so a failed check or a write id minted twice
        // fails the case.
        let mut sim = Sim::play_scenario(&scenario);

        sim.converge();
    }

    #[test]
    fn states_are_equal_after_failures_once_every_replica_has_every_file(
        scenario in Scenario::strategy(),
    ) {
        let mut sim = Sim::play_scenario(&scenario);

        sim.converge();

        sim.check_equal()?;
    }

    #[test]
    fn no_write_that_any_file_or_state_holds_is_lost_after_failures(
        scenario in Scenario::strategy(),
    ) {
        let mut sim = Sim::play_scenario(&scenario);
        let held = sim.held();

        sim.converge();

        sim.check_kept(&held)?;
    }

    #[test]
    fn remote_own_file_is_joined_when_it_arrives_and_not_deleted_before(
        history in History::strategy(),
        mac in any::<Index>(),
        others in vec((any::<Index>(), any::<Index>()), 0..8),
    ) {
        let mut sim = Sim::play(&history);
        let n = mac.index(history.replicas);
        sim.write_name(n);
        let hash = sim.macs[n].last_published.expect("edit publishes");
        // Backup from before the write. Own files written after it are
        // remote.
        let backup = sim.macs[n].backups.len() - 2;
        sim.restore(n, backup, true, true, false);

        // Mac edits and receives files while the newer own file is remote.
        for (offset, version) in others {
            let files = sim.deliverable(sim.peer(n, offset));
            if !files.is_empty() {
                sim.receive(n, files[version.index(files.len())]);
            }
            sim.write_name(n);
            prop_assert!(!sim.files[hash].removed, "remote own file was deleted");
        }

        sim.fault(&Fault::Arrive { mac: n });
        let published = sim.transaction(n);

        let file = sim.files[hash].state.as_ref().expect("published file decodes");
        prop_assert!(!file.context.is_ahead_of(&sim.run.replicas[n].state.context));
        prop_assert_eq!(sim.files[hash].removed, published);
    }

    #[test]
    fn earlier_actor_writes_above_local_context_are_joined_after_restore(
        history in History::strategy(),
        mac in any::<Index>(),
        peer in any::<Index>(),
    ) {
        let mut sim = Sim::play(&history);
        let n = mac.index(history.replicas);
        let p = sim.peer(n, peer);
        sim.write_name(n);
        let write_id = sim.run.replicas[n].session.last_write().expect("edit mints");
        let hash = sim.macs[n].last_published.expect("edit publishes");
        sim.receive(p, hash);
        let backup = sim.macs[n].backups.len() - 2;
        sim.restore(n, backup, true, true, false);
        prop_assert!(!sim.run.replicas[n].state.context.covers(write_id));

        // Strict run, so the peer file passes every check.
        let peer_file = sim.macs[p].last_published.expect("peer published");
        sim.receive(n, peer_file);

        let state = &sim.run.replicas[n].state;
        prop_assert!(state.store.name.get(write_id).is_some());
        sim.write_name(n);
        let next = sim.run.replicas[n].session.last_write().expect("edit mints");
        prop_assert_ne!(next.actor, write_id.actor);
    }

    #[test]
    fn relinked_replica_restored_to_old_sync_state_publishes_under_old_id(
        history in History::strategy(),
        mac in any::<Index>(),
        backup in any::<Index>(),
    ) {
        let mut sim = Sim::play(&history);
        let n = mac.index(history.replicas);
        let old = sim.replica(n);
        let backups: Vec<_> = (0..sim.macs[n].backups.len())
            .filter(|b| sim.macs[n].backups[*b].replica == old)
            .collect();
        sim.fault(&Fault::Relink { mac: n });
        let new = sim.replica(n);
        sim.write_name(n);

        sim.restore(n, *backup.get(&backups), true, false, false);
        let published = sim.write_name(n);

        let hash = sim.macs[n].last_published.expect("edit publishes");
        prop_assert!(published);
        prop_assert_eq!(sim.files[hash].replica, old);
        let held = sim.held();
        sim.converge();
        sim.check_kept(&held)?;
        sim.check_equal()?;
        // New replica id converges as a retired replica.
        let retired: Vec<_> = sim.directory(new);
        prop_assert!(!retired.is_empty());
        let state = &sim.run.replicas[n].state;
        for hash in retired {
            let file = sim.files[hash].state.as_ref().expect("published file decodes");
            prop_assert!(!file.context.is_ahead_of(&state.context));
        }
    }

    #[test]
    fn live_replica_whose_directory_was_deleted_republishes_without_local_edit(
        scenario in Scenario::strategy(),
        mac in any::<Index>(),
    ) {
        let mut sim = Sim::play_scenario(&scenario);
        let n = mac.index(scenario.history.replicas);
        sim.write_name(n);

        sim.delete_directory(sim.replica(n));
        // Writes that only the deleted directory held can be lost.
        let held = sim.held();
        let published = sim.transaction(n);

        prop_assert!(published);
        let hashes = sim.directory(sim.replica(n));
        prop_assert_eq!(hashes, Vec::from_iter(sim.macs[n].last_published));
        sim.converge();
        sim.check_kept(&held)?;
    }

    #[test]
    fn torn_file_is_never_deleted_and_stops_no_other_file_from_joining(
        scenario in Scenario::strategy(),
        torn in vec((any::<Index>(), any::<Index>()), 1..4),
    ) {
        let scenario = scenario.with_torn_files(&torn);
        let mut sim = Sim::play_scenario(&scenario);

        sim.converge();

        for file in sim.files.iter().filter(|file| file.state.is_none()) {
            // Torn file is removed only with its directory.
            prop_assert_eq!(file.removed, file.lost);
        }
        sim.check_equal()?;
    }

    #[test]
    fn state_claiming_session_actor_is_refused_and_no_later_write_is_lost(
        history in History::strategy(),
        target in any::<Index>(),
        forger in any::<Index>(),
        above in 1..=3u64,
    ) {
        let mut sim = Sim::play(&history);
        let t = target.index(history.replicas);
        let f = sim.peer(t, forger);
        sim.write_name(t);
        let last = sim.run.replicas[t].session.last_write().expect("edit mints");
        sim.strict = false;
        let claim = WriteId { seq: last.seq + above, ..last };
        let hash = sim.forge(f, |state| state.context.record(claim));

        sim.receive(t, hash);

        let refused = sim.errors.last().is_some_and(|(m, h, err)| {
            *m == t && *h == hash && matches!(err, JoinError::SessionActorClaimed { .. })
        });
        prop_assert!(refused, "claim was not refused: {:?}", sim.errors);
        prop_assert_eq!(sim.run.replicas[t].session.actor(), None);
        sim.write_name(t);
        let next = sim.run.replicas[t].session.last_write().expect("edit mints");
        prop_assert_ne!(next.actor, last.actor);

        sim.converge();

        // Writes of the ended actor that the forged state lacks can be
        // dropped (D10). Writes after the refusal are kept on every Mac.
        for replica in &sim.run.replicas {
            prop_assert!(replica.state.store.name.get(next).is_some(), "{next:?} was lost");
        }
    }

    #[test]
    fn one_write_id_with_two_values_quarantines_state_that_brings_second_on_every_replica(
        history in History::strategy(),
        writer in any::<Index>(),
        forger in any::<Index>(),
        forged_first in vec(any::<bool>(), 4),
    ) {
        let mut sim = Sim::play(&history);
        let a = writer.index(history.replicas);
        let f = sim.peer(a, forger);
        sim.write_name(a);
        let original = sim.macs[a].last_published.expect("edit publishes");
        let local = &sim.run.replicas[a].state;
        let write_id = sim.run.replicas[a].session.last_write().expect("edit mints");
        let value = local.store.name.get(write_id).expect("name holds the write").clone();
        let info = local.actors[&write_id.actor];
        sim.strict = false;
        let mint = Mint { write_id, counter: value.counter, written_at: value.written_at };
        let forged = sim.forge(f, |state| {
            state.context.record(write_id);
            state.actors.insert(write_id.actor, info);
            state.store.name.write(&mint, "Forged");
        });

        // Each Mac receives both files, in either order. A Mac does not
        // receive its own file, which it joins as an own file.
        for (n, forged_first) in forged_first.into_iter().enumerate().take(history.replicas) {
            let order = if forged_first { [forged, original] } else { [original, forged] };
            for hash in order {
                if sim.files[hash].mac != n {
                    sim.receive(n, hash);
                }
            }
            let quarantined = sim.errors.iter().any(|(m, _, err)| {
                *m == n && *err == JoinError::DuplicateWriteId { write_id }
            });
            prop_assert!(quarantined, "Mac {n} did not quarantine: {:?}", sim.errors);
        }
    }
}
