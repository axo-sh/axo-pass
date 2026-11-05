//! `SyncManager`: the watches of the synced vaults, the reaction to peer
//! changes, and the copy of a staged file that a transaction failed to
//! publish (decision 3, 9.3).
//!
//! One `SyncManager` runs per process, on its own thread. The synced vaults
//! are the local sync states under the app data directory that have a vault
//! file in the catalog. They are read unverified, as `PairingPrompt::vaults`
//! reads them, since they only pick the vaults to watch. The manager holds no
//! key and decrypts nothing.
//!
//! A scan lists the peer state files of a vault ([`PeerListing::changed`]).
//! A local file with a hash not reported before is a peer change. If the
//! app is unlocked, the manager runs a transaction with no requested change
//! and reports `vault_synced`. Otherwise it sets the pending flag, which the
//! next read joins, and reports `peer_changed`. A transaction that fails sets
//! the flag. A file that is not local is not reported, and its download is
//! requested, so the scan after its download reports it. A hash reported
//! once does not set the flag again, so a file that never joins does not
//! make every read run a transaction (D4).
//!
//! The start scan and each watch event scan a vault. Events queued together
//! give one scan of each vault. After each scan the manager copies the staged
//! file if a publish failed ([`VaultWriter::copy_staged`]). Every
//! [`RETRY_INTERVAL`] it copies again while the copy fails or is refused, and
//! watches again a vault with no watch (D13).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use uuid::Uuid;

use super::crdt::ReplicaId;
use super::listing::PeerListing;
use super::local_state::LocalSyncState;
use super::pairing::PairedVault;
use super::sidecar::Sidecar;
use super::state_file::StateHash;
use super::transport::{FileName, SyncTransport, TransportRoot, WatchHandle};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::storage::catalog::VaultCatalog;
use crate::secrets::vaults::storage::handle::check_vault_auth_still_valid;
use crate::secrets::vaults::storage::txn::{Committed, StagedCopy, Target, Unlock, VaultWriter};

/// Time between two retries of a staged file copy, and of a watch of a
/// vault with no watch (D13).
pub const RETRY_INTERVAL: Duration = Duration::from_secs(60);

/// Notifications of the `SyncManager` to the app (D21). The UI that reacts
/// is milestone 10.
pub trait SyncEvents: Send + Sync {
    /// A transaction joined a peer change of vault `vault_id`.
    fn vault_synced(&self, vault_id: Uuid);
    /// A peer change of vault `vault_id` waits for the next unlock.
    fn peer_changed(&self, vault_id: Uuid);
    /// `count` pairing requests under `root` prompt (9.5).
    fn pairing_requests(&self, root: &TransportRoot, count: usize);
    /// The new Mac received the sync key of a vault by pairing (9.5).
    fn paired(&self, vault: PairedVault);
}

/// Events that are only logged, until milestone 10 adds the app callback.
#[derive(Debug, Default)]
pub struct LogEvents;

impl SyncEvents for LogEvents {
    fn vault_synced(&self, vault_id: Uuid) {
        log::info!("Vault {vault_id} joined a peer change");
    }

    fn peer_changed(&self, vault_id: Uuid) {
        log::info!("Vault {vault_id} has a peer change for the next unlock");
    }

    fn pairing_requests(&self, root: &TransportRoot, count: usize) {
        log::info!("{count} pairing requests prompt under {root}");
    }

    fn paired(&self, vault: PairedVault) {
        let vault_id = vault.vault_id;
        log::info!("Vault {vault_id} was paired");
    }
}

/// Unlock of the transactions that the `SyncManager` runs (D5).
pub trait SyncUnlock: Send + Sync {
    /// Whether the app is unlocked. Never prompts.
    fn unlocked(&self) -> bool;
    /// Transaction with no requested change on the vault `target` through
    /// `files`.
    fn transaction(&self, files: &VaultWriter, target: &Target) -> Result<Committed<()>, Error>;
}

/// Unlock of the app: the shared context, while it is still valid.
#[derive(Debug, Default)]
pub struct AppUnlock;

impl SyncUnlock for AppUnlock {
    /// Whether the shared context still covers the vault encryption key.
    /// The probe never prompts, and waits for a prompt already on screen.
    fn unlocked(&self) -> bool {
        check_vault_auth_still_valid().is_ok()
    }

    fn transaction(&self, files: &VaultWriter, target: &Target) -> Result<Committed<()>, Error> {
        files.write(target, Unlock::App, |_| Ok(()))
    }
}

/// Message to the manager thread.
enum Message {
    /// A watch reported a change under the vault with this id.
    Changed(Uuid),
    /// Find the synced vaults again.
    Refresh,
    Shutdown,
}

/// Watches and reactions of the synced vaults, run on one thread. Clones of
/// the sender reach the thread from the watches.
pub struct SyncManager {
    sender: Sender<Message>,
    run: Mutex<Run>,
}

/// How the manager runs.
enum Run {
    /// On its own thread, until shutdown.
    Thread(Option<JoinHandle<()>>),
    /// On the thread of a test, one batch of messages at a time.
    #[cfg(test)]
    Manual(Option<Box<Worker>>),
}

impl SyncManager {
    /// Start the manager on its own thread. It first finds the synced vaults
    /// of `catalog`, scans and watches each, and copies each staged file
    /// that a publish failed to copy. `events` receives the notifications,
    /// and `unlock` decides and runs the transactions.
    pub fn start(
        catalog: VaultCatalog,
        events: Arc<dyn SyncEvents>,
        unlock: Arc<dyn SyncUnlock>,
    ) -> Self {
        let (sender, worker) = Worker::new(catalog, events, unlock);
        let thread = thread::Builder::new()
            .name("sync-manager".into())
            .spawn(move || worker.run());
        let thread = match thread {
            Ok(thread) => Some(thread),
            Err(e) => {
                log::error!("Failed to start the sync manager: {e}");
                None
            },
        };
        Self {
            sender,
            run: Mutex::new(Run::Thread(thread)),
        }
    }

    /// Manager that runs only in [`Self::run_queued`], on the calling
    /// thread, with the start scan queued.
    #[cfg(test)]
    pub(crate) fn manual(
        catalog: VaultCatalog,
        events: Arc<dyn SyncEvents>,
        unlock: Arc<dyn SyncUnlock>,
    ) -> Self {
        let (sender, worker) = Worker::new(catalog, events, unlock);
        Self {
            sender,
            run: Mutex::new(Run::Manual(Some(Box::new(worker)))),
        }
    }

    /// Find the synced vaults again, such as after sync is enabled for a
    /// vault. A new vault is scanned and watched. A vault no longer synced,
    /// or whose root changed, ends its watch first.
    pub fn refresh(&self) {
        let _ = self.sender.send(Message::Refresh);
    }

    /// End every watch and stop the manager. Waits for a scan or a
    /// transaction that runs.
    pub fn shutdown(&self) {
        let _ = self.sender.send(Message::Shutdown);
        let mut run = self.run.lock().unwrap_or_else(|e| e.into_inner());
        match &mut *run {
            Run::Thread(thread) => {
                if let Some(thread) = thread.take()
                    && thread.join().is_err()
                {
                    log::error!("The sync manager thread panicked");
                }
            },
            #[cfg(test)]
            Run::Manual(worker) => {
                if let Some(mut worker) = worker.take() {
                    worker.stop();
                }
            },
        }
    }

    /// Run the queued messages and the retries that are due, as the thread
    /// does when it wakes.
    #[cfg(test)]
    pub(crate) fn run_queued(&self) {
        let mut run = self.run.lock().unwrap_or_else(|e| e.into_inner());
        if let Run::Manual(Some(worker)) = &mut *run
            && !worker.process(Vec::new())
            && let Some(mut worker) = Run::take_manual(&mut run)
        {
            worker.stop();
        }
    }

    /// Advance the clock of the retries by `seconds`.
    #[cfg(test)]
    pub(crate) fn advance_clock(&self, seconds: u64) {
        let mut run = self.run.lock().unwrap_or_else(|e| e.into_inner());
        if let Run::Manual(Some(worker)) = &mut *run {
            worker.clock_offset += Duration::from_secs(seconds);
        }
    }
}

#[cfg(test)]
impl Run {
    fn take_manual(&mut self) -> Option<Box<Worker>> {
        match self {
            Run::Manual(worker) => worker.take(),
            Run::Thread(_) => None,
        }
    }
}

impl Drop for SyncManager {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Synced vault found by a refresh.
struct SyncedVault {
    id: Uuid,
    target: Target,
    replica: ReplicaId,
    root: Option<TransportRoot>,
}

/// One synced vault of the manager.
struct ManagedVault {
    id: Uuid,
    /// Key and path of the vault file, from the catalog scan.
    target: Target,
    /// Replica id of the local sync state, read unverified. It only picks
    /// the directory that the listing skips.
    replica: ReplicaId,
    /// Root of the transport in the sidecar.
    root: Option<TransportRoot>,
    transport: Option<Arc<dyn SyncTransport>>,
    watch: Option<WatchHandle>,
    /// Peer state files already reported, of those still listed and not
    /// joined.
    reported: BTreeSet<(ReplicaId, StateHash)>,
    /// Whether the last staged file copy failed or was refused.
    copy_pending: bool,
    /// Time of the next retry of the copy or the watch.
    retry_at: Option<Instant>,
}

/// State of the manager thread.
struct Worker {
    catalog: VaultCatalog,
    events: Arc<dyn SyncEvents>,
    unlock: Arc<dyn SyncUnlock>,
    /// Sender cloned into each watch.
    sender: Sender<Message>,
    receiver: Receiver<Message>,
    vaults: BTreeMap<Uuid, ManagedVault>,
    /// Time added to the clock of the retries. Zero outside the tests.
    #[cfg(test)]
    clock_offset: Duration,
}

impl Worker {
    /// Worker with the start scan queued, and the sender of its messages.
    fn new(
        catalog: VaultCatalog,
        events: Arc<dyn SyncEvents>,
        unlock: Arc<dyn SyncUnlock>,
    ) -> (Sender<Message>, Self) {
        let (sender, receiver) = mpsc::channel();
        let _ = sender.send(Message::Refresh);
        let worker = Self {
            catalog,
            events,
            unlock,
            sender: sender.clone(),
            receiver,
            vaults: BTreeMap::new(),
            #[cfg(test)]
            clock_offset: Duration::ZERO,
        };
        (sender, worker)
    }

    fn files(&self) -> &VaultWriter {
        self.catalog.files()
    }

    /// Clock of the retries.
    fn now(&self) -> Instant {
        let now = Instant::now();
        #[cfg(test)]
        let now = now + self.clock_offset;
        now
    }

    /// Wait for messages and run them until shutdown, waking for each retry
    /// that is due.
    fn run(mut self) {
        loop {
            let next = match self.next_retry() {
                Some(at) => {
                    let wait = at.saturating_duration_since(self.now());
                    match self.receiver.recv_timeout(wait) {
                        Ok(message) => Some(message),
                        Err(RecvTimeoutError::Timeout) => None,
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                },
                None => match self.receiver.recv() {
                    Ok(message) => Some(message),
                    Err(_) => break,
                },
            };
            if !self.process(next.into_iter().collect()) {
                break;
            }
        }
        self.stop();
    }

    /// Run `received` and every message queued after it, then the retries
    /// that are due. Each vault with a change is scanned once. Returns false
    /// at shutdown.
    fn process(&mut self, mut received: Vec<Message>) -> bool {
        received.extend(self.receiver.try_iter());
        let mut refresh = false;
        let mut changed = BTreeSet::new();
        for message in received {
            match message {
                Message::Shutdown => return false,
                Message::Refresh => refresh = true,
                Message::Changed(vault_id) => {
                    changed.insert(vault_id);
                },
            }
        }
        if refresh {
            for vault_id in self.refresh() {
                changed.insert(vault_id);
            }
        }
        for vault_id in changed {
            self.scan(vault_id);
        }
        self.retry_due();
        true
    }

    /// Earliest retry of any vault.
    fn next_retry(&self) -> Option<Instant> {
        self.vaults
            .values()
            .filter_map(|vault| vault.retry_at)
            .min()
    }

    /// End every watch.
    fn stop(&mut self) {
        let locks = self.files().locks().clone();
        for vault in std::mem::take(&mut self.vaults).into_values() {
            locks.set_watched(vault.id, false);
        }
    }

    /// Synced vaults: each local sync state with a vault file in the catalog
    /// scan. The scan tracks each vault in the vault locks.
    fn synced(&self) -> Vec<SyncedVault> {
        let root = self.files().root().to_path_buf();
        let listed: BTreeMap<Uuid, Target> = self
            .catalog
            .scan()
            .vaults
            .into_iter()
            .filter_map(|(key, vh)| {
                let id = vh.peek_vault_id().ok()?;
                Some((id, Target::new(key, vh.path.clone())))
            })
            .collect();
        LocalSyncState::list(&root)
            .into_iter()
            .filter_map(|(id, path)| {
                let target = listed.get(&id)?.clone();
                let contents = fs::read_to_string(&path).ok()?;
                let (vault_id, replica) = LocalSyncState::peek(&contents)?;
                if vault_id != id {
                    return None;
                }
                let root = match Sidecar::read(&root, id) {
                    Ok(sidecar) => sidecar.transport,
                    Err(e) => {
                        log::warn!("Failed to read the sidecar of vault {id}: {e}");
                        return None;
                    },
                };
                Some(SyncedVault {
                    id,
                    target,
                    replica,
                    root,
                })
            })
            .collect()
    }

    /// Find the synced vaults again. A vault no longer synced, or whose
    /// root or replica changed, ends its watch. Returns the vaults added,
    /// which are watched and not yet scanned.
    fn refresh(&mut self) -> Vec<Uuid> {
        let synced = self.synced();
        let locks = self.files().locks().clone();
        let kept: BTreeSet<Uuid> = synced
            .iter()
            .filter(|found| {
                self.vaults
                    .get(&found.id)
                    .is_some_and(|vault| vault.root == found.root && vault.replica == found.replica)
            })
            .map(|found| found.id)
            .collect();
        self.vaults.retain(|id, _| {
            let keep = kept.contains(id);
            if !keep {
                locks.set_watched(*id, false);
            }
            keep
        });
        let mut added = Vec::new();
        for found in synced {
            if let Some(vault) = self.vaults.get_mut(&found.id) {
                vault.target = found.target;
                continue;
            }
            let id = found.id;
            let mut vault = ManagedVault {
                id,
                target: found.target,
                replica: found.replica,
                root: found.root,
                transport: None,
                watch: None,
                reported: BTreeSet::new(),
                copy_pending: false,
                retry_at: None,
            };
            self.connect(&mut vault);
            self.vaults.insert(id, vault);
            added.push(id);
        }
        added
    }

    /// Resolve the transport of `vault` and watch it, for whichever is
    /// missing. Returns whether a watch started.
    fn connect(&self, vault: &mut ManagedVault) -> bool {
        let id = vault.id;
        if vault.transport.is_none() {
            match self.files().transport_of(vault.root.as_ref()) {
                Ok(transport) => vault.transport = transport,
                Err(e) => log::warn!("Failed to resolve the transport of vault {id}: {e}"),
            }
        }
        if vault.watch.is_some() {
            return false;
        }
        let Some(transport) = &vault.transport else {
            return false;
        };
        let sender = self.sender.clone();
        let notify = Box::new(move || {
            let _ = sender.send(Message::Changed(id));
        });
        vault.watch = transport.watch(id, notify);
        let watched = vault.watch.is_some();
        self.files().locks().set_watched(id, watched);
        watched
    }

    /// Scan vault `vault_id` for peer changes and react to them, then copy
    /// its staged file if a publish failed.
    fn scan(&mut self, vault_id: Uuid) {
        let now = self.now();
        let Some(mut vault) = self.vaults.remove(&vault_id) else {
            return;
        };
        if vault.changes(self.files()) {
            self.react(&mut vault);
        }
        self.copy(&mut vault, now);
        self.vaults.insert(vault_id, vault);
    }

    /// Run a transaction for a peer change of `vault` if the app is
    /// unlocked, and otherwise set the pending flag (D5).
    fn react(&self, vault: &mut ManagedVault) {
        let id = vault.id;
        let locks = self.files().locks();
        if !self.unlock.unlocked() {
            locks.set_pending(id);
            self.events.peer_changed(id);
            return;
        }
        match self.unlock.transaction(self.files(), &vault.target) {
            Ok(committed) => {
                vault.target = Target::of(&committed.vault);
                self.events.vault_synced(id);
            },
            Err(e) => {
                log::warn!("Failed to join a peer change of vault {id}: {e}");
                locks.set_pending(id);
            },
        }
    }

    /// Copy the staged file of `vault` if a publish failed, and schedule the
    /// next retry at `now`.
    fn copy(&self, vault: &mut ManagedVault, now: Instant) {
        let id = vault.id;
        vault.copy_pending = match self.files().copy_staged(id, &vault.target.path) {
            Ok(StagedCopy::Copied | StagedCopy::NotStaged) => false,
            Ok(StagedCopy::Refused) => true,
            Err(e) => {
                log::warn!("Failed to copy the staged file of vault {id}: {e}");
                true
            },
        };
        vault.schedule(now);
    }

    /// Retry each vault whose retry is due: watch again a vault with no
    /// watch, and scan it if the watch starts, and copy a staged file whose
    /// copy failed.
    fn retry_due(&mut self) {
        let now = self.now();
        let due: Vec<Uuid> = self
            .vaults
            .values()
            .filter(|vault| vault.retry_at.is_some_and(|at| at <= now))
            .map(|vault| vault.id)
            .collect();
        for vault_id in due {
            let Some(mut vault) = self.vaults.remove(&vault_id) else {
                continue;
            };
            vault.retry_at = None;
            let watched = vault.watch.is_none() && self.connect(&mut vault);
            if watched && vault.changes(self.files()) {
                self.react(&mut vault);
            }
            if watched || vault.copy_pending {
                self.copy(&mut vault, now);
            } else {
                vault.schedule(now);
            }
            self.vaults.insert(vault_id, vault);
        }
    }
}

impl ManagedVault {
    /// Schedule the next retry after `now` if the vault has no watch or a
    /// copy is pending.
    fn schedule(&mut self, now: Instant) {
        self.retry_at = (self.watch.is_none() || self.copy_pending).then(|| now + RETRY_INTERVAL);
    }

    /// Whether the listing finds a local peer state file not reported
    /// before. Each such file is recorded as reported. A listed file that is
    /// not local is not reported, and one download of the vault is
    /// requested. A vault with no transport, a sidecar that cannot be read,
    /// and a listing that fails find nothing.
    fn changes(&mut self, files: &VaultWriter) -> bool {
        let id = self.id;
        let Some(transport) = self.transport.clone() else {
            return false;
        };
        let listed = Sidecar::read(files.root(), id)
            .and_then(|sidecar| PeerListing::changed(&*transport, &sidecar, id, self.replica));
        let changed = match listed {
            Ok(changed) => changed,
            Err(e) => {
                log::warn!("Failed to list the peer state files of vault {id}: {e}");
                return false;
            },
        };
        let mut found = false;
        let mut remote = false;
        for file in &changed {
            if self.reported.contains(file) {
                continue;
            }
            let (replica, hash) = *file;
            match transport.is_local(id, replica, FileName::State(hash)) {
                Ok(true) => {
                    self.reported.insert(*file);
                    found = true;
                },
                Ok(false) => remote = true,
                Err(e) => {
                    log::warn!("Failed to check state file {hash} of vault {id}: {e}");
                    remote = true;
                },
            }
        }
        self.reported.retain(|file| changed.contains(file));
        if remote && let Err(e) = transport.request_download(id) {
            log::warn!("Failed to request the download of vault {id}: {e}");
        }
        found
    }
}
