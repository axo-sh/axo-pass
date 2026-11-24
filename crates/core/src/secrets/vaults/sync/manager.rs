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
//! Disable (10.4, D8 of doc 18). A `leaving` sync state, with or without a
//! vault file, is copy-only. It is not watched or scanned, runs no
//! transaction, and gives no pairing watch of its root. Its final file is
//! copied at each refresh and each retry, and the copy deletes its sync
//! files, after which the manager drops it. A refresh deletes the sync files
//! of a vault that holds no replica id and whose sync state is not
//! `leaving`, so an unlock stays read-only.
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
//! give one scan of each vault. A vault with no scan for [`RESCAN_INTERVAL`]
//! is scanned again, so a change that no watch reported is found. The
//! pairing requests of each root are counted again at the same interval.
//! A rescan that finds a change is recorded in the sync log, with whether the
//! vault had a watch. A scan after a watch event that finds a change is
//! recorded too. The watch records the signal of each event, so the log shows
//! which signal reported a change and which change no signal reported. After
//! each scan the manager copies the staged
//! file if a publish failed ([`VaultWriter::copy_staged`]). Every
//! [`RETRY_INTERVAL`] it copies again while the copy fails or is refused, and
//! watches again a vault with no watch (D13).
//!
//! Pairing (9.5). The manager watches the pairing directory of each root of
//! the synced vaults, one watch per root. The watch start and each event
//! count the requests that prompt ([`PairingPrompt::pending`]), with the
//! dismissed ids of the root, request their download, and report
//! `pairing_requests`. On the new Mac
//! the manager runs the [`PairingWatcher`] that [`SyncManager::pair`] hands
//! it, until [`SyncManager::finish_pairing`], the expiry, or the shutdown.
//! The manager writes no pairing request. The watcher deletes its own.
//!
//! Pairing import (10.3, D6 of doc 18). With a [`PairingImport`], each vault
//! that the watcher accepts waits in an [`ImportWait`], with its own watch of
//! the vault and the download of the vault requested. The wait is checked at
//! each watch event of the vault, at each poll of the watcher, and every
//! [`POLL_INTERVAL`]. Once a state file of the Mac that paired decodes under
//! the received key, the manager runs `VaultCatalog::join_sync` with the keys
//! of the pairing and finds the synced vaults again in the next batch. A wait
//! outlives the finish and the expiry of its pairing, since the key is
//! already received. It ends at the shutdown, and the keys are dropped.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SendError, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[cfg(test)]
use jiff::SignedDuration;
use jiff::Timestamp;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::crdt::ReplicaId;
use super::join_sync::{ImportWait, PairingImport, WaitReason};
use super::listing::PeerListing;
use super::local_state::LocalSyncState;
use super::pairing::dismissed::DismissedRequests;
use super::pairing::prompt::PairingPrompt;
use super::pairing::watcher::{POLL_INTERVAL, PairingWatcher};
use super::pairing::{PairWait, PairedVault, PendingPairing};
use super::scan_status::{self, ScanOutcome};
use super::sidecar::Sidecar;
use super::state_file::StateHash;
use super::sync_log;
use super::transport::{FileName, SyncTransport, TransportRoot, WatchHandle};
use super::wrapping::{DeviceUnwrap, PairingKeys};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::encrypted_vault::VaultHeader;
use crate::secrets::vaults::storage::catalog::VaultCatalog;
use crate::secrets::vaults::storage::handle::check_vault_auth_still_valid;
use crate::secrets::vaults::storage::txn::{Committed, StagedCopy, Target, Unlock, VaultWriter};

/// Time between two retries of a staged file copy, and of a watch of a
/// vault with no watch (D13).
pub const RETRY_INTERVAL: Duration = Duration::from_secs(60);

/// Time with no scan after which a watched vault is scanned again, and the
/// pairing requests of each root are counted again. A watch that misses an
/// event is caught by this scan.
pub const RESCAN_INTERVAL: Duration = Duration::from_secs(60);

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
    fn paired(&self, vault: &PairedVault);
    /// The import of vault `vault_id` waits for a state file of the Mac that
    /// paired (10.3).
    fn import_waiting(&self, vault_id: Uuid);
    /// The pairing import joined vault `vault_id` into the vault with the
    /// vault key `vault_key` (10.3).
    fn vault_imported(&self, vault_id: Uuid, vault_key: &str);
    /// The pairing import of vault `vault_id` failed with `error`. The user
    /// pairs again (10.3).
    fn import_failed(&self, vault_id: Uuid, error: &Error);
    /// The import of vault `vault_id` waits for `reason`. Called again only
    /// if the reason changes.
    fn import_blocked(&self, _vault_id: Uuid, _reason: &WaitReason) {}
    /// The key of vault `vault_id` has not arrived, for `reason`. Called
    /// again only if the reason changes.
    fn pairing_blocked(&self, _vault_id: Uuid, _reason: &PairWait) {}
    /// The pairing of the new Mac ended, by its expiry, by the key of every
    /// vault arriving, or by the user. Imports that wait continue.
    fn pairing_ended(&self) {}
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

    fn paired(&self, vault: &PairedVault) {
        let vault_id = vault.vault_id;
        log::info!("Vault {vault_id} was paired");
    }

    fn import_waiting(&self, vault_id: Uuid) {
        log::info!("Import of vault {vault_id} waits for the paired Mac's state file");
    }

    fn vault_imported(&self, vault_id: Uuid, vault_key: &str) {
        log::info!("Vault {vault_id} was imported as {vault_key}");
    }

    fn import_failed(&self, vault_id: Uuid, error: &Error) {
        log::warn!("Import of vault {vault_id} failed: {error}");
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
    /// A pairing watch reported a change under the root.
    Pairings(TransportRoot),
    /// Run a pairing of the new Mac.
    Pair(Box<PairingStart>),
    /// The user finished the pairing of the new Mac.
    FinishPairing,
    /// The user asks to scan this vault for peer changes now.
    SyncNow(Uuid),
    /// The user asks to run the failed import of this vault again.
    RetryImport(Uuid),
    /// A watch of the pairing of the new Mac reported a change.
    PairingChanged,
    Shutdown,
}

/// Pairing of the new Mac handed to the manager thread.
struct PairingStart {
    pending: PendingPairing,
    transport: Arc<dyn SyncTransport>,
    keys: Box<dyn PairingKeys + Send>,
    import: Option<PairingImport>,
}

/// Keys of one pairing, shared by its watcher and its import waits on the
/// manager thread. `ManagedKey` is `Send` and not `Sync`, so the keys are
/// held in a mutex.
#[derive(Clone)]
struct SharedKeys(Arc<Mutex<Box<dyn PairingKeys + Send>>>);

impl SharedKeys {
    fn new(keys: Box<dyn PairingKeys + Send>) -> Self {
        Self(Arc::new(Mutex::new(keys)))
    }

    fn lock(&self) -> MutexGuard<'_, Box<dyn PairingKeys + Send>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl DeviceUnwrap for SharedKeys {
    fn unwrap_sync_key(&self, wrapped: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        self.lock().unwrap_sync_key(wrapped)
    }
}

/// Pairing of the new Mac that runs, with its keys and its import.
struct Pairing {
    watcher: PairingWatcher,
    keys: SharedKeys,
    transport: Arc<dyn SyncTransport>,
    import: Option<PairingImport>,
    /// Wait reasons last reported, by vault id.
    reported: BTreeMap<Uuid, PairWait>,
}

/// Import of a paired vault that waits for a state file of the Mac that
/// paired.
struct PendingImport {
    wait: ImportWait,
    root: TransportRoot,
    /// Display name of this Mac.
    name: String,
    keys: SharedKeys,
    transport: Arc<dyn SyncTransport>,
    /// Watch of the vault, which outlives the watches of the pairing. It
    /// ends when the import is dropped.
    _watch: Option<WatchHandle>,
    /// Time of the next check with no event.
    next_check: Instant,
    /// Failed joins since the last retry request.
    attempts: u32,
    /// Whether the join failed [`MAX_IMPORT_ATTEMPTS`] times. The import
    /// then waits for a retry request.
    failed: bool,
    /// Reason last reported for the wait.
    reason: Option<WaitReason>,
}

/// Joins of an import that fail before it is reported as failed.
const MAX_IMPORT_ATTEMPTS: u32 = 3;

/// Interval of the check of an import that failed and waits for a retry
/// request.
const FAILED_IMPORT_IDLE: Duration = Duration::from_secs(24 * 60 * 60);

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

    /// Run the pairing `pending` of the new Mac through `transport` until
    /// [`Self::finish_pairing`], 15 minutes, or the shutdown, each of which
    /// deletes the request. `keys` hold `vault-encryption-key`, read once on
    /// the context of the pairing start (D16 of doc 17). With `import`, each
    /// paired vault is imported once a state file of the Mac that paired
    /// decodes (D6 of doc 18). With `None`, the manager only reports
    /// `paired`. A pairing already running is finished first, and its
    /// import waits continue. If the manager stopped, the request is deleted
    /// immediately.
    pub fn pair(
        &self,
        pending: PendingPairing,
        transport: Arc<dyn SyncTransport>,
        keys: Box<dyn PairingKeys + Send>,
        import: Option<PairingImport>,
    ) {
        let start = Box::new(PairingStart {
            pending,
            transport,
            keys,
            import,
        });
        if let Err(SendError(Message::Pair(start))) = self.sender.send(Message::Pair(start)) {
            let request_id = start.pending.request().request_id;
            if let Err(e) = start.pending.finish(&*start.transport) {
                log::warn!("Failed to delete pairing request {request_id}: {e}");
            }
        }
    }

    /// Finish the pairing of the new Mac: end its watches and delete its
    /// request.
    pub fn finish_pairing(&self) {
        let _ = self.sender.send(Message::FinishPairing);
    }

    /// Scan vault `vault_id` for peer changes now, and join them. Does
    /// nothing if the vault is not synced.
    pub fn sync_now(&self, vault_id: Uuid) {
        let _ = self.sender.send(Message::SyncNow(vault_id));
    }

    /// Run the failed import of vault `vault_id` again. Does nothing if the
    /// import did not fail.
    pub fn retry_import(&self, vault_id: Uuid) {
        let _ = self.sender.send(Message::RetryImport(vault_id));
    }

    /// End every watch, finish the pairing of the new Mac, end the import
    /// waits, and stop the manager. Waits for a scan, a poll, a transaction,
    /// or an import that runs.
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
    target: Option<Target>,
    replica: ReplicaId,
    root: Option<TransportRoot>,
    leaving: bool,
}

/// One synced vault of the manager.
struct ManagedVault {
    id: Uuid,
    /// Key and path of the vault file, from the catalog scan. `None` for a
    /// `leaving` sync state with no vault file.
    target: Option<Target>,
    /// Replica id of the local sync state, read unverified. It only picks
    /// the directory that the listing skips.
    replica: ReplicaId,
    /// Root of the transport in the sidecar.
    root: Option<TransportRoot>,
    /// Whether the sync state is `leaving`, read unverified. A `leaving`
    /// vault is copy-only: it has no transport and no watch, is not
    /// scanned, runs no transaction, and its final file is copied at each
    /// refresh and each retry (D8 of doc 18).
    leaving: bool,
    transport: Option<Arc<dyn SyncTransport>>,
    watch: Option<WatchHandle>,
    /// Peer state files already reported, of those still listed and not
    /// joined.
    reported: BTreeSet<(ReplicaId, StateHash)>,
    /// Whether the last staged file copy failed or was refused.
    copy_pending: bool,
    /// Time of the next retry of the copy or the watch.
    retry_at: Option<Instant>,
    /// Time of the next scan with no watch event. `None` for a `leaving`
    /// vault.
    rescan_at: Option<Instant>,
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
    /// Pairing watch of each root of the synced vaults.
    roots: HashMap<TransportRoot, WatchHandle>,
    /// Pairing of the new Mac, if one runs.
    pairing: Option<Pairing>,
    /// Imports of paired vaults that wait, by vault id.
    imports: BTreeMap<Uuid, PendingImport>,
    /// Count of the pairing requests last reported, by root.
    pairing_counts: HashMap<TransportRoot, usize>,
    /// Time of the next count of the pairing requests with no watch event.
    pairing_rescan_at: Instant,
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
            roots: HashMap::new(),
            pairing: None,
            imports: BTreeMap::new(),
            pairing_counts: HashMap::new(),
            pairing_rescan_at: Instant::now() + RESCAN_INTERVAL,
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

    /// Clock of the pairing prompt, moved with the clock of the retries.
    fn timestamp(&self) -> Timestamp {
        let now = Timestamp::now();
        #[cfg(test)]
        let now = now + SignedDuration::try_from(self.clock_offset).unwrap_or(SignedDuration::ZERO);
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

    /// Run `received` and every message queued after it, then the retries,
    /// the pairing polls, and the import checks that are due. Each vault
    /// with a change is scanned once, and each root with a pairing change is
    /// counted once. A pairing start or finish runs in message order.
    /// Returns false at shutdown, after the pairing messages of the batch
    /// ran.
    fn process(&mut self, mut received: Vec<Message>) -> bool {
        received.extend(self.receiver.try_iter());
        let mut shutdown = false;
        let mut refresh = false;
        let mut changed = BTreeSet::new();
        let mut refreshed = BTreeSet::new();
        let mut import_changed = BTreeSet::new();
        let mut requested = BTreeSet::new();
        let mut roots: Vec<TransportRoot> = Vec::new();
        let mut pairing_changed = false;
        for message in received {
            match message {
                Message::Shutdown => shutdown = true,
                Message::Refresh => refresh = true,
                Message::Changed(vault_id) => {
                    if self.imports.contains_key(&vault_id) {
                        import_changed.insert(vault_id);
                    }
                    changed.insert(vault_id);
                },
                Message::Pairings(root) => {
                    if !roots.contains(&root) {
                        roots.push(root);
                    }
                },
                Message::Pair(start) => self.pair(*start),
                Message::FinishPairing => {
                    if let Some(pairing) = self.pairing.take() {
                        pairing.watcher.finish();
                        self.events.pairing_ended();
                    }
                },
                Message::SyncNow(vault_id) => {
                    requested.insert(vault_id);
                },
                Message::RetryImport(vault_id) => self.retry_import(vault_id),
                Message::PairingChanged => pairing_changed = true,
            }
        }
        if shutdown {
            return false;
        }
        if refresh {
            refreshed.extend(self.refresh());
        }
        let scanned: BTreeSet<Uuid> = changed
            .union(&refreshed)
            .chain(&requested)
            .copied()
            .collect();
        for vault_id in scanned {
            self.scan(vault_id, changed.contains(&vault_id));
        }
        self.retry_due();
        for root in self.watch_roots() {
            if !roots.contains(&root) {
                roots.push(root);
            }
        }
        for root in &roots {
            self.report_pairings(root, false);
        }
        self.rescan_pairings(&roots);
        let polled = self.poll_pairing(pairing_changed);
        self.check_imports(&import_changed, polled);
        true
    }

    /// Earliest retry or rescan of any vault, the next count of the pairing
    /// requests, the next wake of the pairing, or the next check of an
    /// import.
    fn next_retry(&self) -> Option<Instant> {
        self.vaults
            .values()
            .flat_map(|vault| [vault.retry_at, vault.rescan_at])
            .flatten()
            .chain((!self.roots.is_empty()).then_some(self.pairing_rescan_at))
            .chain(
                self.pairing
                    .as_ref()
                    .map(|pairing| pairing.watcher.next_wake()),
            )
            .chain(self.imports.values().map(|import| import.next_check))
            .min()
    }

    /// End every watch, finish the pairing, and end the import waits.
    fn stop(&mut self) {
        let locks = self.files().locks().clone();
        for vault in std::mem::take(&mut self.vaults).into_values() {
            locks.set_watched(vault.id, false);
        }
        self.roots.clear();
        if let Some(pairing) = self.pairing.take() {
            pairing.watcher.finish();
        }
        self.imports.clear();
    }

    /// Start the pairing `start` of the new Mac, after finishing the one
    /// that runs.
    fn pair(&mut self, start: PairingStart) {
        if let Some(pairing) = self.pairing.take() {
            pairing.watcher.finish();
        }
        let sender = self.sender.clone();
        let notify = move || {
            let _ = sender.send(Message::PairingChanged);
        };
        let keys = SharedKeys::new(start.keys);
        let watcher = PairingWatcher::start(
            start.pending,
            start.transport.clone(),
            Box::new(keys.clone()),
            notify,
            self.now(),
        );
        self.pairing = Some(Pairing {
            watcher,
            keys,
            transport: start.transport,
            import: start.import,
            reported: BTreeMap::new(),
        });
        let counted: Vec<TransportRoot> = self.pairing_counts.keys().cloned().collect();
        for root in counted {
            self.report_pairings(&root, false);
        }
    }

    /// Poll the pairing of the new Mac if a watch reported a change or the
    /// poll is due, or finish it if it expired. Each accepted vault is
    /// reported, and its import starts. Returns whether the pairing was
    /// polled.
    fn poll_pairing(&mut self, changed: bool) -> bool {
        let now = self.now();
        let Some(pairing) = &mut self.pairing else {
            return false;
        };
        if pairing.watcher.expired(now) {
            log::info!("Pairing request expired");
            if let Some(pairing) = self.pairing.take() {
                pairing.watcher.finish();
                self.events.pairing_ended();
            }
            return false;
        }
        if !changed && !pairing.watcher.poll_due(now) {
            return false;
        }
        let paired = pairing.watcher.poll(now);
        let waits = pairing.watcher.waits();
        let changed_waits: Vec<(Uuid, PairWait)> = waits
            .iter()
            .filter(|(vault_id, wait)| pairing.reported.get(vault_id) != Some(wait))
            .map(|(vault_id, wait)| (*vault_id, wait.clone()))
            .collect();
        pairing.reported = waits;
        for (vault_id, wait) in &changed_waits {
            self.events.pairing_blocked(*vault_id, wait);
        }
        if paired.is_empty() {
            return true;
        }
        let Some(pairing) = &self.pairing else {
            return true;
        };
        let keys = pairing.keys.clone();
        let transport = pairing.transport.clone();
        let import = pairing.import.clone();
        for vault in paired {
            self.events.paired(&vault);
            if let Some(import) = &import {
                self.wait_for(vault, import, &keys, &transport, now);
            }
        }
        // The request is deleted once every vault has its key. The import
        // waits continue.
        if self
            .pairing
            .as_ref()
            .is_some_and(|pairing| pairing.watcher.complete())
            && let Some(pairing) = self.pairing.take()
        {
            log::info!("Pairing received the key of every vault");
            pairing.watcher.finish();
            self.events.pairing_ended();
        }
        true
    }

    /// Run the failed import of vault `vault_id` again.
    fn retry_import(&mut self, vault_id: Uuid) {
        let now = self.now();
        let Some(import) = self.imports.get_mut(&vault_id) else {
            return;
        };
        if !import.failed {
            return;
        }
        import.failed = false;
        import.attempts = 0;
        import.reason = None;
        import.next_check = now;
        self.events.import_waiting(vault_id);
    }

    /// Start the import of the paired vault `vault` as `import` states:
    /// watch the vault, request its download, and report `import_waiting`.
    /// The first check is due at `now`. A wait of the same vault is
    /// replaced.
    fn wait_for(
        &mut self,
        vault: PairedVault,
        import: &PairingImport,
        keys: &SharedKeys,
        transport: &Arc<dyn SyncTransport>,
        now: Instant,
    ) {
        let vault_id = vault.vault_id;
        let sender = self.sender.clone();
        let notify = Box::new(move || {
            let _ = sender.send(Message::Changed(vault_id));
        });
        let watch = transport.watch(vault_id, notify);
        if let Err(e) = transport.request_download(vault_id) {
            log::warn!("Failed to request the download of vault {vault_id}: {e}");
        }
        let into = import.join_into(vault_id);
        self.imports.insert(
            vault_id,
            PendingImport {
                wait: ImportWait::new(vault, into),
                root: import.root.clone(),
                name: import.name.clone(),
                keys: keys.clone(),
                transport: transport.clone(),
                _watch: watch,
                next_check: now,
                attempts: 0,
                failed: false,
                reason: None,
            },
        );
        self.events.import_waiting(vault_id);
    }

    /// Check each import whose vault reported a change in `changed`, every
    /// import if the pairing was `polled`, and each import whose check is
    /// due. An import whose wait holds runs, and the next check of the
    /// others is due [`POLL_INTERVAL`] later.
    fn check_imports(&mut self, changed: &BTreeSet<Uuid>, polled: bool) {
        let now = self.now();
        let due: Vec<Uuid> = self
            .imports
            .iter()
            .filter(|(vault_id, import)| {
                !import.failed && (polled || changed.contains(vault_id) || import.next_check <= now)
            })
            .map(|(vault_id, _)| *vault_id)
            .collect();
        for vault_id in due {
            let Some(mut import) = self.imports.remove(&vault_id) else {
                continue;
            };
            match import.wait.check(&*import.transport) {
                None => self.import(import, now),
                Some(reason) => {
                    if import.reason.as_ref() != Some(&reason) {
                        self.events.import_blocked(vault_id, &reason);
                        import.reason = Some(reason);
                    }
                    import.next_check = now + POLL_INTERVAL;
                    self.imports.insert(vault_id, import);
                },
            }
        }
    }

    /// Join the paired vault of `import` with the keys of its pairing, and
    /// report `vault_imported`. After an import the synced vaults are found
    /// again in the next batch, so the vault is watched. A join that fails
    /// runs again at the next check, up to [`MAX_IMPORT_ATTEMPTS`] times.
    /// Then the import is reported with `import_failed` and kept until a
    /// retry request.
    fn import(&mut self, mut import: PendingImport, now: Instant) {
        let vault_id = import.wait.vault_id();
        let (join, into) = import.wait.join();
        let result = {
            let keys = import.keys.lock();
            self.catalog
                .join_sync(&join, into, &import.root, &import.name, keys.unlock())
        };
        match result {
            Ok(committed) => {
                sync_log::info(vault_id, "Imported by pairing");
                self.events.vault_imported(vault_id, &committed.vault.key);
                let _ = self.sender.send(Message::Refresh);
            },
            Err(e) => {
                import.attempts += 1;
                sync_log::warn(vault_id, "Failed to import by pairing", &e);
                if import.attempts >= MAX_IMPORT_ATTEMPTS {
                    import.failed = true;
                    import.next_check = now + FAILED_IMPORT_IDLE;
                    self.events.import_failed(vault_id, &e);
                } else {
                    import.next_check = now + POLL_INTERVAL;
                }
                self.imports.insert(vault_id, import);
            },
        }
    }

    /// Watch the pairing directory of each root of the synced vaults that
    /// has a transport and no watch, and end the watch of a root no longer
    /// used. Returns the roots whose watch started.
    fn watch_roots(&mut self) -> Vec<TransportRoot> {
        let mut used: HashMap<TransportRoot, Arc<dyn SyncTransport>> = HashMap::new();
        for vault in self.vaults.values() {
            if let (Some(root), Some(transport)) = (&vault.root, &vault.transport) {
                used.entry(root.clone())
                    .or_insert_with(|| transport.clone());
            }
        }
        self.roots.retain(|root, _| used.contains_key(root));
        let mut started = Vec::new();
        for (root, transport) in used {
            if self.roots.contains_key(&root) {
                continue;
            }
            let sender = self.sender.clone();
            let changed = root.clone();
            let notify = Box::new(move || {
                let _ = sender.send(Message::Pairings(changed.clone()));
            });
            if let Some(watch) = transport.watch_pairings(notify) {
                self.roots.insert(root.clone(), watch);
                started.push(root);
            }
        }
        started
    }

    /// Count the pairing requests of `root` that prompt and report them. A
    /// count from a rescan is reported only if it differs from the last one.
    /// The download of each request that prompts is requested, so it is local
    /// by the time the user types its code.
    fn report_pairings(&mut self, root: &TransportRoot, rescan: bool) {
        let transport = self
            .vaults
            .values()
            .find(|vault| vault.root.as_ref() == Some(root))
            .and_then(|vault| vault.transport.clone());
        let Some(transport) = transport else {
            return;
        };
        let dismissed = DismissedRequests::load(self.files().root()).of(root);
        let own = self
            .pairing
            .as_ref()
            .and_then(|pairing| pairing.watcher.request_id());
        let prompting = match PairingPrompt::prompting(&*transport, &dismissed, self.timestamp()) {
            Ok(prompting) => prompting
                .into_iter()
                .filter(|id| Some(*id) != own)
                .collect::<Vec<_>>(),
            Err(e) => {
                sync_log::record(
                    sync_log::Level::Warn,
                    None,
                    "Failed to list the pairing requests",
                    Some(format!("{root}: {e}")),
                );
                return;
            },
        };
        for id in &prompting {
            if let Err(e) = transport.request_pairing_download(*id) {
                sync_log::record(
                    sync_log::Level::Warn,
                    None,
                    "Failed to request the download of a pairing request",
                    Some(format!("{root}: {id}: {e}")),
                );
            }
        }
        let count = prompting.len();
        let last = self.pairing_counts.insert(root.clone(), count);
        if rescan {
            if last == Some(count) {
                return;
            }
            sync_log::record(
                sync_log::Level::Info,
                None,
                "Rescan found a change in the pairing requests that no watch event reported",
                Some(format!("{root}: {count} prompt")),
            );
        }
        self.events.pairing_requests(root, count);
    }

    /// Count the pairing requests of each root with a watch if the count
    /// with no watch event is due. A root in `counted` was just counted.
    fn rescan_pairings(&mut self, counted: &[TransportRoot]) {
        let now = self.now();
        if self.pairing_rescan_at > now {
            return;
        }
        self.pairing_rescan_at = now + RESCAN_INTERVAL;
        let roots: Vec<TransportRoot> = self
            .roots
            .keys()
            .filter(|root| !counted.contains(root))
            .cloned()
            .collect();
        for root in roots {
            self.report_pairings(&root, true);
        }
    }

    /// Synced vaults: each local sync state with a vault file in the catalog
    /// scan, and each `leaving` sync state, with or without a vault file.
    /// The scan tracks each vault in the vault locks.
    ///
    /// A sync state that is not `leaving`, of a vault file that holds no
    /// replica id, is left from a disable, such as a sync state restored
    /// after a disable finished. Its sync state, staged file, and sidecar are
    /// deleted under the vault locks (D8 of doc 18), and it is not listed.
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
                let target = listed.get(&id).cloned();
                let contents = fs::read_to_string(&path).ok()?;
                let peeked = LocalSyncState::peek(&contents)?;
                if peeked.vault_id != id || (target.is_none() && !peeked.leaving) {
                    return None;
                }
                if let Some(target) = &target
                    && !peeked.leaving
                    && self.delete_disabled(id, target)
                {
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
                    replica: peeked.replica_id,
                    root,
                    leaving: peeked.leaving,
                })
            })
            .collect()
    }

    /// Delete the sync files of vault `id` if its vault file at `target`
    /// holds no replica id ([`VaultWriter::delete_disabled_sync`]). The
    /// replica id is read first without verifying the file, so a synced
    /// vault takes no lock. Returns whether the files were deleted.
    fn delete_disabled(&self, id: Uuid, target: &Target) -> bool {
        if !matches!(VaultHeader::peek_replica_id(&target.path), Ok(None)) {
            return false;
        }
        match self.files().delete_disabled_sync(id, &target.path) {
            Ok(deleted) => deleted,
            Err(e) => {
                log::warn!("Failed to delete the sync files left by a disable of vault {id}: {e}");
                false
            },
        }
    }

    /// Find the synced vaults again. A vault no longer synced, or whose
    /// root, replica, or `leaving` changed, ends its watch. Returns the
    /// vaults added, which are watched and not yet scanned, and every
    /// `leaving` vault, whose scan is a copy of its final file.
    fn refresh(&mut self) -> Vec<Uuid> {
        let synced = self.synced();
        let locks = self.files().locks().clone();
        let kept: BTreeSet<Uuid> = synced
            .iter()
            .filter(|found| {
                self.vaults.get(&found.id).is_some_and(|vault| {
                    vault.root == found.root
                        && vault.replica == found.replica
                        && vault.leaving == found.leaving
                })
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
        let mut scanned = Vec::new();
        for found in synced {
            if let Some(vault) = self.vaults.get_mut(&found.id) {
                vault.target = found.target;
                if vault.leaving {
                    scanned.push(found.id);
                }
                continue;
            }
            let id = found.id;
            let mut vault = ManagedVault {
                id,
                target: found.target,
                replica: found.replica,
                root: found.root,
                leaving: found.leaving,
                transport: None,
                watch: None,
                reported: BTreeSet::new(),
                copy_pending: false,
                retry_at: None,
                rescan_at: None,
            };
            if !vault.leaving {
                self.connect(&mut vault);
            }
            self.vaults.insert(id, vault);
            scanned.push(id);
        }
        scanned
    }

    /// Resolve the transport of `vault` and watch it, for whichever is
    /// missing. Returns whether a watch started.
    fn connect(&self, vault: &mut ManagedVault) -> bool {
        let id = vault.id;
        if vault.transport.is_none() {
            match self.files().transport_of(vault.root.as_ref()) {
                Ok(transport) => vault.transport = transport,
                Err(e) => sync_log::warn(id, "Failed to resolve the transport", &e),
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
        if watched {
            sync_log::info(id, "Watch started");
        } else {
            sync_log::record(
                sync_log::Level::Warn,
                Some(id),
                "Failed to start the watch",
                None,
            );
        }
        watched
    }

    /// Scan vault `vault_id` for peer changes and react to them, then copy
    /// its staged file if a publish failed. A `leaving` vault has no
    /// transport, so its scan only copies. A change found after a watch
    /// event, as `after_event` states, is recorded in the sync log.
    fn scan(&mut self, vault_id: Uuid, after_event: bool) {
        let now = self.now();
        let Some(mut vault) = self.vaults.remove(&vault_id) else {
            return;
        };
        if vault.changes(self.files()) {
            if after_event {
                sync_log::info(vault_id, "Watch event found a peer change");
            }
            self.react(&mut vault);
        }
        if self.copy(&mut vault, now) {
            self.vaults.insert(vault_id, vault);
        }
    }

    /// Run a transaction for a peer change of `vault` if the app is
    /// unlocked, and otherwise set the pending flag (D5). A vault with no
    /// vault file runs none.
    fn react(&self, vault: &mut ManagedVault) {
        let id = vault.id;
        let Some(target) = &vault.target else {
            return;
        };
        let locks = self.files().locks();
        if !self.unlock.unlocked() {
            locks.set_pending(id);
            sync_log::info(id, "Peer change waits for the next unlock");
            self.events.peer_changed(id);
            return;
        }
        match self.unlock.transaction(self.files(), target) {
            Ok(committed) => {
                vault.target = Some(Target::of(&committed.vault));
                sync_log::info(id, "Joined a peer change");
                self.events.vault_synced(id);
            },
            Err(e) => {
                sync_log::warn(id, "Failed to join a peer change", &e);
                scan_status::record(
                    id,
                    ScanOutcome::Failed {
                        message: "Could not join a change from another device.".to_string(),
                    },
                );
                locks.set_pending(id);
            },
        }
    }

    /// Copy the staged file of `vault` if a publish failed, or the final
    /// file of a `leaving` vault, and schedule the next retry at `now`.
    /// Returns false if the copy deleted the sync files of a `leaving`
    /// vault, which the manager then drops.
    fn copy(&self, vault: &mut ManagedVault, now: Instant) -> bool {
        let id = vault.id;
        let path = vault.target.as_ref().map(|target| target.path.as_path());
        vault.copy_pending = match self.files().copy_staged(id, path) {
            Ok(StagedCopy::Left) => {
                sync_log::info(id, "Left sync");
                return false;
            },
            Ok(StagedCopy::Copied | StagedCopy::NotStaged) => false,
            Ok(StagedCopy::Refused) => true,
            Err(e) => {
                sync_log::warn(id, "Failed to copy the staged file", &e);
                true
            },
        };
        vault.schedule(now);
        true
    }

    /// Retry each vault whose retry or rescan is due: watch again a vault
    /// with no watch, scan it if the watch starts or the rescan is due, and
    /// copy a staged file whose copy failed. A `leaving` vault is never
    /// watched or rescanned, and copies only.
    fn retry_due(&mut self) {
        let now = self.now();
        let due: Vec<Uuid> = self
            .vaults
            .values()
            .filter(|vault| {
                vault.retry_at.is_some_and(|at| at <= now)
                    || vault.rescan_at.is_some_and(|at| at <= now)
            })
            .map(|vault| vault.id)
            .collect();
        for vault_id in due {
            let Some(mut vault) = self.vaults.remove(&vault_id) else {
                continue;
            };
            let rescan = vault.rescan_at.is_some_and(|at| at <= now);
            vault.retry_at = None;
            vault.rescan_at = None;
            let watched = !vault.leaving && vault.watch.is_none() && self.connect(&mut vault);
            if (watched || rescan) && vault.changes(self.files()) {
                let message = if watched {
                    "Scan after the watch started again found a peer change"
                } else if vault.watch.is_some() {
                    "Rescan found a peer change that no watch event reported"
                } else {
                    "Rescan found a peer change and the vault has no watch"
                };
                sync_log::info(vault_id, message);
                self.react(&mut vault);
            } else if rescan {
                log::debug!("Rescan of vault {vault_id} found no peer change");
            }
            let kept = if watched || vault.copy_pending {
                self.copy(&mut vault, now)
            } else {
                vault.schedule(now);
                true
            };
            if kept {
                self.vaults.insert(vault_id, vault);
            }
        }
    }
}

impl ManagedVault {
    /// Schedule the next retry after `now` if a copy is pending, or if the
    /// vault has no watch and is not `leaving`. Schedule the next rescan
    /// unless the vault is `leaving`.
    fn schedule(&mut self, now: Instant) {
        let unwatched = self.watch.is_none() && !self.leaving;
        self.retry_at = (unwatched || self.copy_pending).then(|| now + RETRY_INTERVAL);
        self.rescan_at = (!self.leaving).then(|| now + RESCAN_INTERVAL);
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
                sync_log::warn(id, "Failed to list the peer state files", &e);
                scan_status::record(
                    id,
                    ScanOutcome::Failed {
                        message: "Could not read the synced folder.".to_string(),
                    },
                );
                return false;
            },
        };
        let mut found = false;
        let mut waiting: u32 = 0;
        for file in &changed {
            if self.reported.contains(file) {
                continue;
            }
            let (replica, hash) = *file;
            match transport.is_local(id, replica, FileName::State(hash)) {
                Ok(true) => {
                    self.reported.insert(*file);
                    found = true;
                    sync_log::record(
                        sync_log::Level::Info,
                        Some(id),
                        "Peer state file found",
                        Some(format!("{} {hash}", replica.0)),
                    );
                },
                Ok(false) => waiting += 1,
                Err(e) => {
                    sync_log::warn(id, "Failed to check a state file", &format!("{hash}: {e}"));
                    waiting += 1;
                },
            }
        }
        self.reported.retain(|file| changed.contains(file));
        scan_status::record(
            id,
            if waiting == 0 {
                ScanOutcome::Synced
            } else {
                ScanOutcome::Waiting { files: waiting }
            },
        );
        if waiting > 0 {
            sync_log::info(id, "Peer state file is not downloaded, download requested");
            if let Err(e) = transport.request_download(id) {
                sync_log::warn(id, "Failed to request the download", &e);
            }
        }
        found
    }
}
