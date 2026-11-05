//! Per-vault locks shared by the writers of one process.

use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use uuid::Uuid;

use super::vault_file;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::sync::crdt::{ReplicaId, Session};
use crate::secrets::vaults::sync::state_file::StateHash;

/// Locks shared by the app and the broker, which run in one process.
static GLOBAL_LOCKS: LazyLock<VaultLocks> = LazyLock::new(VaultLocks::default);

/// Least time between two listings of the peer state files of a vault with
/// no live watch, by reads (D20).
pub(crate) const LISTING_INTERVAL: Duration = Duration::from_secs(60);

/// In-process lock entries of vaults, by vault id.
///
/// Each entry holds the per-vault mutex, the current path of the vault file,
/// a save counter, a flag set if the vault was deleted, and the sync session
/// with the hash of the sync state it saved last. It also holds the pending
/// flag of a peer change not yet joined, whether the vault has a live watch,
/// and the time of the last listing by a read. These are read without the
/// per-vault mutex. The mutex
/// serializes writers in this process. The cross-process lock file is taken
/// under it by [`VaultWriter`](super::VaultWriter).
///
/// There is one global instance, from [`Self::global`]. The app and the broker
/// run in one process and must share it. Writers with separate instances do
/// not exclude each other, and a save through one is invisible to
/// [`Self::is_current`] on the other. Production code uses
/// [`VaultWriter::app`](super::VaultWriter::app), which holds the global
/// instance. Tests use `VaultWriter::isolated` to get a private instance.
///
/// Clones share the entries.
#[derive(Clone, Debug, Default)]
pub struct VaultLocks {
    entries: Arc<Mutex<HashMap<Uuid, Arc<VaultLock>>>>,
}

impl VaultLocks {
    /// Locks of the app and the broker.
    pub fn global() -> Self {
        GLOBAL_LOCKS.clone()
    }

    fn entries(&self) -> MutexGuard<'_, HashMap<Uuid, Arc<VaultLock>>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Lock entry for `id`. A new entry starts at `path`.
    pub(super) fn entry(&self, id: Uuid, path: &Path) -> Arc<VaultLock> {
        self.entries()
            .entry(id)
            .or_insert_with(|| {
                Arc::new(VaultLock {
                    state: Mutex::new(VaultLockState {
                        path: path.to_path_buf(),
                        removed: false,
                        sync: None,
                    }),
                    saves: AtomicU64::new(0),
                    pending: AtomicU64::new(0),
                    watched: AtomicBool::new(false),
                    listed_at: Mutex::new(None),
                })
            })
            .clone()
    }

    /// Existing lock entry of vault `id`.
    fn get(&self, id: Uuid) -> Option<Arc<VaultLock>> {
        self.entries().get(&id).cloned()
    }

    /// Raise the pending epoch of vault `id` and set its pending flag, for a
    /// peer change that a read joins before it serves the vault. Returns
    /// false if the vault has no lock entry. The catalog scan tracks every
    /// listed vault.
    pub fn set_pending(&self, id: Uuid) -> bool {
        self.get(id).inspect(|entry| entry.set_pending()).is_some()
    }

    /// Whether the pending flag of vault `id` is set.
    pub fn is_pending(&self, id: Uuid) -> bool {
        self.get(id).is_some_and(|entry| entry.is_pending())
    }

    /// Pending epoch of vault `id`. Zero if the vault has no lock entry.
    pub fn pending_epoch(&self, id: Uuid) -> u64 {
        self.get(id).map_or(0, |entry| entry.pending_epoch())
    }

    /// Clear the pending flag of vault `id` if its epoch is still `epoch`.
    pub fn clear_pending(&self, id: Uuid, epoch: u64) {
        if let Some(entry) = self.get(id) {
            entry.clear_pending(epoch);
        }
    }

    /// Record whether vault `id` has a live watch.
    pub fn set_watched(&self, id: Uuid, watched: bool) {
        if let Some(entry) = self.get(id) {
            entry.watched.store(watched, Ordering::SeqCst);
        }
    }

    /// Whether a read of vault `id` at `now` lists its peer state files: the
    /// vault has no live watch, and no read listed them in the last
    /// [`LISTING_INTERVAL`]. A listing is recorded at `now` if so, so reads
    /// at the same time list once.
    pub(crate) fn take_listing(&self, id: Uuid, now: Instant) -> bool {
        let Some(entry) = self.get(id) else {
            return false;
        };
        if entry.watched.load(Ordering::SeqCst) {
            return false;
        }
        let mut listed_at = entry.listed_at.lock().unwrap_or_else(|e| e.into_inner());
        if listed_at.is_some_and(|at| now.saturating_duration_since(at) < LISTING_INTERVAL) {
            return false;
        }
        *listed_at = Some(now);
        true
    }

    /// Save count of vault `id`. `None` if the vault has no lock entry.
    pub fn save_count(&self, id: Uuid) -> Option<u64> {
        self.get(id).map(|entry| entry.save_count())
    }

    /// Record the path of a vault read from disk, if there is no lock entry
    /// for its id yet.
    pub fn track(&self, id: Uuid, path: &Path) {
        self.entry(id, path);
    }

    /// Whether a copy of vault `id` saved at count `saved` is still the newest
    /// save through these locks.
    pub fn is_current(&self, id: Uuid, saved: u64) -> bool {
        self.entries()
            .get(&id)
            .is_some_and(|entry| entry.save_count() == saved)
    }

    /// Whether the per-vault mutex of vault `id` is held, by any thread.
    #[cfg(test)]
    pub(crate) fn is_held(&self, id: Uuid) -> bool {
        self.get(id)
            .is_some_and(|entry| entry.state.try_lock().is_err())
    }

    /// Whether there is a lock entry for vault `id`.
    #[cfg(test)]
    pub(crate) fn contains(&self, id: Uuid) -> bool {
        self.entries().contains_key(&id)
    }

    /// Drop `entry` if it is still the entry of vault `id`.
    pub(super) fn remove(&self, id: Uuid, entry: &Arc<VaultLock>) {
        let mut entries = self.entries();
        if entries
            .get(&id)
            .is_some_and(|current| Arc::ptr_eq(current, entry))
        {
            entries.remove(&id);
        }
    }
}

/// Lock entry of one vault. Holding `state` is holding the per-vault mutex.
#[derive(Debug)]
pub(super) struct VaultLock {
    state: Mutex<VaultLockState>,
    /// Count of saves through this entry. A copy of the vault saved at count
    /// `n` is current while the count is still `n`. Readable without the mutex.
    saves: AtomicU64,
    /// Pending epoch shifted left by one, with the pending flag in the low
    /// bit, so a clear compares the epoch and clears the flag in one step.
    pending: AtomicU64,
    /// Whether the vault has a live watch.
    watched: AtomicBool,
    /// Time of the last listing of the peer state files by a read.
    listed_at: Mutex<Option<Instant>>,
}

/// The per-vault mutex and the cross-process lock of one vault. The lock file
/// is released first.
pub(super) struct Locked<'a> {
    _file: File,
    pub(super) state: MutexGuard<'a, VaultLockState>,
}

impl VaultLock {
    /// Take the per-vault mutex, then the `flock` from `lock_file`. Fails with
    /// `VaultNotFound` if vault `id` was deleted. The mutex excludes other
    /// threads. The `flock` excludes other processes. The order is the same
    /// everywhere.
    pub(super) fn lock(
        &self,
        id: Uuid,
        lock_file: impl FnOnce() -> Result<File, Error>,
    ) -> Result<Locked<'_>, Error> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.removed {
            return Err(Error::VaultNotFound(id.to_string()));
        }
        Ok(Locked {
            _file: lock_file()?,
            state,
        })
    }

    /// Count a save and return the new count.
    pub(super) fn record_save(&self) -> u64 {
        self.saves.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Count of saves so far.
    pub(super) fn save_count(&self) -> u64 {
        self.saves.load(Ordering::SeqCst)
    }

    /// Raise the pending epoch and set the pending flag.
    fn set_pending(&self) {
        let _ = self
            .pending
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                Some((((value >> 1) + 1) << 1) | 1)
            });
    }

    fn is_pending(&self) -> bool {
        self.pending.load(Ordering::SeqCst) & 1 == 1
    }

    /// Pending epoch, raised by each [`Self::set_pending`].
    pub(super) fn pending_epoch(&self) -> u64 {
        self.pending.load(Ordering::SeqCst) >> 1
    }

    /// Clear the pending flag if the epoch is still `epoch`. A flag set
    /// again since `epoch` was read stays set.
    pub(super) fn clear_pending(&self, epoch: u64) {
        let _ = self.pending.compare_exchange(
            (epoch << 1) | 1,
            epoch << 1,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
    }
}

#[derive(Debug)]
pub(super) struct VaultLockState {
    /// Current path of the vault file.
    path: PathBuf,
    /// Set if the vault was deleted. A writer that waited for the mutex
    /// fails.
    removed: bool,
    /// Session that mints the write ids of this vault, if the vault is
    /// synced.
    sync: Option<SyncSession>,
}

/// Session of a synced vault, and the content hash of the sync state this
/// process saved last.
#[derive(Debug)]
struct SyncSession {
    session: Session,
    /// `None` until the session saves a sync state.
    saved: Option<StateHash>,
}

impl VaultLockState {
    /// Session that mints write ids of `replica` into the sync state loaded
    /// from a file with hash `loaded`. The session continues only if this
    /// process saved that file last, for the same replica. Otherwise a new
    /// session starts, so the next mint starts a new actor.
    pub(super) fn session(&mut self, replica: ReplicaId, loaded: StateHash) -> &mut Session {
        let continues = self
            .sync
            .as_ref()
            .is_some_and(|sync| sync.session.replica == replica && sync.saved == Some(loaded));
        if !continues {
            self.sync = Some(SyncSession {
                session: Session::new(replica),
                saved: None,
            });
        }
        let sync = self.sync.as_mut().expect("session is set");
        &mut sync.session
    }

    /// Record `hash` as the content hash of the sync state this process saved
    /// last.
    pub(super) fn record_saved_state(&mut self, hash: StateHash) {
        if let Some(sync) = &mut self.sync {
            sync.saved = Some(hash);
        }
    }

    /// End the actor of the session, so the next mint starts a new actor.
    pub(super) fn end_actor(&mut self) {
        if let Some(sync) = &mut self.sync {
            sync.session.end();
        }
    }

    /// Current path of the vault file.
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// Path of the vault file, resolved under the locks and tracked.
    /// `caller_path` is where the caller found the vault. The tracked path is
    /// used if the vault was renamed since.
    pub(super) fn resolve(&mut self, id: Uuid, caller_path: &Path) -> Result<PathBuf, Error> {
        let path = vault_file::resolve(&self.path, id, caller_path)?;
        self.path = path.clone();
        Ok(path)
    }

    /// Track `path` as the current path of the vault file.
    pub(super) fn set_path(&mut self, path: PathBuf) {
        self.path = path;
    }

    /// Mark the vault as deleted.
    pub(super) fn mark_removed(&mut self) {
        self.removed = true;
    }
}
