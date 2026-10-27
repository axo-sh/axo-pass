//! Per-vault locks shared by the writers of one process.

use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};

use uuid::Uuid;

use super::vault_file;
use crate::secrets::vaults::errors::Error;

/// Locks shared by the app and the broker, which run in one process.
static GLOBAL_LOCKS: LazyLock<VaultLocks> = LazyLock::new(VaultLocks::default);

/// In-process lock entries of vaults, by vault id.
///
/// Each entry holds the per-vault mutex, the current path of the vault file,
/// a save counter, and a flag set if the vault was deleted. The mutex
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
                    }),
                    saves: AtomicU64::new(0),
                })
            })
            .clone()
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
}

#[derive(Debug)]
pub(super) struct VaultLockState {
    /// Current path of the vault file.
    path: PathBuf,
    /// Set if the vault was deleted. A writer that waited for the mutex
    /// fails.
    removed: bool,
}

impl VaultLockState {
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
