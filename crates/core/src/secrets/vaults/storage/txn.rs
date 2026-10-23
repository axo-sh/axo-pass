//! Transactional vault writes.
//!
//! Every vault write goes through [`VaultWriter::write`],
//! [`VaultWriter::create`], or [`VaultWriter::delete`]. A write unwraps the
//! file key first, which can prompt. It then takes the per-vault mutex and
//! the cross-process lock, reloads the file, applies the change, retains the
//! replaced file, and saves. No keychain call that can prompt runs while the
//! locks are held. Signing with `device-signing-key` never prompts, so it may
//! run under the locks.
//!
//! Reads do not lock. Saves replace the file by renaming, so a read sees
//! either the old or the new file.

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use uuid::Uuid;

use crate::core::auth::AuthContext;
use crate::core::dirs::app_data_dir;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::encrypted_vault::{EncryptedVault, VaultHeader};
#[cfg(test)]
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::format::signing::{KeychainSigner, VaultSigner};
use crate::secrets::vaults::model::{UnlockedKey, Vault};
use crate::secrets::vaults::storage::handle::{
    VaultHandle, check_vault_auth_still_valid, get_vault_encryption_key_on,
};

mod locks;
mod vault_file;
mod versions;

pub use locks::VaultLocks;
use locks::{Locked, VaultLock};
pub use versions::RetainedVersion;
use versions::{VersionsDir, now_ms};

/// Attempts to open a vault whose wrapped file key changed after it was
/// unwrapped.
const MAX_ATTEMPTS: usize = 3;

/// Writer of vault files under the app data directory. It owns the retained
/// versions and lock files, and runs the transactional write, create, and
/// delete.
#[derive(Clone, Debug)]
pub struct VaultWriter {
    root: PathBuf,
    locks: VaultLocks,
    signer: Arc<dyn VaultSigner>,
}

impl Default for VaultWriter {
    fn default() -> Self {
        Self::app()
    }
}

impl VaultWriter {
    /// The app data directory, the global locks, and the keychain signer.
    pub fn app() -> Self {
        Self {
            root: app_data_dir(),
            locks: VaultLocks::global(),
            signer: Arc::new(KeychainSigner),
        }
    }

    /// Writer under `root` with its own locks, separate from the global locks.
    /// It signs with the test device key.
    #[cfg(test)]
    pub fn isolated(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            locks: VaultLocks::default(),
            signer: Arc::new(TestSigner::device()),
        }
    }

    pub fn locks(&self) -> &VaultLocks {
        &self.locks
    }

    /// Signer for vault files.
    pub fn signer(&self) -> &Arc<dyn VaultSigner> {
        &self.signer
    }

    /// Retained versions of vault `id`.
    fn versions(&self, id: Uuid) -> VersionsDir {
        VersionsDir::at(self.root.join("versions").join(id.to_string()))
    }

    fn lock_path(&self, id: Uuid) -> PathBuf {
        self.root.join("locks").join(format!("{id}.lock"))
    }

    /// Exclusive `flock` on the lock file of vault `id`. The kernel releases
    /// it when the file closes, including when the process exits.
    fn lock_file(&self, id: Uuid) -> Result<File, Error> {
        let path = self.lock_path(id);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(Error::VaultLockError)?;
        }
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(Error::VaultLockError)?;
        file.lock().map_err(Error::VaultLockError)?;
        Ok(file)
    }

    /// Take the locks of vault `id` through `entry`.
    fn lock_entry<'a>(&self, entry: &'a VaultLock, id: Uuid) -> Result<Locked<'a>, Error> {
        entry.lock(id, || self.lock_file(id))
    }
}

/// How a transaction gets the vault file key.
pub enum Unlock<'a> {
    /// The shared context the app authenticated. Fails if its authentication
    /// lapsed, instead of prompting.
    App,
    /// Use the file key of a vault already unlocked in memory. No keychain
    /// call runs.
    Unlocked(&'a VaultHandle),
    /// Call a function for the key, for tests.
    #[cfg(test)]
    Test(&'a (dyn Fn() -> UnlockedKey + Sync)),
}

impl Unlock<'_> {
    /// Vault id and unwrapped file key of the vault at `path`.
    fn key(&self, path: &Path) -> Result<(Uuid, UnlockedKey), Error> {
        match self {
            Unlock::App => {
                check_vault_auth_still_valid()?;
                Self::unwrap_key(path, AuthContext::SharedThreadLocal)
            },
            Unlock::Unlocked(vh) => Ok((vh.vault_id()?, vh.unlocked_key()?)),
            #[cfg(test)]
            Unlock::Test(key) => Ok((VaultHeader::peek(path)?.id, key())),
        }
    }

    fn unwrap_key(path: &Path, context: AuthContext) -> Result<(Uuid, UnlockedKey), Error> {
        let enc_vault = EncryptedVault::load(path)?;
        let managed_key = get_vault_encryption_key_on(context)?;
        let key = UnlockedKey::unwrap(&managed_key, &enc_vault)
            .inspect_err(|e| log::debug!("failed to unwrap the vault file key: {e}"))
            .map_err(|_| Error::VaultFileKeyDecryptionError)?;
        Ok((enc_vault.id, key))
    }
}

/// Vault a transaction writes: its key, and the path where the caller found
/// it.
#[derive(Clone, Debug)]
pub struct Target {
    pub key: String,
    pub path: PathBuf,
}

impl Target {
    pub fn new(key: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            key: key.into(),
            path: path.into(),
        }
    }

    pub fn of(vh: &VaultHandle) -> Self {
        Self::new(vh.key.clone(), vh.path.clone())
    }
}

/// Result of a transaction.
pub struct Committed<R> {
    pub value: R,
    /// Vault as saved, unlocked.
    pub vault: VaultHandle,
    pub vault_id: Uuid,
    /// Key the caller knew the vault by. It differs from the key of `vault` if
    /// the transaction renamed the vault, or found it renamed.
    pub previous_key: String,
    /// Whether the vault changed and was written.
    pub changed: bool,
    /// Save count of the vault when the transaction ended. The saved copy is
    /// current while [`VaultLocks::is_current`] holds for this count.
    pub save_count: u64,
}

/// Outcome of one attempt of [`VaultWriter::write`].
enum Attempt<R, F> {
    Done(Committed<R>),
    /// The wrapped file key changed. Holds the unused transaction function.
    Retry(F),
}

impl VaultWriter {
    /// Run `f` on a fresh copy of the vault and save the result.
    ///
    /// The file key is unwrapped before the locks are taken. Under the locks
    /// the file is reloaded, and decrypted with that key only if its wrapped
    /// file key is unchanged. Otherwise the locks are released and the key is
    /// unwrapped again. `f` runs once, under the locks. If `f` fails, nothing
    /// is written. If the vault did not change, nothing is written and no
    /// version is retained.
    pub fn write<R, E>(
        &self,
        target: &Target,
        unlock: Unlock<'_>,
        mut f: impl FnOnce(&mut VaultHandle) -> Result<R, E>,
    ) -> Result<Committed<R>, E>
    where
        E: From<Error>,
    {
        for _ in 0..MAX_ATTEMPTS {
            match self.attempt(target, &unlock, f)? {
                Attempt::Done(committed) => return Ok(committed),
                Attempt::Retry(unused) => f = unused,
            }
        }
        Err(Error::VaultFileKeyChanged.into())
    }

    /// One attempt of [`Self::write`]. `f` is returned in `Retry` if it did not
    /// run.
    fn attempt<R, E, F>(
        &self,
        target: &Target,
        unlock: &Unlock<'_>,
        f: F,
    ) -> Result<Attempt<R, F>, E>
    where
        E: From<Error>,
        F: FnOnce(&mut VaultHandle) -> Result<R, E>,
    {
        // Unwrap the file key first. This may prompt.
        let (id, file_key) = unlock.key(&target.path)?;

        // Take the per-vault mutex and the cross-process lock.
        let vault_lock = self.locks.entry(id, &target.path);
        let mut locked = self.lock_entry(&vault_lock, id)?;
        let path = locked.state.resolve(id, &target.path)?;

        // Re-read the file under the locks and decrypt it with the file key.
        let contents = EncryptedVault::read_file(&path)?;
        let enc_vault = EncryptedVault::parse(&contents)?;
        if enc_vault.id != id {
            return Err(Error::VaultNotFound(path.display().to_string()).into());
        }
        let vault = match Vault::from_unlocked_key(&file_key, enc_vault) {
            // Another writer rewrapped the file key. Release the locks and
            // unwrap again.
            Err(Error::VaultFileKeyChanged) => {
                log::warn!("Vault {id} file key changed after it was unwrapped, unwrapping again");
                return Ok(Attempt::Retry(f));
            },
            other => other?,
        };

        // Name the vault by the caller's key. If another writer renamed the
        // vault since the caller found it, use the new file name.
        let key = if path == target.path {
            target.key.clone()
        } else {
            path.file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| target.key.clone())
        };
        let mut vh = VaultHandle::unlocked(key, path.clone(), vault);

        // Apply the change. An error leaves the file unchanged.
        let value = f(&mut vh)?;

        // Save only if the vault changed.
        let changed = vault_file::commit(&path, &contents, &vh, |old| self.retain(id, old))?;
        let save_count = if changed {
            locked.state.set_path(vh.path.clone());
            vault_lock.record_save()
        } else {
            vault_lock.save_count()
        };
        Ok(Attempt::Done(Committed {
            value,
            vault: vh,
            vault_id: id,
            previous_key: target.key.clone(),
            changed,
            save_count,
        }))
    }

    /// [`Self::write`] on a vault already unlocked in memory, with its
    /// file key. No keychain call runs.
    pub fn write_unlocked<R, E>(
        &self,
        vh: &VaultHandle,
        f: impl FnOnce(&mut VaultHandle) -> Result<R, E>,
    ) -> Result<Committed<R>, E>
    where
        E: From<Error>,
    {
        self.write(&Target::of(vh), Unlock::Unlocked(vh), f)
    }

    /// Write a new vault file. Fails if a file exists at its path, or if
    /// another file holds its vault id. Writes once and retains no version.
    /// Returns the save count.
    pub fn create(&self, vh: &VaultHandle) -> Result<u64, Error> {
        let id = vh.vault_id()?;
        let entry = self.locks.entry(id, &vh.path);
        let mut locked = self.lock_entry(&entry, id)?;
        vault_file::check_create_path(locked.state.path(), id, &vh.path)?;

        let contents = vh.file_contents()?;
        if let Some(dir) = vh.path.parent() {
            fs::create_dir_all(dir).map_err(Error::VaultDirCreateError)?;
        }
        vault_file::write_new(vh, &contents)?;
        locked.state.set_path(vh.path.clone());
        Ok(entry.record_save())
    }

    /// Remove the vault file at `path` with `remove`, such as a move to the
    /// Trash, under the vault locks. A writer that waits for the locks then
    /// fails, so it cannot recreate the file. Retained versions are kept, so a
    /// vault restored from the Trash keeps them. [`Self::prune_all`] deletes
    /// them once they expire.
    pub fn delete(
        &self,
        path: &Path,
        remove: impl FnOnce(&Path) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let id = VaultHeader::peek(path)?.id;
        let entry = self.locks.entry(id, path);
        let mut locked = self.lock_entry(&entry, id)?;
        let path = locked.state.resolve(id, path)?;
        remove(&path)?;
        locked.state.mark_removed();
        self.locks.remove(id, &entry);
        Ok(())
    }

    /// Retained versions of vault `id`, newest first. Versions past retention
    /// are deleted first.
    pub fn list_versions(&self, id: Uuid) -> Result<Vec<RetainedVersion>, Error> {
        self.versions(id)
            .prune(now_ms())
            .map_err(Error::VaultReadError)
    }

    /// Replace the vault with its retained version `name`. The replaced file
    /// is retained in turn.
    pub fn restore_version(
        &self,
        target: &Target,
        unlock: Unlock<'_>,
        name: &str,
    ) -> Result<Committed<()>, Error> {
        if RetainedVersion::parse(name).is_none() {
            return Err(Error::VaultVersionNotFound(name.to_string()));
        }
        self.write(target, unlock, |vh| {
            let id = vh.vault_id()?;
            let path = self.versions(id).file(name);
            let contents = EncryptedVault::read_file(&path).map_err(|e| match e {
                Error::VaultNotFound(_) => Error::VaultVersionNotFound(name.to_string()),
                e => e,
            })?;
            let enc_vault = EncryptedVault::parse(&contents)?;
            if enc_vault.id != id {
                return Err(Error::VaultVersionNotFound(name.to_string()));
            }
            let vault = Vault::from_unlocked_key(&vh.unlocked_key()?, enc_vault).map_err(|e| {
                if matches!(e, Error::VaultFileKeyChanged) {
                    Error::VaultVersionKeyChanged(name.to_string())
                } else {
                    e
                }
            })?;
            vh.replace_vault(vault);
            Ok(())
        })
    }

    /// Delete every retained version of vault `id`, found at `path`. The vault
    /// locks are held, so no save adds a version meanwhile. Returns the number
    /// of versions deleted.
    pub fn erase_versions(&self, id: Uuid, path: &Path) -> Result<usize, Error> {
        let entry = self.locks.entry(id, path);
        let _locked = self.lock_entry(&entry, id)?;
        self.versions(id).erase()
    }

    /// Prune the retained versions of every vault, including vaults deleted
    /// outside the app, and remove empty version directories. Retention runs
    /// on each save, so this covers vaults that are not saved again. Failures
    /// are logged.
    pub fn prune_all(&self) {
        let root = self.root.join("versions");
        let entries = match fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return,
            Err(e) => {
                log::error!("Failed to read {}: {e}", root.display());
                return;
            },
        };
        let now = now_ms();
        for path in entries.flatten().map(|entry| entry.path()) {
            if !path.is_dir() {
                continue;
            }
            let dir = VersionsDir::at(path);
            match dir.prune(now) {
                // A save that retains a version at the same time creates the
                // directory again.
                Ok(kept) if kept.is_empty() => {
                    let _ = fs::remove_dir(&dir.path);
                },
                Ok(_) => {},
                Err(e) => log::error!("Failed to prune {}: {e}", dir.path.display()),
            }
        }
    }

    /// Retain `contents`, the vault as it was before a save, and prune the
    /// versions. A failure is logged and does not fail the save.
    fn retain(&self, id: Uuid, contents: &str) {
        let dir = self.versions(id);
        let now = now_ms();
        if let Err(e) = dir.add(now, contents) {
            log::error!("Failed to retain a version of vault {id}: {e}");
        }
        if let Err(e) = dir.prune(now) {
            log::error!("Failed to prune the retained versions of vault {id}: {e}");
        }
    }
}

/// Vault locks held on another thread until dropped, for tests of code that
/// waits for them.
#[cfg(test)]
pub(crate) struct HeldForTest {
    release: std::sync::mpsc::Sender<()>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(test)]
impl Drop for HeldForTest {
    fn drop(&mut self) {
        let _ = self.release.send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
impl VaultWriter {
    /// Take the locks of vault `id` on another thread and hold them until the
    /// result is dropped.
    pub(crate) fn hold_for_test(&self, id: Uuid, path: &Path) -> HeldForTest {
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let files = self.clone();
        let path = path.to_path_buf();
        let thread = std::thread::spawn(move || {
            let entry = files.locks.entry(id, &path);
            let _locked = files.lock_entry(&entry, id).unwrap();
            locked_tx.send(()).unwrap();
            let _ = release_rx.recv();
        });
        locked_rx.recv().unwrap();
        HeldForTest {
            release: release_tx,
            thread: Some(thread),
        }
    }
}

#[cfg(test)]
mod tests;
