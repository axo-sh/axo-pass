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
//! A write to a vault with a trusted sync state joins this replica's own state
//! files, runs the change, and records its local edits in the sync state
//! (`sync/txn.rs`). A synced vault at `v < s`, or of another replica id than
//! its sync state, is rebuilt from the sync state before the change. `s`
//! advances if and only if the vault file changes. The staged file is
//! written first, then the sync state, then the vault, and the staged file is
//! then copied to the synced folder. A sync state under a key id the unlock
//! did not unwrap is unlocked once more. A second miss saves the vault only.
//! [`VaultWriter::rebuild`] and
//! [`VaultWriter::restore_refused`] replace a refused or missing vault file
//! without loading it. A replaced refused file is kept as an invalid file.
//!
//! Reads do not lock. Saves replace the file by renaming, so a read sees
//! either the old or the new file.

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use jiff::Timestamp;
use uuid::Uuid;

use crate::core::auth::AuthContext;
use crate::core::dirs::app_data_dir;
use crate::core::files::write_atomic;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::encrypted_vault::{EncryptedVault, VaultHeader};
use crate::secrets::vaults::format::short_id::ShortId;
#[cfg(test)]
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::format::signing::{KeychainSigner, VaultSigner};
use crate::secrets::vaults::model::{UnlockedKey, Vault};
use crate::secrets::vaults::storage::handle::{
    VaultHandle, check_vault_auth_still_valid, get_vault_encryption_key_on,
};
use crate::secrets::vaults::sync::keys::SyncKeyring;
#[cfg(test)]
use crate::secrets::vaults::sync::keys::TestKeyWrapper;
use crate::secrets::vaults::sync::load::{Mismatch, SyncLoad};
use crate::secrets::vaults::sync::local_state::LocalSyncState;
use crate::secrets::vaults::sync::rebuild::Rebuild;
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::transport::SyncTransport;
use crate::secrets::vaults::sync::txn::SyncTxn;

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
    /// Synced folder of this replica's own state files. `None` until
    /// milestone 7 builds the transports.
    transport: Option<Arc<dyn SyncTransport>>,
    /// Seconds added to the clock of mints. Zero outside the tests.
    clock_offset: i64,
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
            transport: None,
            clock_offset: 0,
        }
    }

    /// Writer under `root` with its own locks, separate from the global locks.
    /// It signs with the test device key.
    #[cfg(test)]
    pub fn isolated(root: impl Into<PathBuf>) -> Self {
        Self::isolated_with_signer(root, TestSigner::device())
    }

    /// [`Self::isolated`] with `signer` instead of the test device key, as
    /// another Mac.
    #[cfg(test)]
    pub fn isolated_with_signer(root: impl Into<PathBuf>, signer: TestSigner) -> Self {
        Self {
            root: root.into(),
            locks: VaultLocks::default(),
            signer: Arc::new(signer),
            transport: None,
            clock_offset: 0,
        }
    }

    /// This writer with the synced folder `transport`.
    #[cfg(test)]
    pub fn with_transport(self, transport: Arc<dyn SyncTransport>) -> Self {
        Self {
            transport: Some(transport),
            ..self
        }
    }

    /// This writer with `seconds` added to the clock of mints, as a Mac
    /// whose clock is off. Vault times keep the system clock.
    #[cfg(test)]
    pub fn with_clock_offset(self, seconds: i64) -> Self {
        Self {
            clock_offset: seconds,
            ..self
        }
    }

    /// App data directory of the retained versions, lock files, and sync
    /// files.
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn locks(&self) -> &VaultLocks {
        &self.locks
    }

    /// Signer for vault files.
    pub fn signer(&self) -> &Arc<dyn VaultSigner> {
        &self.signer
    }

    /// Retained versions of vault `id`, in a directory named by its short id.
    fn versions(&self, id: Uuid) -> VersionsDir {
        VersionsDir::at(self.root.join("versions").join(ShortId::encode_uuid(id)))
    }

    /// Lock file of vault `id`, named by its short id.
    fn lock_path(&self, id: Uuid) -> PathBuf {
        let id = ShortId::encode_uuid(id);
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

/// How a transaction gets the vault file key and the sync keyring.
pub enum Unlock<'a> {
    /// The shared context the app authenticated. Fails if its authentication
    /// lapsed, instead of prompting.
    App,
    /// Use the file key and keyring of a vault already unlocked in memory. No
    /// keychain call runs.
    Unlocked(&'a VaultHandle),
    /// Call a function for the file key, for tests. The keyring is unwrapped
    /// with [`TestKeyWrapper`] before the function is called.
    #[cfg(test)]
    Test(&'a (dyn Fn() -> UnlockedKey + Sync)),
}

/// Keys a transaction unlocks with.
struct UnlockedKeys {
    id: Uuid,
    file_key: UnlockedKey,
    /// Keyring of the local sync state as read before the locks. Empty if
    /// the vault is not synced or the sync state fails to load. `None` if the
    /// keyring fails to unwrap.
    keyring: Option<SyncKeyring>,
}

impl Unlock<'_> {
    /// Vault id, unwrapped file key, and sync keyring of the vault at `path`,
    /// with the sync files under the app data directory `root`. A file that
    /// is unwrapped is verified under the key of `signer` first.
    fn keys(
        &self,
        root: &Path,
        path: &Path,
        signer: &dyn VaultSigner,
    ) -> Result<UnlockedKeys, Error> {
        match self {
            Unlock::App => {
                check_vault_auth_still_valid()?;
                Self::unwrap_keys(root, path, signer, AuthContext::SharedThreadLocal)
            },
            Unlock::Unlocked(vh) => Ok(UnlockedKeys {
                id: vh.vault_id()?,
                file_key: vh.unlocked_key()?,
                keyring: Some(vh.keyring()?.clone()),
            }),
            #[cfg(test)]
            Unlock::Test(key) => {
                let enc_vault = EncryptedVault::load(path, signer)?;
                let keyring = SyncLoad::keyring(root, &enc_vault, signer, &TestKeyWrapper);
                Ok(UnlockedKeys {
                    id: enc_vault.id,
                    file_key: key(),
                    keyring,
                })
            },
        }
    }

    /// New file key of vault `id` and the sync keyring of its local sync
    /// state under the app data directory `root`, for a rebuild with no vault
    /// file that verifies. The keyring is `None` if it fails to unwrap. A
    /// vault unlocked in memory holds no vault encryption key to wrap a new
    /// file key, so `Unlocked` fails with `VaultLocked`.
    fn new_keys(
        &self,
        root: &Path,
        id: Uuid,
        signer: &dyn VaultSigner,
    ) -> Result<(UnlockedKey, Option<SyncKeyring>), Error> {
        match self {
            Unlock::App => {
                check_vault_auth_still_valid()?;
                let managed_key = get_vault_encryption_key_on(AuthContext::SharedThreadLocal)?;
                let file_key = UnlockedKey::generate(&managed_key, id)?;
                let keyring = SyncLoad::keyring_of(root, id, signer, &managed_key);
                Ok((file_key, keyring))
            },
            Unlock::Unlocked(_) => Err(Error::VaultLocked),
            #[cfg(test)]
            Unlock::Test(key) => {
                let keyring = SyncLoad::keyring_of(root, id, signer, &TestKeyWrapper);
                Ok((key(), keyring))
            },
        }
    }

    /// Unwrap the file key and the sync keyring with one vault encryption
    /// key read on `context`.
    fn unwrap_keys(
        root: &Path,
        path: &Path,
        signer: &dyn VaultSigner,
        context: AuthContext,
    ) -> Result<UnlockedKeys, Error> {
        let enc_vault = EncryptedVault::load(path, signer)?;
        let managed_key = get_vault_encryption_key_on(context)?;
        let file_key = UnlockedKey::unwrap(&managed_key, &enc_vault)
            .inspect_err(|e| log::debug!("failed to unwrap the vault file key: {e}"))
            .map_err(|_| Error::VaultFileKeyDecryptionError)?;
        let keyring = SyncLoad::keyring(root, &enc_vault, signer, &managed_key);
        Ok(UnlockedKeys {
            id: enc_vault.id,
            file_key,
            keyring,
        })
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
    /// the transaction changed the vault key, or found it changed.
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
    /// The sync state is under a key id the unlock did not unwrap. Holds the
    /// unused transaction function.
    KeyMissing(F),
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
    ///
    /// If the sync state is under a key id the unlock did not unwrap, the
    /// locks are released and the keys are unwrapped once more. A second
    /// miss saves the vault and leaves the sync state unchanged.
    pub fn write<R, E>(
        &self,
        target: &Target,
        unlock: Unlock<'_>,
        mut f: impl FnOnce(&mut VaultHandle) -> Result<R, E>,
    ) -> Result<Committed<R>, E>
    where
        E: From<Error>,
    {
        let mut retry_key_missing = true;
        for _ in 0..MAX_ATTEMPTS {
            match self.attempt(target, &unlock, retry_key_missing, f)? {
                Attempt::Done(committed) => return Ok(committed),
                Attempt::Retry(unused) => f = unused,
                Attempt::KeyMissing(unused) => {
                    retry_key_missing = false;
                    f = unused;
                },
            }
        }
        Err(Error::VaultFileKeyChanged.into())
    }

    /// One attempt of [`Self::write`]. `f` is returned in `Retry` or
    /// `KeyMissing` if it did not run. `KeyMissing` is returned only if
    /// `retry_key_missing` is set.
    fn attempt<R, E, F>(
        &self,
        target: &Target,
        unlock: &Unlock<'_>,
        retry_key_missing: bool,
        f: F,
    ) -> Result<Attempt<R, F>, E>
    where
        E: From<Error>,
        F: FnOnce(&mut VaultHandle) -> Result<R, E>,
    {
        // Unwrap the file key and the sync keyring first. This may prompt.
        let UnlockedKeys {
            id,
            file_key,
            keyring,
        } = unlock.keys(&self.root, &target.path, &*self.signer)?;

        // Take the per-vault mutex and the cross-process lock.
        let vault_lock = self.locks.entry(id, &target.path);
        let mut locked = self.lock_entry(&vault_lock, id)?;
        let path = locked.state.resolve(id, &target.path)?;

        // Re-read the file under the locks, verify it before the file key is
        // compared, and decrypt it with the file key.
        let contents = EncryptedVault::read_file(&path)?;
        let enc_vault = EncryptedVault::parse(&contents, &*self.signer)?;
        if enc_vault.id != id {
            return Err(Error::VaultNotFound(path.display().to_string()).into());
        }

        // Classify the file against the local sync state under the locks. A
        // `v < s` vault and a vault of another replica id are rebuilt from the
        // sync state. Any other case that needs a repair writes nothing.
        let loaded = LocalSyncState::load_hashed(&self.root, id, &*self.signer);
        let loaded_hash = loaded.as_ref().ok().map(|(_, hash)| *hash);
        let local = loaded.map(|(local, _)| local);
        let (case, trusted) =
            SyncLoad::classify_trusted(&enc_vault, local, keyring.as_ref(), &*self.signer)?;
        if retry_key_missing && matches!(case, SyncLoad::KeyMissing(_)) {
            log::info!("Vault {id} sync state is under a key the unlock lacks, unlocking again");
            return Ok(Attempt::KeyMissing(f));
        }
        let rebuild = matches!(
            case,
            SyncLoad::OlderVault { .. } | SyncLoad::Mismatch(Mismatch::ReplicaId(_))
        );
        // A file of another replica id is refused, so it is kept as an
        // invalid file. A `v < s` file is retained as a version.
        let refused = matches!(case, SyncLoad::Mismatch(_));
        let mut sync = match (trusted, keyring, loaded_hash) {
            (Some(trusted), Some(keyring), Some(hash)) if rebuild || case == SyncLoad::Current => {
                let sidecar = Sidecar::load(&self.root, id);
                Some(SyncTxn::new(trusted, keyring, hash, sidecar))
            },
            _ => {
                case.check()?;
                None
            },
        };

        let mut vault = match Vault::from_unlocked_key(&file_key, enc_vault) {
            // Another writer rewrapped the file key. Release the locks and
            // unwrap again.
            Err(Error::VaultFileKeyChanged) => {
                log::warn!("Vault {id} file key changed after it was unwrapped, unwrapping again");
                return Ok(Attempt::Retry(f));
            },
            other => other?,
        };

        // Join this replica's own state files, then the peer files, before
        // any write id is minted. A rebuilt vault takes the id, key, and file
        // key of the file it replaces, which verified, and holds the view of
        // the joined state.
        let mut session = None;
        if let Some(sync) = &mut sync {
            let session = session.insert(locked.state.session(sync.replica(), sync.loaded()));
            let joined = match &self.transport {
                Some(transport) => {
                    let own = sync.join_own(&**transport, session);
                    sync.join_peers(&**transport, session) || own
                },
                None => false,
            };
            if rebuild {
                vault = sync.rebuilt_vault(vault.key().to_string(), &vault.unlocked_key())?;
            } else if joined {
                sync.apply(&mut vault)?;
            }
        }

        // The key comes from the vault. It differs from the caller's key if
        // another writer changed the key since the caller found the vault.
        let keyring = sync
            .as_ref()
            .map(|sync| sync.keyring().clone())
            .unwrap_or_default();
        let mut vh = VaultHandle::unlocked_with_keyring(path.clone(), vault, keyring);

        // Apply the change. An error leaves the files unchanged.
        let value = f(&mut vh)?;

        let changed = match (&mut sync, session) {
            (Some(sync), Some(session)) => {
                // A recorded edit can change the shown keys of a duplicate
                // key group, such as a trash of the entry that holds the
                // bare key. The view of the recorded state is applied, so
                // the vault shows those keys and the next diff finds no
                // edits.
                let now = Timestamp::now().as_second() + self.clock_offset;
                if sync
                    .record(vh.get_unlocked_vault()?, session, now)?
                    .is_some()
                {
                    sync.apply(vh.get_unlocked_vault_mut()?)?;
                }
                // `s` advances if and only if the vault file changes. A key
                // change writes the same path. A rebuild always changes the
                // vault file.
                let vault_changed = vault_file::is_changed(&contents, &vh)?;
                if vault_changed {
                    let vault = vh.get_unlocked_vault_mut()?;
                    vault.set_sync(sync.generation() + 1, vault.replica_id());
                }
                // The staged file is written before the sync state that names
                // it.
                sync.stage(&self.root)?;

                // The sync state is saved before the vault, whenever it or
                // `s` changes.
                let mut saved = None;
                let result = if vault_changed {
                    vault_file::commit(&path, &contents, &vh, &*self.signer, |old| {
                        if refused {
                            self.keep_invalid(id, old.as_bytes())?;
                        } else {
                            self.retain(id, old);
                        }
                        saved = Some(sync.save(&self.root, &*self.signer, true)?);
                        Ok(())
                    })
                } else if sync.needs_save() {
                    sync.save(&self.root, &*self.signer, false).map(|hash| {
                        saved = Some(hash);
                        false
                    })
                } else {
                    Ok(false)
                };
                // A sync state that failed to save ends the actor, so no
                // write id it minted is minted again. The staged file this
                // transaction wrote holds that write id, so it is deleted.
                match saved {
                    Some(hash) => locked.state.record_saved_state(hash),
                    None if result.is_err() => {
                        sync.discard_staged(&self.root);
                        locked.state.end_actor();
                    },
                    None => {},
                }
                let changed = result?;
                // No signed save follows the vault save. A failed copy does
                // not fail the save.
                if let Some(transport) = &self.transport {
                    sync.publish(&**transport);
                }
                sync.save_sidecar(&self.root);
                changed
            },
            // Save only if the vault changed. A key change writes the same
            // path.
            _ => vault_file::commit(&path, &contents, &vh, &*self.signer, |old| {
                self.retain(id, old);
                Ok(())
            })?,
        };
        let save_count = if changed {
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

        let contents = vh.file_contents(&*self.signer)?;
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

    /// Replace the vault with its retained version `name`. The version is
    /// verified first, and a version whose signature fails is not restored.
    /// The replaced file is retained in turn. The vault key, the sync
    /// generation, and the replica id are kept. A version with another
    /// replica id is not restored.
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
            let enc_vault = EncryptedVault::parse(&contents, &*self.signer)?;
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
            vh.restore_vault(vault)
        })
    }

    /// Replace a refused vault file, one that fails to load, with its retained
    /// version `name`, without loading the refused file. The vault id is read
    /// from the refused file header without verifying it, and only picks the
    /// versions directory. The version is verified and its file key unwrapped
    /// before the locks. A version whose signature fails is not restored. The
    /// refused file is kept as an invalid file. A synced version older than a
    /// trusted sync state of its replica id takes the sync state generation,
    /// as [`Self::restore_version`] does. Any other case that needs a repair
    /// writes nothing. Fails with `VaultNotRefused` if the file verifies.
    pub fn restore_refused(
        &self,
        target: &Target,
        unlock: Unlock<'_>,
        name: &str,
    ) -> Result<Committed<()>, Error> {
        let not_found = |e| match e {
            Error::VaultNotFound(_) => Error::VaultVersionNotFound(name.to_string()),
            e => e,
        };
        if RetainedVersion::parse(name).is_none() {
            return Err(Error::VaultVersionNotFound(name.to_string()));
        }
        let id = VaultHeader::peek(&target.path)?.id;
        let version_path = self.versions(id).file(name);
        let UnlockedKeys {
            id: version_id,
            file_key,
            keyring,
        } = unlock
            .keys(&self.root, &version_path, &*self.signer)
            .map_err(not_found)?;
        if version_id != id {
            return Err(Error::VaultVersionNotFound(name.to_string()));
        }

        let entry = self.locks.entry(id, &target.path);
        let mut locked = self.lock_entry(&entry, id)?;
        let refused = self.refused_file(&locked, id, &target.path)?;

        let contents = EncryptedVault::read_file(&version_path).map_err(not_found)?;
        let enc_vault = EncryptedVault::parse(&contents, &*self.signer)?;
        let local = LocalSyncState::load(&self.root, id, &*self.signer);
        let case = SyncLoad::classify(&enc_vault, local, keyring.as_ref(), &*self.signer)?;
        let mut vault = Vault::from_unlocked_key(&file_key, enc_vault).map_err(|e| match e {
            Error::VaultFileKeyChanged => Error::VaultVersionKeyChanged(name.to_string()),
            e => e,
        })?;
        let keyring = match case {
            // A retained version of a synced vault is older than its sync
            // state.
            SyncLoad::OlderVault { state, .. } => {
                vault.set_sync(state, vault.replica_id());
                keyring.unwrap_or_default()
            },
            case => {
                case.check()?;
                case.with_keyring(keyring).1
            },
        };
        let vh = VaultHandle::unlocked_with_keyring(target.path.clone(), vault, keyring);
        let previous_key = target.key.clone();
        self.replace_refused(&entry, &mut locked, refused, vh, previous_key, || Ok(()))
    }

    /// Rebuild vault `id` at `path` from its trusted local sync state, for a
    /// vault file that is refused or missing. The rebuild takes a new file
    /// key, and the vault key that `choose_key` returns for the vault name of
    /// the view. A file at `path` is kept as an invalid file. The sync state
    /// is saved first, at the next generation, then the vault. Fails with
    /// `VaultNotRefused` if `path` holds a file of vault `id` that verifies,
    /// and with `SyncRepairNeeded` if the sync state is not trusted, belongs
    /// to another vault, or is `leaving`.
    pub fn rebuild(
        &self,
        id: Uuid,
        path: &Path,
        unlock: Unlock<'_>,
        choose_key: impl FnOnce(Option<&str>) -> Result<String, Error>,
    ) -> Result<Committed<()>, Error> {
        let (file_key, keyring) = unlock.new_keys(&self.root, id, &*self.signer)?;

        let entry = self.locks.entry(id, path);
        let mut locked = self.lock_entry(&entry, id)?;
        let refused = self.refused_file(&locked, id, path)?;

        let local = LocalSyncState::load(&self.root, id, &*self.signer);
        let trusted = SyncLoad::trust(local, keyring.as_ref(), &*self.signer)?.map_err(|case| {
            Error::SyncRepairNeeded(format!("sync state cannot rebuild the vault: {case}"))
        })?;
        if trusted.local.vault_id != id {
            let case = SyncLoad::Mismatch(Mismatch::VaultId(trusted.local.vault_id));
            return Err(Error::SyncRepairNeeded(case.to_string()));
        }
        if trusted.local.leaving {
            return Err(Error::SyncRepairNeeded(
                SyncLoad::DisableInProgress.to_string(),
            ));
        }
        // A trusted sync state was opened with the keyring.
        let keyring = keyring.unwrap_or_default();
        let rebuild = Rebuild::new(trusted, &keyring)?;
        let vault = rebuild.vault(choose_key(rebuild.name())?, &file_key)?;
        let vh = VaultHandle::unlocked_with_keyring(path.to_path_buf(), vault, keyring);
        let previous_key = vh.key.clone();
        self.replace_refused(&entry, &mut locked, refused, vh, previous_key, || {
            rebuild.save_state(&self.root, &*self.signer)
        })
    }

    /// Bytes of the refused file of vault `id` at `path`, read under the
    /// locks `locked`, or `None` if no file exists there. Fails if the vault
    /// locks track another file that holds the vault, or if the file at
    /// `path` is a file of the vault that verifies.
    fn refused_file(
        &self,
        locked: &Locked<'_>,
        id: Uuid,
        path: &Path,
    ) -> Result<Option<Vec<u8>>, Error> {
        vault_file::check_create_path(locked.state.path(), id, path)?;
        let refused = vault_file::read_bytes(path)?;
        if let Some(bytes) = &refused {
            vault_file::check_refused(path, bytes, id, &*self.signer)?;
        }
        Ok(refused)
    }

    /// Write `vh` at its path in place of the refused file `refused`, or as a
    /// new file if `refused` is `None`. The refused bytes are kept as an
    /// invalid file first, then `before_write` runs, then the vault is
    /// written. An error from either leaves the file unchanged.
    /// `previous_key` is the key the caller knew the vault by.
    fn replace_refused(
        &self,
        entry: &VaultLock,
        locked: &mut Locked<'_>,
        refused: Option<Vec<u8>>,
        vh: VaultHandle,
        previous_key: String,
        before_write: impl FnOnce() -> Result<(), Error>,
    ) -> Result<Committed<()>, Error> {
        let id = vh.vault_id()?;
        let contents = vh.file_contents(&*self.signer)?;
        if let Some(bytes) = &refused {
            self.keep_invalid(id, bytes)?;
        }
        before_write()?;
        if let Some(dir) = vh.path.parent() {
            fs::create_dir_all(dir).map_err(Error::VaultDirCreateError)?;
        }
        write_atomic(&vh.path, contents.as_bytes()).map_err(Error::VaultWriteError)?;
        locked.state.set_path(vh.path.clone());
        Ok(Committed {
            value: (),
            vault_id: id,
            previous_key,
            changed: true,
            save_count: entry.record_save(),
            vault: vh,
        })
    }

    /// Keep `contents`, a refused vault file of vault `id`, as an invalid
    /// file. A failure fails the save, so a refused file is never replaced
    /// without a copy.
    fn keep_invalid(&self, id: Uuid, contents: &[u8]) -> Result<(), Error> {
        self.versions(id)
            .add_invalid(now_ms(), contents)
            .map(|_| ())
            .map_err(Error::VaultWriteError)
    }

    /// Names of the invalid files of vault `id`, newest first.
    #[cfg(test)]
    pub(crate) fn list_invalid(&self, id: Uuid) -> Vec<String> {
        self.versions(id)
            .list_invalid()
            .unwrap()
            .into_iter()
            .map(|file| file.name)
            .collect()
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
