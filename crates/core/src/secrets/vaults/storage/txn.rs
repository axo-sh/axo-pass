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
//! then copied to the synced folder. The transport of the synced folder is
//! resolved from the root in the sidecar of the vault. A sidecar with no root
//! gives no transport, and a root that fails to resolve pauses sync with
//! `Unreachable`. A sync state under a key id the unlock
//! did not unwrap is unlocked once more. A second miss saves the vault only.
//! Before any join, the no-edit guard diffs the vault as loaded against the
//! view of the sync state. If it finds edits, sync stops by drift, and the
//! transaction saves locally and publishes nothing. A `v < s` vault from a
//! period of stopped sync loads as it is and is not rebuilt. A `v > s` vault,
//! and a sync stopped by drift on another build or after the user override,
//! run a repair in place of the guard (`sync/repair.rs`). An apply or diff
//! failure pauses sync and never fails the save (`sync/txn.rs`).
//! [`VaultWriter::rebuild`] and
//! [`VaultWriter::restore_refused`] replace a refused or missing vault file
//! without loading it. A replaced refused file is kept as an invalid file.
//!
//! Reads do not lock. Saves replace the file by renaming, so a read sees
//! either the old or the new file.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

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
use crate::secrets::vaults::storage::resign::Resigned;
#[cfg(test)]
use crate::secrets::vaults::sync::apply::ApplyFault;
use crate::secrets::vaults::sync::diff::LocalEdits;
use crate::secrets::vaults::sync::keys::SyncKeyring;
#[cfg(test)]
use crate::secrets::vaults::sync::keys::TestKeyWrapper;
use crate::secrets::vaults::sync::load::{Mismatch, SyncLoad};
use crate::secrets::vaults::sync::local_state::LocalSyncState;
use crate::secrets::vaults::sync::rebuild::Rebuild;
use crate::secrets::vaults::sync::repair::{Repair, SyncRequest};
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::status::SyncStatus;
#[cfg(test)]
use crate::secrets::vaults::sync::transport::FixedTransport;
use crate::secrets::vaults::sync::transport::{SyncTransport, SyncTransports, TransportRoot};
use crate::secrets::vaults::sync::txn::SyncTxn;

mod locks;
mod vault_file;
mod versions;

pub use locks::VaultLocks;
use locks::{Locked, VaultLock};
pub use versions::RetainedVersion;
use versions::{VersionsDir, now_ms};

/// Directory of the retained versions under the app data directory.
pub(super) const VERSIONS_DIR: &str = "versions";

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
    /// Transports of the synced vaults, resolved from the root in the
    /// sidecar of each vault.
    transports: Arc<dyn SyncTransports>,
    /// Seconds added to the clock of mints. Zero outside the tests.
    clock_offset: i64,
    /// Item views whose apply fails, as on a build whose view cannot apply
    /// them.
    #[cfg(test)]
    apply_fault: Option<ApplyFault>,
}

impl Default for VaultWriter {
    fn default() -> Self {
        Self::app()
    }
}

impl VaultWriter {
    /// The app data directory, the global locks, the keychain signer, and
    /// the app transports.
    pub fn app() -> Self {
        Self {
            root: app_data_dir(),
            locks: VaultLocks::global(),
            signer: Arc::new(KeychainSigner),
            transports: Arc::new(AppTransports::default()),
            clock_offset: 0,
            #[cfg(test)]
            apply_fault: None,
        }
    }

    /// Writer under `root` with its own locks, separate from the global locks.
    /// It signs with the test device key and holds the app transports.
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
            transports: Arc::new(AppTransports::default()),
            clock_offset: 0,
            apply_fault: None,
        }
    }

    /// This writer with the apply of the sync state view failing at the
    /// first item for which `fault` holds, as a build whose view cannot
    /// apply it. `None` stands for a later build with a fixed view.
    #[cfg(test)]
    pub(crate) fn with_apply_fault(self, fault: Option<ApplyFault>) -> Self {
        Self {
            apply_fault: fault,
            ..self
        }
    }

    /// This writer with the synced folder `transport` for every synced vault,
    /// whatever the root in its sidecar.
    #[cfg(test)]
    pub fn with_transport(self, transport: Arc<dyn SyncTransport>) -> Self {
        Self {
            transports: Arc::new(FixedTransport(transport)),
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
        VersionsDir::at(self.root.join(VERSIONS_DIR).join(ShortId::encode_uuid(id)))
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

    /// Transport of the root in the sidecar of `sync`. `None` if the sidecar
    /// has no root. A root that fails to resolve pauses sync with
    /// `Unreachable` and gives no transport, so the transaction saves
    /// locally.
    fn transport(&self, sync: &mut SyncTxn) -> Option<Arc<dyn SyncTransport>> {
        match self.transports.resolve(sync.transport_root()) {
            Ok(transport) => transport,
            Err(e) => {
                let id = sync.vault_id();
                log::warn!("Failed to resolve the transport of vault {id}: {e}");
                sync.unreachable(e);
                None
            },
        }
    }
}

/// Transports of the app, one for each root, built at the first resolve of
/// the root and kept for the process. No root resolves until the folder
/// and iCloud transports are built.
#[derive(Debug, Default)]
pub struct AppTransports {
    built: Mutex<HashMap<TransportRoot, Arc<dyn SyncTransport>>>,
}

impl AppTransports {
    /// New transport of `root`.
    fn build(root: &TransportRoot) -> Result<Arc<dyn SyncTransport>, Error> {
        Err(Error::SyncTransportError(format!(
            "no transport is built for {root}"
        )))
    }
}

impl SyncTransports for AppTransports {
    fn resolve(
        &self,
        root: Option<&TransportRoot>,
    ) -> Result<Option<Arc<dyn SyncTransport>>, Error> {
        let Some(root) = root else {
            return Ok(None);
        };
        let mut built = self.built.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(transport) = built.get(root) {
            return Ok(Some(transport.clone()));
        }
        let transport = Self::build(root)?;
        built.insert(root.clone(), transport.clone());
        Ok(Some(transport))
    }
}

/// How a transaction gets the vault file key and the sync keyring.
pub enum Unlock<'a> {
    /// The shared context the app authenticated. Fails if its authentication
    /// lapsed, instead of prompting. Creates no key.
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
    /// file key, so `Unlocked` fails with `VaultLocked`. `App` creates no
    /// key. It fails with `VaultEncryptionKeyMissing` if the key is missing.
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
    /// Sync status the transaction found. `None` for a vault that is not
    /// synced or is being disabled, and for a rebuild or a restore over a
    /// refused file.
    pub sync_status: Option<SyncStatus>,
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
    /// miss saves a changed vault at the next generation and leaves the sync
    /// state unchanged, so the next load is `v > s` and the `v > s` repair
    /// adds the change.
    pub fn write<R, E>(
        &self,
        target: &Target,
        unlock: Unlock<'_>,
        f: impl FnOnce(&mut VaultHandle) -> Result<R, E>,
    ) -> Result<Committed<R>, E>
    where
        E: From<Error>,
    {
        self.write_as(target, unlock, SyncRequest::Change, f)
    }

    /// [`Self::write`], with `request` for the sync state.
    pub(crate) fn write_as<R, E>(
        &self,
        target: &Target,
        unlock: Unlock<'_>,
        request: SyncRequest,
        mut f: impl FnOnce(&mut VaultHandle) -> Result<R, E>,
    ) -> Result<Committed<R>, E>
    where
        E: From<Error>,
    {
        let mut retry_key_missing = true;
        for _ in 0..MAX_ATTEMPTS {
            match self.attempt(target, &unlock, request, retry_key_missing, f)? {
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

    /// One attempt of [`Self::write_as`]. `f` is returned in `Retry` or
    /// `KeyMissing` if it did not run. `KeyMissing` is returned only if
    /// `retry_key_missing` is set.
    fn attempt<R, E, F>(
        &self,
        target: &Target,
        unlock: &Unlock<'_>,
        request: SyncRequest,
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
        // sync state, and a `v > s` vault is repaired. Any other case that
        // needs a repair writes nothing.
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
        // A `v < s` vault from a period of stopped sync loads as it is.
        let loads = matches!(
            case,
            SyncLoad::Current | SyncLoad::StoppedOlderVault { .. } | SyncLoad::NewerVault { .. }
        );
        let mut sync = match (trusted, keyring, loaded_hash) {
            (Some(trusted), Some(keyring), Some(hash)) if rebuild || loads => {
                let sidecar = Sidecar::load(&self.root, id);
                let mut sync = SyncTxn::new(trusted, keyring, hash, sidecar);
                if let SyncLoad::NewerVault { vault, .. } = case {
                    sync.set_newer_vault(vault);
                }
                #[cfg(test)]
                sync.set_apply_fault(self.apply_fault);
                Some(sync)
            },
            _ => {
                case.check()?;
                None
            },
        };
        // The override runs only while it is offered, and writes nothing
        // otherwise.
        let confirmed = request == SyncRequest::Override;
        if confirmed
            && !sync
                .as_ref()
                .is_some_and(|s| !rebuild && s.override_offered())
        {
            return Err(Error::SyncOverrideNotOffered.into());
        }

        let mut vault = match Vault::from_unlocked_key(&file_key, enc_vault) {
            // Another writer rewrapped the file key. Release the locks and
            // unwrap again.
            Err(Error::VaultFileKeyChanged) => {
                log::warn!("Vault {id} file key changed after it was unwrapped, unwrapping again");
                return Ok(Attempt::Retry(f));
            },
            other => other?,
        };

        // The no-edit guard diffs the vault as loaded against the view of
        // the state as loaded, before any join and before the change. A
        // rebuilt vault replaces the loaded vault, so it is not diffed. The
        // `v > s` repair and the recovery merge run in place of the guard.
        //
        // Join this replica's own state files, then the peer files, before
        // any write id is minted. A repair adds the vault differences between
        // the two joins, so a value a peer changed is never compared with the
        // vault. A rebuilt vault takes the id, key, and file key of the file
        // it replaces, which verified, and holds the view of the joined
        // state. A stopped sync joins nothing.
        //
        // If the view of the joined state fails to apply, the join is
        // discarded, and the change runs on the vault as it was before the
        // join. A diff that fails, and an apply that fails in a repair, make
        // the transaction save the vault only, with no further join.
        //
        // The transport is resolved from the root in the sidecar only if
        // the transaction syncs.
        let mut session = None;
        let mut transport = None;
        let now = Timestamp::now().as_second() + self.clock_offset;
        if let Some(sync) = &mut sync {
            let repair = if rebuild {
                None
            } else {
                sync.repair(confirmed)
            };
            match repair {
                Some(repair) => sync.start_repair(repair),
                None if !rebuild => sync.guard(&vault)?,
                None => {},
            }
            let session = session.insert(locked.state.session(sync.replica(), sync.loaded()));
            if sync.syncs() {
                transport = self.transport(sync);
            }
            let transport = transport.as_deref();
            let mut changed = false;
            if let Some(transport) = transport.filter(|_| sync.syncs()) {
                changed |= sync.join_own(transport, session);
            }
            if repair.is_some() && sync.syncs() {
                changed |= sync.record_repair(&vault, session, now)?.is_some();
            }
            if let Some(transport) = transport.filter(|_| sync.syncs()) {
                changed |= sync.join_peers(transport, session);
            }
            if rebuild {
                vault = sync.rebuilt_vault(vault.key().to_string(), &vault.unlocked_key())?;
            } else if changed && sync.syncs() {
                sync.apply_joined(&mut vault)?;
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

        let mut sync_status = SyncStatus::of_case(&case);
        let changed = match (&mut sync, session) {
            (Some(sync), Some(session)) => {
                // A recorded edit can change the shown keys of a duplicate
                // key group, such as a trash of the entry that holds the
                // bare key. The view of the recorded state is applied, so
                // the vault shows those keys and the next diff finds no
                // edits. A stopped sync records no edit. After a repair, the
                // change is recorded under a second write id, minted after
                // the peer join. If that view fails to apply, the edit is
                // kept and the vault is saved as the change left it.
                let restore = request == SyncRequest::Restore;
                if sync.syncs()
                    && sync
                        .record(vh.get_unlocked_vault()?, session, now, restore)?
                        .is_some()
                {
                    sync.apply_recorded(vh.get_unlocked_vault_mut()?)?;
                }
                // `s` advances if and only if the vault file changes. A key
                // change writes the same path. A rebuild always changes the
                // vault file. A vault at `v > s` is always saved, at `v + 1`,
                // unless the transaction saves the vault only.
                let vault_changed =
                    vault_file::is_changed(&contents, &vh)? || sync.forces_vault_save();
                if vault_changed {
                    let vault = vh.get_unlocked_vault_mut()?;
                    vault.set_sync(sync.next_generation(), vault.replica_id());
                }
                // The staged file is written before the sync state that names
                // it. A stopped sync publishes nothing.
                if sync.syncs() {
                    sync.stage(&self.root)?;
                }

                // The sync state is saved before the vault, whenever it or
                // `s` changes. A transaction that saves the vault only leaves
                // the sync state as loaded, so the next load of a changed
                // vault is `v > s`. It ends the actor, since a write id it
                // minted is not saved.
                let mut saved = None;
                let result = if vault_changed {
                    vault_file::commit(&path, &contents, &vh, &*self.signer, |old| {
                        if refused {
                            self.keep_invalid(id, old.as_bytes())?;
                        } else {
                            self.retain(id, old);
                        }
                        if !sync.is_vault_only() {
                            saved = Some(sync.save(&self.root, &*self.signer, true)?);
                        }
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
                    None if sync.is_vault_only() => locked.state.end_actor(),
                    None => {},
                }
                let changed = result?;
                // No signed save follows the vault save. A failed copy does
                // not fail the save.
                if let Some(transport) = &transport {
                    sync.publish(&**transport);
                }
                sync.settle_status();
                sync.save_sidecar(&self.root);
                sync_status = Some(sync.status());
                changed
            },
            // Save only if the vault changed. A key change writes the same
            // path. After a second miss of the sync state key, a changed
            // vault takes the next generation and the sync state is left as
            // it is. The next load with the key is `v > s`, whose repair
            // adds the change.
            _ => {
                if matches!(case, SyncLoad::KeyMissing(_))
                    && vault_file::is_changed(&contents, &vh)?
                {
                    let vault = vh.get_unlocked_vault_mut()?;
                    vault.set_sync(vault.generation() + 1, vault.replica_id());
                }
                vault_file::commit(&path, &contents, &vh, &*self.signer, |old| {
                    self.retain(id, old);
                    Ok(())
                })?
            },
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
            sync_status,
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
    /// replica id is not restored. For a synced vault, each difference of
    /// the version against the view is recorded as an edit, and an item or
    /// credential the version lacks is moved to the trash.
    pub fn restore_version(
        &self,
        target: &Target,
        unlock: Unlock<'_>,
        name: &str,
    ) -> Result<Committed<()>, Error> {
        if RetainedVersion::parse(name).is_none() {
            return Err(Error::VaultVersionNotFound(name.to_string()));
        }
        self.write_as(target, unlock, SyncRequest::Restore, |vh| {
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
    /// as [`Self::restore_version`] does, and its differences against the
    /// view are recorded as [`Self::restore_version`] records them, unless
    /// sync is stopped. Any other case that needs a repair writes nothing.
    /// Fails with `VaultNotRefused` if the file verifies.
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
        let loaded = LocalSyncState::load_hashed(&self.root, id, &*self.signer);
        let loaded_hash = loaded.as_ref().ok().map(|(_, hash)| *hash);
        let local = loaded.map(|(local, _)| local);
        let (case, trusted) =
            SyncLoad::classify_trusted(&enc_vault, local, keyring.as_ref(), &*self.signer)?;
        let mut vault = Vault::from_unlocked_key(&file_key, enc_vault).map_err(|e| match e {
            Error::VaultFileKeyChanged => Error::VaultVersionKeyChanged(name.to_string()),
            e => e,
        })?;
        let previous_key = target.key.clone();
        let keyring = match (case, trusted, keyring, loaded_hash) {
            // A retained version of a synced vault is older than its sync
            // state. Its differences against the view are recorded.
            (SyncLoad::OlderVault { .. }, Some(trusted), Some(keyring), Some(hash)) => {
                let sidecar = Sidecar::load(&self.root, id);
                let sync = SyncTxn::new(trusted, keyring, hash, sidecar);
                let path = target.path.clone();
                return self.restore_refused_synced(
                    &entry,
                    &mut locked,
                    refused,
                    (path, vault),
                    sync,
                    previous_key,
                );
            },
            // A stopped sync records no edit.
            (SyncLoad::StoppedOlderVault { state, .. }, _, keyring, _) => {
                vault.set_sync(state, vault.replica_id());
                keyring.unwrap_or_default()
            },
            (case, _, keyring, _) => {
                case.check()?;
                case.with_keyring(keyring).1
            },
        };
        let vh = VaultHandle::unlocked_with_keyring(target.path.clone(), vault, keyring);
        self.replace_refused(&entry, &mut locked, refused, vh, previous_key, || Ok(()))
    }

    /// Number of differences the recovery merge would add to the vault of
    /// `target`, against its sync state as loaded under the vault locks, for
    /// the confirmation of the user override. Writes nothing. Fails with
    /// `SyncOverrideNotOffered` if the override is not offered.
    pub(crate) fn override_preview(
        &self,
        target: &Target,
        unlock: Unlock<'_>,
    ) -> Result<usize, Error> {
        let UnlockedKeys {
            id,
            file_key,
            keyring,
        } = unlock.keys(&self.root, &target.path, &*self.signer)?;
        let entry = self.locks.entry(id, &target.path);
        let mut locked = self.lock_entry(&entry, id)?;
        let path = locked.state.resolve(id, &target.path)?;
        let enc_vault = EncryptedVault::load(&path, &*self.signer)?;
        if enc_vault.id != id {
            return Err(Error::VaultNotFound(path.display().to_string()));
        }
        let local = LocalSyncState::load(&self.root, id, &*self.signer);
        let (case, trusted) =
            SyncLoad::classify_trusted(&enc_vault, local, keyring.as_ref(), &*self.signer)?;
        // A transaction rebuilds these cases and runs no merge.
        let rebuilds = matches!(case, SyncLoad::OlderVault { .. } | SyncLoad::Mismatch(_));
        let Some(trusted) = trusted.filter(|t| !rebuilds && Repair::override_offered(&t.local))
        else {
            return Err(Error::SyncOverrideNotOffered);
        };
        let vault = Vault::from_unlocked_key(&file_key, enc_vault)?;
        let edits = LocalEdits::find_repair(&trusted.state, &vault, trusted.local.replica_id)?;
        Ok(edits.len())
    }

    /// Write the retained version `vault` at `path` over the refused file
    /// `refused` of a vault with the trusted sync state `sync`, as
    /// [`Self::restore_refused`] does. Own and peer files are joined first.
    /// Each difference of the version against the view is then recorded as
    /// an edit, and an item or credential the version lacks is moved to the
    /// trash. If the sync state changes, the vault shows its view, the sync
    /// state is saved at the next generation before the vault, and the staged
    /// file is published. Otherwise the vault takes the sync state generation
    /// and the sync state is left as it is. If the diff or the apply fails,
    /// the join and the differences are discarded, and the version is saved
    /// at the next generation without the sync state, so the next
    /// transaction runs the `v > s` repair.
    fn restore_refused_synced(
        &self,
        entry: &VaultLock,
        locked: &mut Locked<'_>,
        refused: Option<Vec<u8>>,
        (path, mut vault): (PathBuf, Vault),
        mut sync: SyncTxn,
        previous_key: String,
    ) -> Result<Committed<()>, Error> {
        #[cfg(test)]
        sync.set_apply_fault(self.apply_fault);
        let session = locked.state.session(sync.replica(), sync.loaded());
        let now = Timestamp::now().as_second() + self.clock_offset;
        let transport = self.transport(&mut sync);
        if let Some(transport) = &transport {
            sync.join_own(&**transport, session);
            sync.join_peers(&**transport, session);
        }
        sync.record(&vault, session, now, true)?;
        if sync.needs_save() {
            sync.apply_restored(&mut vault)?;
        }
        // A diff or apply failure saves the version only, at the next
        // generation, so the next transaction runs the `v > s` repair.
        let generation = if sync.needs_save() {
            sync.stage(&self.root)?;
            sync.next_generation()
        } else if sync.is_vault_only() {
            locked.state.end_actor();
            sync.next_generation()
        } else {
            sync.generation()
        };
        vault.set_sync(generation, vault.replica_id());
        let vh = VaultHandle::unlocked_with_keyring(path, vault, sync.keyring().clone());

        let mut saved = None;
        let result = self.replace_refused(entry, locked, refused, vh, previous_key, || {
            if sync.needs_save() {
                saved = Some(sync.save(&self.root, &*self.signer, true)?);
            }
            Ok(())
        });
        match saved {
            Some(hash) => locked.state.record_saved_state(hash),
            None if result.is_err() => {
                sync.discard_staged(&self.root);
                locked.state.end_actor();
            },
            None => {},
        }
        let committed = result?;
        if let Some(transport) = &transport {
            sync.publish(&**transport);
        }
        sync.settle_status();
        sync.save_sidecar(&self.root);
        Ok(committed)
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
            sync_status: None,
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

    /// Keep `contents` as an invalid file of vault `id`, as a restore over a
    /// refused file does.
    #[cfg(test)]
    pub(crate) fn add_invalid_for_test(&self, id: Uuid, contents: &[u8]) {
        self.keep_invalid(id, contents).unwrap();
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

    /// Sign again, with the signer of this writer, each vault file of
    /// `vault_files` and every retained version of vault `id`, under the vault
    /// locks. `path` is the path of a new lock entry. Each file must hold vault
    /// `id` ([`EncryptedVault::sign_again`]). Only the envelope signature
    /// changes. Invalid files are not listed, so they are not signed again.
    /// A file that fails is skipped and logged, and the other files are still
    /// signed.
    pub(super) fn resign(&self, id: Uuid, path: &Path, vault_files: &[PathBuf]) -> Resigned {
        let mut resigned = Resigned::default();
        let entry = self.locks.entry(id, path);
        let _locked = match self.lock_entry(&entry, id) {
            Ok(locked) => locked,
            Err(e) => {
                log::error!("Failed to lock vault {id} to sign it again: {e}");
                resigned.skipped.extend(vault_files.iter().cloned());
                return resigned;
            },
        };
        let versions = self.versions(id);
        let version_files = match versions.list() {
            Ok(list) => list.iter().map(|v| versions.file(&v.name)).collect(),
            Err(e) => {
                log::error!("Failed to list {}: {e}", versions.path.display());
                resigned.skipped.push(versions.path.clone());
                Vec::new()
            },
        };
        for file in vault_files.iter().chain(&version_files) {
            match self.resign_file(id, file) {
                Ok(()) => resigned.signed += 1,
                Err(e) => {
                    log::error!("Failed to sign {} again: {e}", file.display());
                    resigned.skipped.push(file.clone());
                },
            }
        }
        resigned
    }

    /// Sign the file at `path` of vault `id` again and replace it.
    fn resign_file(&self, id: Uuid, path: &Path) -> Result<(), Error> {
        let contents = EncryptedVault::read_file(path)?;
        let signed = EncryptedVault::sign_again(&contents, id, &*self.signer)?;
        write_atomic(path, signed.as_bytes()).map_err(Error::VaultWriteError)
    }

    /// Vault ids of the retained version directories, ordered by id. A
    /// directory whose name is not a short id is skipped.
    pub(super) fn version_ids(&self) -> Vec<Uuid> {
        let mut ids: Vec<Uuid> = fs::read_dir(self.root.join(VERSIONS_DIR))
            .into_iter()
            .flatten()
            .flatten()
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
            .filter_map(|entry| {
                let name = entry.file_name();
                let short_id = name.to_str()?;
                let id = ShortId::decode(short_id).ok()?.uuid();
                (ShortId::encode_uuid(id) == short_id).then_some(id)
            })
            .collect();
        ids.sort();
        ids
    }

    /// Prune the retained versions of every vault, including vaults deleted
    /// outside the app, and remove empty version directories. Retention runs
    /// on each save, so this covers vaults that are not saved again. Failures
    /// are logged.
    pub fn prune_all(&self) {
        let root = self.root.join(VERSIONS_DIR);
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
