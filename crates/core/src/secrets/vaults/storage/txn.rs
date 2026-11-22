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
//! (`sync/txn.rs`). Before the edits are recorded, the history entry that the
//! change added for a replaced shown value takes its derived id
//! (`sync/resolve.rs`). A synced vault at `v < s`, or of another replica id
//! than its sync state, is rebuilt from the sync state before the change. `s`
//! advances if and only if the vault file changes. The staged file is
//! written first, then the sync state, then the vault. The own `key.json` is
//! then written once if it lacks a wrapping, and the staged file is then
//! copied to the synced folder. The transport of the synced folder is
//! resolved from the root in the sidecar of the vault. A sidecar with no root
//! gives no transport, and a root that fails to resolve pauses sync with
//! `Unreachable`. A sidecar that cannot be read fails the transaction, as a
//! sync state that cannot be read does. A sync state under a key id the unlock
//! did not unwrap is unlocked once more. A second miss saves the vault only.
//! Before any join, the no-edit guard diffs the vault as loaded against the
//! view of the sync state. If it finds edits, sync stops by drift, and the
//! transaction saves locally and publishes nothing. A `v < s` vault from a
//! period of stopped sync loads as it is and is not rebuilt. A `v > s` vault,
//! and a sync stopped by drift on another build or after the user override,
//! run a repair in place of the guard (`sync/repair.rs`). An apply or diff
//! failure pauses sync and never fails the save (`sync/txn.rs`). A pairing
//! grant is a transaction that changes no vault content and pins and wraps
//! for a new Mac under the locks (`sync/pairing/grant.rs`).
//! [`VaultWriter::rebuild`] and
//! [`VaultWriter::restore_refused`] replace a refused or missing vault file
//! without loading it. A replaced refused file is kept as an invalid file.
//!
//! A transaction whose joins list a state file that is not local yet asks
//! the transport once to download the files of the vault, and does not wait.
//! A peer join that lists every peer directory clears the pending flag of the
//! vault, unless the flag was set again after the join started.
//!
//! [`VaultWriter::copy_staged`] copies a staged file that a transaction
//! failed to publish, under the locks and with no key, for the
//! `SyncManager` (`sync/manager.rs`). For a `leaving` sync state it copies
//! the final file and then deletes the sync state, the staged file, and the
//! sidecar.
//!
//! [`VaultWriter::disable_sync`] records the own `left` entry, marks the
//! sync state `leaving`, stages the final file, and saves the sync state and
//! then the vault without its replica id, under the locks. A vault saved
//! before its `leaving` sync state loads as `SyncLoad::Leaving`, and the
//! next transaction saves it without the replica id.
//!
//! [`VaultWriter::enable_sync`] writes `meta.json`, the first sync state, the
//! vault, and `key.json` of a vault at its sync setup, under the locks
//! (`sync/setup.rs`).
//!
//! [`VaultWriter::join_sync`] joins a sync key into an existing vault or a
//! new one, with the recovery merge, under the locks (`sync/join_sync.rs`).
//!
//! A transaction that saves then deletes the local file blobs of the vault
//! that no record references in the saved vault or in a retained version,
//! and that the saved sync state does not stage, under the locks
//! (`files/gc.rs`). A publish uploads the staged file blobs that the folder
//! lacks before it copies the staged file (`sync/blobs.rs`). A transaction
//! with a transport that did not publish uploads the referenced blobs that
//! the local store holds and the folder lacks, after the vault is saved. A
//! failure is logged and changes no local state. No synced blob is deleted.
//! [`VaultWriter::fetch_blob`] fetches a blob that the local store lacks.
//!
//! Reads do not lock. Saves replace the file by renaming, so a read sees
//! either the old or the new file. A read runs a transaction with no
//! requested change first if [`VaultWriter::read_joins`] holds
//! (`storage/catalog.rs`).

use std::borrow::Borrow;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(test)]
use std::time::Duration;
use std::time::Instant;

use jiff::Timestamp;
use uuid::Uuid;

use crate::core::auth::AuthContext;
use crate::core::dirs::app_data_dir;
use crate::core::files::write_atomic;
use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::files::store::BlobStore;
use crate::secrets::vaults::files::{FileHash, gc};
use crate::secrets::vaults::format::encrypted_vault::{EncryptedVault, VaultHeader, VerifiedVault};
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
use crate::secrets::vaults::sync::audit_events::SyncEvents;
use crate::secrets::vaults::sync::blobs;
use crate::secrets::vaults::sync::crdt::CausalState;
use crate::secrets::vaults::sync::edit_check::{
    ConflictDetail, EditRequest, ResolvePick, SyncReads,
};
use crate::secrets::vaults::sync::join_sync::{JoinFile, JoinKey};
#[cfg(test)]
use crate::secrets::vaults::sync::keys::TestKeyWrapper;
use crate::secrets::vaults::sync::keys::{SyncKeyring, WrappedSyncKey};
use crate::secrets::vaults::sync::listing::PeerListing;
use crate::secrets::vaults::sync::load::{Mismatch, SyncLoad, TrustedState};
use crate::secrets::vaults::sync::local_state::{LocalStateError, LocalSyncState};
use crate::secrets::vaults::sync::meta::MetaFile;
use crate::secrets::vaults::sync::model::{ItemId, PublicKey, ReplicaKeys, SyncState};
use crate::secrets::vaults::sync::pairing::grant::PairingGrant;
use crate::secrets::vaults::sync::publish::Staged;
use crate::secrets::vaults::sync::rebuild::Rebuild;
use crate::secrets::vaults::sync::recovery::RecoveryKit;
use crate::secrets::vaults::sync::repair::{Repair, SyncRequest};
use crate::secrets::vaults::sync::setup::{FIRST_KEY_ID, SyncSetup};
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::state_file::StateHash;
use crate::secrets::vaults::sync::status::SyncStatus;
#[cfg(test)]
use crate::secrets::vaults::sync::transport::FixedTransport;
use crate::secrets::vaults::sync::transport::folder::FolderTransport;
use crate::secrets::vaults::sync::transport::folder::io::CoordinatedIo;
use crate::secrets::vaults::sync::transport::s3::S3Transport;
use crate::secrets::vaults::sync::transport::s3::credentials::default_credential_store;
use crate::secrets::vaults::sync::transport::{SyncTransport, SyncTransports, TransportRoot};
use crate::secrets::vaults::sync::txn::{Recorded, SyncTxn};

mod legacy_v1; // MIGRATE_V1
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
    /// Seconds added to the clock of the read listings, shared by clones.
    #[cfg(test)]
    listing_offset: Arc<AtomicU64>,
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
            #[cfg(test)]
            listing_offset: Arc::default(),
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
            listing_offset: Arc::default(),
        }
    }

    /// Advance the clock of the read listings by `seconds`, for this writer
    /// and its clones.
    #[cfg(test)]
    pub(crate) fn advance_listing_clock(&self, seconds: u64) {
        self.listing_offset.fetch_add(seconds, Ordering::SeqCst);
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

    /// This writer with `transports`, which resolve each vault by the root in
    /// its sidecar.
    #[cfg(test)]
    pub fn with_transports(self, transports: Arc<dyn SyncTransports>) -> Self {
        Self { transports, ..self }
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

    /// Clock of the read listings.
    fn listing_now(&self) -> Instant {
        let now = Instant::now();
        #[cfg(test)]
        let now = now + Duration::from_secs(self.listing_offset.load(Ordering::SeqCst));
        now
    }

    /// Whether a read of vault `id` runs a transaction with no requested
    /// change before it serves the vault. It does if the pending flag is set.
    /// Otherwise, if the vault has no live watch and no read listed it in the
    /// last minute, the peer directories are listed, and it does if a listed
    /// file is neither joined nor quarantined (D20). The flag costs no file
    /// I/O. The listing reads no state file. A vault with no trusted sync
    /// state to list for, no transport, or a listing that fails runs none.
    pub(crate) fn read_joins(&self, id: Uuid) -> bool {
        if self.locks.is_pending(id) {
            return true;
        }
        if !self.locks.take_listing(id, self.listing_now()) {
            return false;
        }
        match self.peer_changes(id) {
            Ok(changed) => changed > 0,
            Err(e) => {
                log::warn!("Failed to list the peer state files of vault {id}: {e}");
                false
            },
        }
    }

    /// Transport of the synced folder at `root`, as a transaction resolves
    /// it. `Ok(None)` if the vault has no root.
    pub(crate) fn transport_of(
        &self,
        root: Option<&TransportRoot>,
    ) -> Result<Option<Arc<dyn SyncTransport>>, Error> {
        self.transports.resolve(root)
    }

    /// Count of the peer state files of vault `id` that the sidecar neither
    /// records as joined nor quarantines ([`PeerListing::changed`]). Zero if
    /// the local sync state fails to load or is `leaving`, or if the sidecar
    /// gives no transport.
    fn peer_changes(&self, id: Uuid) -> Result<usize, Error> {
        let Ok(local) = LocalSyncState::load(&self.root, id, &*self.signer) else {
            return Ok(0);
        };
        if local.leaving {
            return Ok(0);
        }
        let sidecar = Sidecar::read(&self.root, id)?;
        let Some(transport) = self.transports.resolve(sidecar.transport.as_ref())? else {
            return Ok(0);
        };
        let changed = PeerListing::changed(&*transport, &sidecar, id, local.replica_id)?;
        if !changed.is_empty() {
            let count = changed.len();
            log::info!("Vault {id} lists {count} peer state files not joined");
        }
        Ok(changed.len())
    }
}

/// Transports of the app, one for each root, built at the first resolve of
/// the root and kept for the process. A folder root resolves to a
/// [`FolderTransport`] with [`CoordinatedIo`] if it is a folder. A root that
/// fails is not kept, so the next resolve tries it again. An iCloud root does
/// not resolve yet.
#[derive(Debug, Default)]
pub struct AppTransports {
    built: Mutex<HashMap<TransportRoot, Arc<dyn SyncTransport>>>,
}

impl AppTransports {
    /// New transport of `root`.
    fn build(root: &TransportRoot) -> Result<Arc<dyn SyncTransport>, Error> {
        match root {
            TransportRoot::Folder { path } => {
                let transport = FolderTransport::new(path.clone(), Arc::new(CoordinatedIo));
                transport.check_root()?;
                Ok(Arc::new(transport))
            },
            TransportRoot::S3 { name } => {
                let store = default_credential_store().ok_or_else(|| {
                    Error::SyncTransportError(format!("no credential store for {root}"))
                })?;
                let config = store.load(name)?.ok_or_else(|| {
                    Error::SyncTransportError(format!("no settings are saved for {root}"))
                })?;
                Ok(Arc::new(S3Transport::connect(&config)?))
            },
            TransportRoot::ICloud {} => Err(Error::SyncTransportError(format!(
                "no transport is built for {root}"
            ))),
        }
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
    /// Context of a read, such as the context of a broker request. Checks
    /// nothing, and unwraps the keys on the context as `App` does on the
    /// shared context. A read already authenticated the context, so the
    /// transaction adds no prompt (D7).
    Context(AuthContext),
    /// Vault encryption key already read on a context, such as the key that
    /// a pairing holds for its imports (D6 of doc 18). Reads no key. An
    /// unwrap with the key prompts if its context lapsed.
    Key(&'a ManagedKey),
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
                Self::unwrap_keys(root, path, signer, || {
                    get_vault_encryption_key_on(AuthContext::SharedThreadLocal)
                })
            },
            Unlock::Context(context) => Self::unwrap_keys(root, path, signer, || {
                get_vault_encryption_key_on(context.clone())
            }),
            Unlock::Key(managed_key) => Self::unwrap_keys(root, path, signer, || Ok(*managed_key)),
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
    /// file key, so `Unlocked` fails with `VaultLocked`. `App` and `Context`
    /// create no key. They fail with `VaultEncryptionKeyMissing` if the key
    /// is missing.
    fn new_keys(
        &self,
        root: &Path,
        id: Uuid,
        signer: &dyn VaultSigner,
    ) -> Result<(UnlockedKey, Option<SyncKeyring>), Error> {
        let generate = |managed_key: &ManagedKey| {
            let file_key = UnlockedKey::generate(managed_key, id)?;
            let keyring = SyncLoad::keyring_of(root, id, signer, managed_key);
            Ok((file_key, keyring))
        };
        match self {
            Unlock::App => {
                check_vault_auth_still_valid()?;
                generate(&get_vault_encryption_key_on(
                    AuthContext::SharedThreadLocal,
                )?)
            },
            Unlock::Context(context) => generate(&get_vault_encryption_key_on(context.clone())?),
            Unlock::Key(managed_key) => generate(managed_key),
            Unlock::Unlocked(_) => Err(Error::VaultLocked),
            #[cfg(test)]
            Unlock::Test(key) => {
                let keyring = SyncLoad::keyring_of(root, id, signer, &TestKeyWrapper);
                Ok((key(), keyring))
            },
        }
    }

    /// Keyring of the local sync state of vault `id` under the app data
    /// directory `root`, for a disable of a vault with no vault file. `None`
    /// if it fails to unwrap. A vault unlocked in memory holds no vault
    /// encryption key, so `Unlocked` fails with `VaultLocked`.
    fn keyring_of(
        &self,
        root: &Path,
        id: Uuid,
        signer: &dyn VaultSigner,
    ) -> Result<Option<SyncKeyring>, Error> {
        match self {
            Unlock::App => {
                check_vault_auth_still_valid()?;
                let managed_key = get_vault_encryption_key_on(AuthContext::SharedThreadLocal)?;
                Ok(SyncLoad::keyring_of(root, id, signer, &managed_key))
            },
            Unlock::Context(context) => {
                let managed_key = get_vault_encryption_key_on(context.clone())?;
                Ok(SyncLoad::keyring_of(root, id, signer, &managed_key))
            },
            Unlock::Key(managed_key) => Ok(SyncLoad::keyring_of(root, id, signer, *managed_key)),
            Unlock::Unlocked(_) => Err(Error::VaultLocked),
            #[cfg(test)]
            Unlock::Test(_) => Ok(SyncLoad::keyring_of(root, id, signer, &TestKeyWrapper)),
        }
    }

    /// Keys of a sync setup or join of the vault file `file`, with the sync
    /// files under the app data directory `root`: the vault id, the file key,
    /// `keyring` wrapped to `vault-encryption-key`, the public key of
    /// `vault-encryption-key`, and the keyring of the local sync state of an
    /// existing vault. An existing vault file is verified under the key of
    /// `signer` first, and its file key is unwrapped. A new vault takes a new
    /// file key. `App` and `Context` read the key once, and `Key` reads none.
    /// A vault unlocked in memory holds no vault encryption key, so
    /// `Unlocked` fails with `VaultLocked`.
    fn setup_keys(
        &self,
        root: &Path,
        file: SetupFile<'_>,
        signer: &dyn VaultSigner,
        keyring: &SyncKeyring,
    ) -> Result<SetupKeys, Error> {
        match self {
            Unlock::App => {
                check_vault_auth_still_valid()?;
                Self::read_setup_keys(root, file, signer, keyring, || {
                    get_vault_encryption_key_on(AuthContext::SharedThreadLocal)
                })
            },
            Unlock::Context(context) => Self::read_setup_keys(root, file, signer, keyring, || {
                get_vault_encryption_key_on(context.clone())
            }),
            Unlock::Key(managed_key) => {
                Self::read_setup_keys(root, file, signer, keyring, || Ok(*managed_key))
            },
            Unlock::Unlocked(_) => Err(Error::VaultLocked),
            #[cfg(test)]
            Unlock::Test(key) => {
                let (id, local_keyring) = match file {
                    SetupFile::Existing(path) => {
                        let enc_vault = EncryptedVault::load(path, signer)?;
                        let local_keyring =
                            SyncLoad::keyring(root, &enc_vault, signer, &TestKeyWrapper);
                        (enc_vault.id, local_keyring)
                    },
                    SetupFile::New(id) => (id, Some(SyncKeyring::default())),
                };
                Ok(SetupKeys {
                    id,
                    file_key: key(),
                    sync_keys: keyring.wrap(&TestKeyWrapper)?,
                    encryption: TestKeyWrapper::public_key(),
                    local_keyring,
                })
            },
        }
    }

    /// [`Self::setup_keys`] with the vault encryption key of `read`. The
    /// vault file is verified before `read` runs.
    fn read_setup_keys<K: Borrow<ManagedKey>>(
        root: &Path,
        file: SetupFile<'_>,
        signer: &dyn VaultSigner,
        keyring: &SyncKeyring,
        read: impl FnOnce() -> Result<K, Error>,
    ) -> Result<SetupKeys, Error> {
        let (id, enc_vault) = match file {
            SetupFile::Existing(path) => {
                let enc_vault = EncryptedVault::load(path, signer)?;
                (enc_vault.id, Some(enc_vault))
            },
            SetupFile::New(id) => (id, None),
        };
        let managed_key = read()?;
        let managed_key = managed_key.borrow();
        let (file_key, local_keyring) = match &enc_vault {
            Some(enc_vault) => {
                let file_key = UnlockedKey::unwrap(managed_key, enc_vault)
                    .inspect_err(|e| log::debug!("failed to unwrap the vault file key: {e}"))
                    .map_err(|_| Error::VaultFileKeyDecryptionError)?;
                let local_keyring = SyncLoad::keyring(root, enc_vault, signer, managed_key);
                (file_key, local_keyring)
            },
            None => (
                UnlockedKey::generate(managed_key, id)?,
                Some(SyncKeyring::default()),
            ),
        };
        let encryption = managed_key
            .public_key_sec1()
            .map_err(Error::KeyRetrievalFailed)?;
        Ok(SetupKeys {
            id,
            file_key,
            sync_keys: keyring.wrap(managed_key)?,
            encryption: PublicKey(encryption),
            local_keyring,
        })
    }

    /// Unwrap the file key and the sync keyring with the vault encryption
    /// key of `read`. The vault file is verified before `read` runs.
    fn unwrap_keys<K: Borrow<ManagedKey>>(
        root: &Path,
        path: &Path,
        signer: &dyn VaultSigner,
        read: impl FnOnce() -> Result<K, Error>,
    ) -> Result<UnlockedKeys, Error> {
        let enc_vault = EncryptedVault::load(path, signer)?;
        let managed_key = read()?;
        let managed_key = managed_key.borrow();
        let file_key = UnlockedKey::unwrap(managed_key, &enc_vault)
            .inspect_err(|e| log::debug!("failed to unwrap the vault file key: {e}"))
            .map_err(|_| Error::VaultFileKeyDecryptionError)?;
        let keyring = SyncLoad::keyring(root, &enc_vault, signer, managed_key);
        Ok(UnlockedKeys {
            id: enc_vault.id,
            file_key,
            keyring,
        })
    }
}

/// Vault file of a sync setup or join.
#[derive(Clone, Copy)]
enum SetupFile<'a> {
    /// Vault file at the path, which holds its file key.
    Existing(&'a Path),
    /// New vault of the vault id.
    New(Uuid),
}

/// Keys a sync setup or join writes with.
struct SetupKeys {
    id: Uuid,
    file_key: UnlockedKey,
    /// Sync keyring of the setup, wrapped to `vault-encryption-key`.
    sync_keys: Vec<WrappedSyncKey>,
    /// Public key of `vault-encryption-key`.
    encryption: PublicKey,
    /// Keyring of the local sync state of the vault as read before the
    /// locks, for the trust check of a join. Empty if the vault is new, is
    /// not synced, or its sync state fails to load. `None` if the keyring
    /// fails to unwrap.
    local_keyring: Option<SyncKeyring>,
}

/// Vault and local sync state of [`VaultWriter::read_locked`], read under the
/// vault locks.
pub(crate) struct LockedRead {
    pub(crate) id: Uuid,
    pub(crate) file_key: UnlockedKey,
    /// Vault file as reloaded and verified under the locks.
    pub(crate) vault: VerifiedVault,
    /// Case of the vault against its sync state.
    pub(crate) case: SyncLoad,
    /// Trusted sync state if the case compares the vault with one. The
    /// trusted state of `Mismatch(VaultId)` belongs to another vault.
    pub(crate) trusted: Option<TrustedState>,
    /// Keyring of the sync state as unwrapped before the locks. `None` if it
    /// failed to unwrap.
    pub(crate) keyring: Option<SyncKeyring>,
}

/// Vault file of a join as loaded under the locks.
enum JoinLoaded<'a> {
    /// Existing vault, with its file contents and its generation `v`.
    Existing {
        contents: String,
        vault: Box<Vault>,
        generation: u64,
    },
    /// New vault, with the function that chooses its key for the view name.
    New(&'a dyn Fn(Option<&str>) -> Result<String, Error>),
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
    /// Whether the `recovery` map of the sync state holds no recipient of
    /// the current key, the degraded state (D18). False if the transaction
    /// holds no trusted sync state, and for a rebuild or a restore over a
    /// refused file of a vault that is not synced.
    pub recovery_kit_missing: bool,
}

/// Outcome of [`VaultWriter::copy_staged`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StagedCopy {
    /// The staged file was copied, or was already listed under its hash, and
    /// the sidecar records it as the last publish.
    Copied,
    /// No staged file waits for a copy, or the vault cannot copy one.
    NotStaged,
    /// The staged file does not hash to the staged hash, so it is not copied
    /// (D14). The next transaction rewrites it.
    Refused,
    /// The final file of a `leaving` sync state was copied, or was already
    /// listed, and the sync state, the staged file, and the sidecar were
    /// deleted. The vault is no longer synced on this Mac.
    Left,
}

/// Outcome of [`VaultWriter::disable_sync`] and
/// [`VaultWriter::disable_missing`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disabled {
    /// The final file was copied, and the sync state, the staged file, and
    /// the sidecar were deleted.
    Left,
    /// The final file waits in the `leaving` sync state until the synced
    /// folder can be reached. The `SyncManager` copies it.
    Waiting,
    /// The sync state is missing, fails its signature, or is under a key
    /// the unlock lacks, so no final file was written. The sync state, the
    /// staged file, and the sidecar were deleted, and peers see the replica
    /// as inactive (D9 of doc 18).
    Deleted,
    /// Another Mac enabled sync for the vault separately, and no other
    /// replica is in `replica_keys`. The own replica directory was deleted in
    /// place of the final file, since no other Mac reads its files. The sync
    /// state, the staged file, and the sidecar were deleted (D11 of doc 18).
    DirectoryDeleted,
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
        f: impl FnOnce(&mut VaultHandle) -> Result<R, E>,
    ) -> Result<Committed<R>, E>
    where
        E: From<Error>,
    {
        self.write_with(target, unlock, request, None, f)
    }

    /// Transaction on the vault `target` that changes no vault content and
    /// runs `grant` under the locks (`sync/pairing/grant.rs`).
    pub(crate) fn write_granting(
        &self,
        target: &Target,
        unlock: Unlock<'_>,
        grant: &mut PairingGrant<'_>,
    ) -> Result<Committed<()>, Error> {
        self.write_with(target, unlock, SyncRequest::Change, Some(grant), |_| Ok(()))
    }

    /// [`Self::write_as`], with the pairing grant `grant` if set.
    fn write_with<R, E>(
        &self,
        target: &Target,
        unlock: Unlock<'_>,
        request: SyncRequest,
        mut grant: Option<&mut PairingGrant<'_>>,
        mut f: impl FnOnce(&mut VaultHandle) -> Result<R, E>,
    ) -> Result<Committed<R>, E>
    where
        E: From<Error>,
    {
        let mut retry_key_missing = true;
        for _ in 0..MAX_ATTEMPTS {
            let grant = grant.as_deref_mut();
            match self.attempt(target, &unlock, &request, retry_key_missing, grant, f)? {
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

    /// One attempt of [`Self::write_with`]. `f` is returned in `Retry` or
    /// `KeyMissing` if it did not run. `KeyMissing` is returned only if
    /// `retry_key_missing` is set. `grant` is checked before the joins,
    /// prepared after them, and written after the saves.
    fn attempt<R, E, F>(
        &self,
        target: &Target,
        unlock: &Unlock<'_>,
        request: &SyncRequest,
        retry_key_missing: bool,
        mut grant: Option<&mut PairingGrant<'_>>,
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
                let sidecar = Sidecar::read(&self.root, id)?;
                let mut sync = SyncTxn::new(trusted, keyring, hash, sidecar);
                sync.set_blob_store(BlobStore::of(&self.root, id));
                if let SyncLoad::NewerVault { vault, .. } = case {
                    sync.set_newer_vault(vault);
                }
                #[cfg(test)]
                sync.set_apply_fault(self.apply_fault);
                Some(sync)
            },
            _ => {
                SyncEvents::load_failed(&self.root, id, &case);
                case.check()?;
                None
            },
        };
        // A pairing grant refuses a vault whose sync state is not trusted
        // before any join. It writes nothing, except the sidecar record of a
        // sync state that is missing or fails its signature check.
        if let Some(grant) = grant.as_deref() {
            grant.check(&case, sync.as_ref())?;
        }
        // A recovery recipient is added only to a trusted sync state.
        let recovery = match request {
            SyncRequest::AddRecovery(add) => Some(add),
            _ => None,
        };
        if recovery.is_some() && sync.is_none() {
            return Err(Error::RecoveryKitNotAdded(case.to_string()).into());
        }
        // The override runs only while it is offered. Otherwise it writes
        // nothing, except the sidecar record of a load failure.
        let confirmed = *request == SyncRequest::Override;
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
            // The pending flag is cleared after a peer join that listed every
            // peer directory, whatever each file's outcome, unless it was set
            // again after the epoch was read (D4).
            if let Some(transport) = transport.filter(|_| sync.syncs()) {
                let epoch = vault_lock.pending_epoch();
                changed |= sync.join_peers(transport, session);
                if sync.listed_every_peer() {
                    vault_lock.clear_pending(epoch);
                }
            }
            if let Some(transport) = transport {
                sync.request_downloads(transport);
            }
            if rebuild {
                vault = sync.rebuilt_vault(vault.key().to_string(), &vault.unlocked_key())?;
            } else if changed && sync.syncs() {
                sync.apply_joined(&mut vault)?;
            }
            // A pairing grant pins the new Mac before the first-use pins, so
            // a value joined by this transaction cannot pin its replica id
            // first. A refused grant writes nothing.
            if let Some(grant) = grant.as_deref_mut() {
                grant.prepare(sync, transport, &*self.signer)?;
            }
            // Peers are pinned after the joins and the apply, so a discarded
            // join pins nothing it held. A stopped sync pins nothing.
            sync.pin_first_use();
        }

        // The key comes from the vault. It differs from the caller's key if
        // another writer changed the key since the caller found the vault.
        let keyring = sync
            .as_ref()
            .map(|sync| sync.keyring().clone())
            .unwrap_or_default();
        // The vault before the change, which a refused edit saves in place of
        // the change, with the join.
        let mut before_change = match &sync {
            Some(sync) if sync.syncs() => Some(vault.duplicate()?),
            _ => None,
        };
        let mut vh = VaultHandle::unlocked_with_keyring(path.clone(), vault, keyring);

        // Apply the change. An error leaves the files unchanged.
        let value = f(&mut vh)?;
        let edit = vh.take_edit();
        let mut edit_refused = None;

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
                // kept and the vault is saved as the change left it. A
                // recovery recipient is refused before any save if sync does
                // not run or the kit is not for the current key, and if the
                // diff fails it is not recorded and nothing is saved.
                //
                // An edit refused by its edit check records nothing. The vault
                // as it was before the change is saved with the join, and the
                // refusal is returned after the saves.
                if let Some(add) = recovery {
                    sync.check_recovery(add)?;
                }
                if sync.syncs() {
                    let vault = vh.get_unlocked_vault_mut()?;
                    match sync.record(vault, session, now, request, &edit)? {
                        Recorded::Minted(Some(_)) => sync.apply_recorded(vault)?,
                        Recorded::Minted(None) => {},
                        Recorded::Refused(refusal) => {
                            if let Some(before) = before_change.take() {
                                *vault = before;
                            }
                            edit_refused = Some(refusal);
                        },
                    }
                }
                if recovery.is_some() && !sync.syncs() {
                    return Err(Error::RecoveryKitNotAdded(
                        "vault failed to diff against its sync state".to_string(),
                    )
                    .into());
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
                // The own `key.json` is read and written once, after the
                // saves: the wrapping of a pairing grant, then the missing
                // `Age` wrappings. A failed write does not fail the save.
                if let Some(transport) = &transport {
                    match grant {
                        Some(grant) => grant.write(sync, &**transport),
                        None => {
                            let _ = sync.write_key_file(&**transport, None);
                        },
                    }
                }
                // No signed save follows the vault save. A failed copy does
                // not fail the save. A transaction that did not publish
                // uploads the referenced blobs that the folder lacks, and
                // changes no local state.
                if let Some(transport) = &transport {
                    sync.publish(&**transport);
                    if sync.syncs() {
                        sync.heal_blobs(&**transport);
                    }
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
            // adds the change. A vault saved before its `leaving` sync state
            // finishes the disable. It is saved without the replica id, and
            // the `SyncManager` copies the final file (D8 of doc 18).
            _ => {
                if matches!(case, SyncLoad::KeyMissing(_))
                    && vault_file::is_changed(&contents, &vh)?
                {
                    let vault = vh.get_unlocked_vault_mut()?;
                    vault.set_sync(vault.generation() + 1, vault.replica_id());
                }
                if case == SyncLoad::Leaving {
                    let vault = vh.get_unlocked_vault_mut()?;
                    vault.set_sync(vault.generation(), None);
                    log::info!("Vault {id} finishes the disable of sync stopped before its save");
                }
                vault_file::commit(&path, &contents, &vh, &*self.signer, |old| {
                    self.retain(id, old);
                    Ok(())
                })?
            },
        };
        if changed {
            self.collect_blobs(id, &vh);
        }
        let save_count = if changed {
            vault_lock.record_save()
        } else {
            vault_lock.save_count()
        };
        if let Some(refusal) = edit_refused {
            return Err(Error::EditRefused(refusal).into());
        }
        let recovery_kit_missing = sync.as_ref().is_some_and(SyncTxn::recovery_kit_missing);
        Ok(Attempt::Done(Committed {
            value,
            vault: vh,
            vault_id: id,
            previous_key: target.key.clone(),
            changed,
            save_count,
            sync_status,
            recovery_kit_missing,
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

    /// Local sync state of the unlocked vault `vh`, and the hash of its file,
    /// if it is at the generation and replica id of the vault. `None` if the
    /// vault is not synced, if the sync state fails to load, or if a later
    /// save replaced `vh`.
    fn matching_state(
        &self,
        vh: &VaultHandle,
    ) -> Result<Option<(LocalSyncState, StateHash)>, Error> {
        let vault = vh.get_unlocked_vault()?;
        let Some(replica) = vault.replica_id() else {
            return Ok(None);
        };
        let id = vault.id();
        let (local, hash) = match LocalSyncState::load_hashed(&self.root, id, &*self.signer) {
            Ok(loaded) => loaded,
            Err(e) => {
                log::info!("Vault {id} has no sync state to read edits against: {e}");
                return Ok(None);
            },
        };
        if local.generation != vault.generation() || local.replica_id.0 != replica {
            return Ok(None);
        }
        Ok(Some((local, hash)))
    }

    /// Sync state of the unlocked vault `vh`, opened with its keyring, as
    /// [`Self::matching_state`] finds it.
    fn matching_body(&self, vh: &VaultHandle) -> Result<Option<CausalState<SyncState>>, Error> {
        let Some((local, _)) = self.matching_state(vh)? else {
            return Ok(None);
        };
        Ok(local.open(vh.keyring()?).ok())
    }

    /// Write ids of the Ask registers of the unlocked vault `vh`, for edits
    /// from the UI. The reads are cached in `vh` by the hash of the sync state
    /// file. `None` for a vault that is not synced, a sync state that fails
    /// to load or open, and a copy that a later save replaced. An edit made
    /// with no reads is refused if it writes an Ask register, and the UI then
    /// reads again.
    pub fn sync_reads(&self, vh: &mut VaultHandle) -> Result<Option<Arc<SyncReads>>, Error> {
        let Some((local, hash)) = self.matching_state(vh)? else {
            return Ok(None);
        };
        if let Some(reads) = vh.cached_reads(hash) {
            return Ok(Some(reads));
        }
        let Ok(state) = local.open(vh.keyring()?) else {
            return Ok(None);
        };
        let reads = Arc::new(SyncReads::of(&state));
        vh.cache_reads(hash, Arc::clone(&reads));
        Ok(Some(reads))
    }

    /// Conflicts of the unlocked vault `vh`, each with its values, the Mac
    /// that wrote each value, and its write time. Empty for a vault that is
    /// not synced, as [`Self::sync_reads`] states.
    pub fn conflicts(&self, vh: &VaultHandle) -> Result<Vec<ConflictDetail>, Error> {
        Ok(self
            .matching_body(vh)?
            .map(|state| ConflictDetail::of(&state))
            .unwrap_or_default())
    }

    /// Resolve a conflict of the vault `target` with the value `pick`
    /// chooses, in a transaction. It supersedes every value of the register,
    /// writes each credential value not chosen to `history`, and records
    /// `sync.conflict_resolved`. Fails with `EditRefused` if the register
    /// holds other write ids than `pick` read. A vault that is not synced
    /// changes nothing.
    pub fn resolve_conflict(
        &self,
        target: &Target,
        unlock: Unlock<'_>,
        pick: ResolvePick,
    ) -> Result<Committed<()>, Error> {
        self.write_as(target, unlock, SyncRequest::Resolve(pick), |_| Ok(()))
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
                let sidecar = Sidecar::read(&self.root, id)?;
                let mut sync = SyncTxn::new(trusted, keyring, hash, sidecar);
                sync.set_blob_store(BlobStore::of(&self.root, id));
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

    /// Copy the staged file of vault `id`, found at `path`, to the synced
    /// folder, for a publish that failed (D12). Runs under the per-vault
    /// mutex and the lock file, with no key and no unlock. `path` is `None`
    /// for a `leaving` sync state with no vault file, and the lock entry
    /// then starts at the sync state path.
    ///
    /// The local sync state is verified under `device-signing-key`, which
    /// never prompts. Nothing is copied unless the sync state verifies and is
    /// of vault `id`. A `leaving` sync state copies its final file and then
    /// deletes the sync files ([`Self::copy_left`]). Otherwise nothing is
    /// copied unless the sync state is not stopped and holds a staged hash
    /// that the sidecar does not record as the last publish, and unless the
    /// sidecar gives a transport. A staged file whose bytes do not hash to
    /// the staged hash is refused (D14). The file blobs of `staged_blobs` are
    /// uploaded from the blob store of the vault first, and a failed upload
    /// copies nothing and returns its error. A file already listed under the
    /// hash is not written again. On success the sidecar records the hash as
    /// the last publish and as joined, and drops a `PublishFailed` cause. No
    /// file is decrypted and no own file is deleted. The next transaction
    /// moves `staged_context` to `published_context`.
    pub fn copy_staged(&self, id: Uuid, path: Option<&Path>) -> Result<StagedCopy, Error> {
        let state_path = LocalSyncState::path(&self.root, id);
        let entry = self.locks.entry(id, path.unwrap_or(&state_path));
        let _locked = self.lock_entry(&entry, id)?;
        let local = match LocalSyncState::load(&self.root, id, &*self.signer) {
            Ok(local) => local,
            Err(e) => {
                log::debug!("Vault {id} has no valid sync state to copy a staged file for: {e}");
                return Ok(StagedCopy::NotStaged);
            },
        };
        if local.vault_id != id {
            return Ok(StagedCopy::NotStaged);
        }
        if local.leaving {
            return self.copy_left(&local);
        }
        if local.stopped_build.is_some() {
            return Ok(StagedCopy::NotStaged);
        }
        let Some(hash) = local.staged_hash else {
            return Ok(StagedCopy::NotStaged);
        };
        let mut sidecar = Sidecar::read(&self.root, id)?;
        if sidecar.last_publish == Some(hash) {
            return Ok(StagedCopy::NotStaged);
        }
        let Some(staged) = Staged::existing(&self.root, id, hash) else {
            log::warn!("Staged file of vault {id} does not hash to {hash}, so it is not copied");
            return Ok(StagedCopy::Refused);
        };
        let Some(transport) = self.transports.resolve(sidecar.transport.as_ref())? else {
            return Ok(StagedCopy::NotStaged);
        };
        let replica = local.replica_id;
        blobs::upload(
            &*transport,
            id,
            &BlobStore::of(&self.root, id),
            &local.staged_blobs,
        )?;
        let listed = transport.list_states(id, replica).unwrap_or_default();
        if !listed.contains(&hash) {
            staged.copy(&*transport, id, replica, &[])?;
        }
        sidecar.last_publish = Some(hash);
        sidecar.record_joined(replica, hash);
        let before = sidecar.health.clone();
        sidecar.clear_publish_failed();
        sidecar.save(&self.root, id)?;
        SyncEvents::record_health_change(id, &before, &sidecar.health);
        log::info!("Copied the staged file {hash} of vault {id} to the synced folder");
        Ok(StagedCopy::Copied)
    }

    /// Copy the final file of the verified `leaving` sync state `local`, for
    /// [`Self::copy_staged`] under the vault locks, then delete the sync
    /// state, the staged file, and the sidecar (D8 of doc 18).
    ///
    /// The staged file is copied if the sidecar does not record it as the
    /// last publish and the folder does not list it. The sidecar then
    /// records the hash, and the three files are deleted. A sync state with
    /// no staged hash has no final file to copy. A sidecar with no root
    /// gives no folder, so the final file cannot be copied, and the files
    /// are deleted. A staged file that does not hash to the staged hash is
    /// refused and kept. A copy that fails returns its error, and the files
    /// are kept for the next copy.
    ///
    /// The file blobs of `staged_blobs` are uploaded from the blob store of
    /// the vault before the copy, and a failed upload copies nothing and
    /// returns its error.
    fn copy_left(&self, local: &LocalSyncState) -> Result<StagedCopy, Error> {
        let id = local.vault_id;
        let replica = local.replica_id;
        let mut sidecar = Sidecar::read(&self.root, id)?;
        if let Some(hash) = local.staged_hash
            && sidecar.last_publish != Some(hash)
        {
            let Some(staged) = Staged::existing(&self.root, id, hash) else {
                log::warn!("Final file of vault {id} does not hash to {hash}, so it is not copied");
                return Ok(StagedCopy::Refused);
            };
            let transport = self.transports.resolve(sidecar.transport.as_ref())?;
            match transport {
                Some(transport) => {
                    let store = BlobStore::of(&self.root, id);
                    blobs::upload(&*transport, id, &store, &local.staged_blobs)?;
                    let listed = transport.list_states(id, replica).unwrap_or_default();
                    if !listed.contains(&hash) {
                        staged.copy(&*transport, id, replica, &[])?;
                    }
                    sidecar.last_publish = Some(hash);
                    sidecar.save(&self.root, id)?;
                    log::info!("Copied the final file {hash} of vault {id} to the synced folder");
                },
                None => log::warn!("Vault {id} has no synced folder for its final file"),
            }
        }
        self.delete_sync_files(id)?;
        let replica = replica.0;
        log::info!("Vault {id} left sync as replica {replica}");
        Ok(StagedCopy::Left)
    }

    /// Delete the sync state, the staged file, and the sidecar of vault `id`,
    /// in that order, under the vault locks the caller holds. A file that is
    /// missing is skipped.
    fn delete_sync_files(&self, id: Uuid) -> Result<(), Error> {
        let paths = [
            LocalSyncState::path(&self.root, id),
            LocalSyncState::staged_path(&self.root, id),
            Sidecar::path(&self.root, id),
        ];
        for path in paths {
            match fs::remove_file(&path) {
                Ok(()) => {},
                Err(e) if e.kind() == io::ErrorKind::NotFound => {},
                Err(e) => return Err(Error::SyncStateWriteError(e)),
            }
        }
        Ok(())
    }

    /// Disable sync of the vault `target` (D8 and D9 of doc 18). Returns the
    /// vault as saved, without the replica id, and the outcome.
    ///
    /// The file key and the sync keyring are unwrapped before the locks, as
    /// in [`Self::write`]. A sync state under a key id the unlock did not
    /// unwrap is unlocked once more. Under the locks the vault is reloaded
    /// and verified. A vault that holds no replica id fails with
    /// `SyncDisableInProgress` if its sync state is `leaving`, and with
    /// `SyncNotEnabled` otherwise.
    ///
    /// A trusted sync state that syncs, pauses, or is stopped by drift
    /// records only `true` in the own `left` register, under one write id,
    /// and diffs nothing. The sync state is marked `leaving`, the final file
    /// is staged, the sync state is saved, and the vault is saved without
    /// the replica id, both at the next generation. A `v < s` vault is
    /// rebuilt from the sync state first, as a transaction rebuilds it. After
    /// the locks the final file is copied ([`Self::copy_staged`]), which
    /// deletes the sync files. A copy that fails leaves the `leaving` sync
    /// state for the `SyncManager`.
    ///
    /// A trusted sync state whose sidecar records `SeparateKey`, and whose
    /// `replica_keys` holds no other replica, writes no final file (D11 of
    /// doc 18). The own replica directory is deleted in the synced folder,
    /// the vault is saved without the replica id at the next generation, and
    /// the sync state, the staged file, and the sidecar are deleted. A folder
    /// that cannot be reached fails with `SyncFolderUnreachable`, and nothing
    /// is written.
    ///
    /// A vault saved before its `leaving` sync state is saved without the
    /// replica id, and the final file is copied. A sync state that is
    /// missing, fails its signature, is under a key the unlock lacks after
    /// the second unlock, or holds another vault id or replica id writes no
    /// final file. The vault is saved without the replica id, then the sync
    /// state, the staged file, and the sidecar are deleted. A sync state of
    /// a newer format is refused and nothing is written.
    pub fn disable_sync(
        &self,
        target: &Target,
        unlock: Unlock<'_>,
    ) -> Result<Committed<Disabled>, Error> {
        let mut retry_key_missing = true;
        for _ in 0..MAX_ATTEMPTS {
            match self.disable_attempt(target, &unlock, retry_key_missing)? {
                Attempt::Done(mut committed) => {
                    if committed.value == Disabled::Waiting {
                        let path = committed.vault.path.clone();
                        committed.value = self.copy_final(committed.vault_id, Some(&path));
                    }
                    return Ok(committed);
                },
                Attempt::Retry(()) => {},
                Attempt::KeyMissing(()) => retry_key_missing = false,
            }
        }
        Err(Error::VaultFileKeyChanged)
    }

    /// One attempt of [`Self::disable_sync`], under the vault locks. Returns
    /// `Waiting` if a final file waits for its copy.
    fn disable_attempt(
        &self,
        target: &Target,
        unlock: &Unlock<'_>,
        retry_key_missing: bool,
    ) -> Result<Attempt<Disabled, ()>, Error> {
        let UnlockedKeys {
            id,
            file_key,
            keyring,
        } = unlock.keys(&self.root, &target.path, &*self.signer)?;

        let vault_lock = self.locks.entry(id, &target.path);
        let mut locked = self.lock_entry(&vault_lock, id)?;
        let path = locked.state.resolve(id, &target.path)?;
        let contents = EncryptedVault::read_file(&path)?;
        let enc_vault = EncryptedVault::parse(&contents, &*self.signer)?;
        if enc_vault.id != id {
            return Err(Error::VaultNotFound(path.display().to_string()));
        }
        let loaded = LocalSyncState::load_hashed(&self.root, id, &*self.signer);
        if enc_vault.replica_id.is_none() {
            return Err(match loaded {
                Ok((local, _)) if local.leaving => Error::SyncDisableInProgress,
                _ => Error::SyncNotEnabled,
            });
        }
        let loaded_hash = loaded.as_ref().ok().map(|(_, hash)| *hash);
        let local = loaded.map(|(local, _)| local);
        let (case, trusted) =
            SyncLoad::classify_trusted(&enc_vault, local, keyring.as_ref(), &*self.signer)?;
        if retry_key_missing && matches!(case, SyncLoad::KeyMissing(_)) {
            log::info!("Vault {id} sync state is under a key the unlock lacks, unlocking again");
            return Ok(Attempt::KeyMissing(()));
        }
        let writes_final = matches!(
            case,
            SyncLoad::Current
                | SyncLoad::OlderVault { .. }
                | SyncLoad::StoppedOlderVault { .. }
                | SyncLoad::NewerVault { .. }
        );
        let mut sync = match (trusted, keyring, loaded_hash) {
            (Some(trusted), Some(keyring), Some(hash)) if writes_final => {
                let sidecar = Sidecar::read(&self.root, id)?;
                let mut sync = SyncTxn::new(trusted, keyring, hash, sidecar);
                sync.set_blob_store(BlobStore::of(&self.root, id));
                if let SyncLoad::NewerVault { vault, .. } = case {
                    sync.set_newer_vault(vault);
                }
                Some(sync)
            },
            // A sync state of a newer format is kept for the build that wrote
            // it.
            _ => {
                if let SyncLoad::VersionSkew(message) = &case {
                    return Err(Error::SyncStateVersionSkew(message.clone()));
                }
                None
            },
        };

        let mut vault = match Vault::from_unlocked_key(&file_key, enc_vault) {
            Err(Error::VaultFileKeyChanged) => {
                log::warn!("Vault {id} file key changed after it was unwrapped, unwrapping again");
                return Ok(Attempt::Retry(()));
            },
            other => other?,
        };
        let disabled = match &mut sync {
            Some(sync) => {
                if matches!(case, SyncLoad::OlderVault { .. }) {
                    vault = sync.rebuilt_vault(vault.key().to_string(), &vault.unlocked_key())?;
                }
                if sync.leaves_separately() {
                    self.delete_own_directory(sync)?;
                    vault.set_sync(sync.next_generation(), None);
                    Disabled::DirectoryDeleted
                } else {
                    let now = Timestamp::now().as_second() + self.clock_offset;
                    let session = locked.state.session(sync.replica(), sync.loaded());
                    sync.leave(session, now)?;
                    vault.set_sync(sync.next_generation(), None);
                    sync.stage(&self.root)?;
                    Disabled::Waiting
                }
            },
            None if case == SyncLoad::Leaving => {
                vault.set_sync(vault.generation(), None);
                Disabled::Waiting
            },
            None => {
                vault.set_sync(vault.generation(), None);
                Disabled::Deleted
            },
        };
        // Audit events of a rebuild, recorded after the vault save.
        let mut events = sync.as_mut().map(SyncTxn::take_events);
        // A separate enable saves no sync state, so its files are deleted.
        if disabled == Disabled::DirectoryDeleted {
            sync = None;
        }
        let vh = VaultHandle::unlocked_with_keyring(path.clone(), vault, SyncKeyring::default());

        // The `leaving` sync state is saved before the vault, so a vault
        // that still holds the replica id loads as `Leaving`.
        let mut saved = false;
        let result = vault_file::commit(&path, &contents, &vh, &*self.signer, |old| {
            self.retain(id, old);
            if let Some(sync) = &mut sync {
                sync.save(&self.root, &*self.signer, true)?;
                saved = true;
            }
            Ok(())
        });
        if result.is_err()
            && !saved
            && let Some(sync) = &mut sync
        {
            sync.discard_staged(&self.root);
        }
        // No write id of this replica is minted after a disable.
        locked.state.end_actor();
        let changed = result?;
        if let Some(events) = &mut events {
            events.record();
        }
        // A vault that no longer syncs joins no peer change, so a flag set
        // before the disable would never clear.
        vault_lock.clear_pending(vault_lock.pending_epoch());
        if matches!(disabled, Disabled::Deleted | Disabled::DirectoryDeleted) {
            self.delete_sync_files(id)?;
        }
        let save_count = if changed {
            vault_lock.record_save()
        } else {
            vault_lock.save_count()
        };
        log::info!("Disabled sync of vault {id}: {disabled:?}");
        Ok(Attempt::Done(Committed {
            value: disabled,
            vault: vh,
            vault_id: id,
            previous_key: target.key.clone(),
            changed,
            save_count,
            sync_status: None,
            recovery_kit_missing: false,
        }))
    }

    /// Delete the own replica directory of `sync` in the synced folder, for
    /// the disable of a vault that enabled sync separately (D11 of doc 18).
    /// Runs under the vault locks before any save. A sidecar with no root, a
    /// root that cannot be resolved, and a delete that fails give
    /// `SyncFolderUnreachable`, and nothing is written.
    fn delete_own_directory(&self, sync: &SyncTxn) -> Result<(), Error> {
        let id = sync.vault_id();
        let replica = sync.replica();
        let unreachable = |e: Error| Error::SyncFolderUnreachable(e.to_string());
        let transport = self
            .transports
            .resolve(sync.transport_root())
            .map_err(unreachable)?
            .ok_or_else(|| {
                Error::SyncFolderUnreachable("vault has no synced folder".to_string())
            })?;
        transport.delete_replica(id, replica).map_err(unreachable)?;
        let replica = replica.0;
        log::info!("Deleted the replica directory {replica} of vault {id}, enabled separately");
        Ok(())
    }

    /// Disable sync of vault `id`, whose vault file is missing (D9 of doc
    /// 18). The caller checks that no vault file holds the id.
    ///
    /// The keyring is unwrapped before the locks with
    /// [`SyncLoad::keyring_of`]. Under the locks, a trusted sync state of the
    /// vault records only `true` in the own `left` register, is marked
    /// `leaving`, stages the final file, and is saved at the next generation.
    /// No vault is saved. After the locks the final file is copied. A
    /// `leaving` sync state is copied only. A sync state that fails its
    /// signature, is under a key the keyring lacks, or belongs to another
    /// vault is deleted with the staged file and the sidecar. A missing sync
    /// state fails with `SyncNotEnabled`, and one of a newer format with
    /// `SyncStateVersionSkew`.
    pub fn disable_missing(&self, id: Uuid, unlock: Unlock<'_>) -> Result<Disabled, Error> {
        let keyring = unlock.keyring_of(&self.root, id, &*self.signer)?;
        let state_path = LocalSyncState::path(&self.root, id);
        let entry = self.locks.entry(id, &state_path);
        let mut locked = self.lock_entry(&entry, id)?;
        vault_file::check_create_path(locked.state.path(), id, &state_path)?;

        let loaded = LocalSyncState::load_hashed(&self.root, id, &*self.signer);
        let loaded_hash = loaded.as_ref().ok().map(|(_, hash)| *hash);
        let local = loaded.map(|(local, _)| local);
        let trust = SyncLoad::trust(local, keyring.as_ref(), &*self.signer)?;
        let disabled = match (trust, keyring, loaded_hash) {
            (Err(SyncLoad::StateMissing), ..) => return Err(Error::SyncNotEnabled),
            (Err(SyncLoad::VersionSkew(message)), ..) => {
                return Err(Error::SyncStateVersionSkew(message));
            },
            (Ok(trusted), ..) if trusted.local.vault_id == id && trusted.local.leaving => {
                Disabled::Waiting
            },
            (Ok(trusted), Some(keyring), Some(hash)) if trusted.local.vault_id == id => {
                let sidecar = Sidecar::read(&self.root, id)?;
                let mut sync = SyncTxn::new(trusted, keyring, hash, sidecar);
                let now = Timestamp::now().as_second() + self.clock_offset;
                let session = locked.state.session(sync.replica(), sync.loaded());
                sync.leave(session, now)?;
                sync.stage(&self.root)?;
                let saved = sync.save(&self.root, &*self.signer, true);
                if saved.is_err() {
                    sync.discard_staged(&self.root);
                }
                locked.state.end_actor();
                saved?;
                Disabled::Waiting
            },
            _ => Disabled::Deleted,
        };
        if disabled == Disabled::Deleted {
            self.delete_sync_files(id)?;
        }
        drop(locked);
        log::info!("Disabled sync of vault {id} with no vault file: {disabled:?}");
        Ok(match disabled {
            Disabled::Waiting => self.copy_final(id, None),
            other => other,
        })
    }

    /// Copy the final file of vault `id`, found at `path`, after a disable.
    /// `Left` if the copy deleted the sync files. Otherwise the failure is
    /// logged, and the `SyncManager` copies the final file later.
    fn copy_final(&self, id: Uuid, path: Option<&Path>) -> Disabled {
        match self.copy_staged(id, path) {
            Ok(StagedCopy::Left) => Disabled::Left,
            Ok(copy) => {
                log::warn!("Final file of vault {id} was not copied: {copy:?}");
                Disabled::Waiting
            },
            Err(e) => {
                log::warn!("Failed to copy the final file of vault {id}, it waits: {e}");
                Disabled::Waiting
            },
        }
    }

    /// Delete the sync state, the staged file, and the sidecar of vault `id`
    /// at `path` if the vault holds no replica id and the sync state is not
    /// `leaving`, such as a sync state restored after a disable finished (D8
    /// of doc 18). Runs under the vault locks, with no key. The vault file is
    /// verified first. A sync state that is missing or of a newer format is
    /// kept, and a vault or sync state that cannot be read fails. Returns
    /// whether the files were deleted.
    pub(crate) fn delete_disabled_sync(&self, id: Uuid, path: &Path) -> Result<bool, Error> {
        let entry = self.locks.entry(id, path);
        let mut locked = self.lock_entry(&entry, id)?;
        let path = locked.state.resolve(id, path)?;
        let vault = EncryptedVault::load(&path, &*self.signer)?;
        if vault.id != id || vault.replica_id.is_some() {
            return Ok(false);
        }
        match LocalSyncState::load(&self.root, id, &*self.signer) {
            Ok(local) if local.leaving => return Ok(false),
            Err(LocalStateError::Missing | LocalStateError::VersionSkew(_)) => return Ok(false),
            Err(LocalStateError::Read(e)) => return Err(Error::SyncStateReadError(e)),
            Err(LocalStateError::SigningKey(e)) => return Err(e),
            _ => {},
        }
        self.delete_sync_files(id)?;
        log::info!("Deleted the sync files of vault {id}, whose vault holds no replica id");
        Ok(true)
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
        self.read_locked(target, unlock, |read| {
            let Some(trusted) = Repair::override_state(&read.case, read.trusted.as_ref()) else {
                return Err(Error::SyncOverrideNotOffered);
            };
            let vault = Vault::from_unlocked_key(&read.file_key, read.vault)?;
            Repair::preview(trusted, &vault)
        })
    }

    /// Run `f` on the vault `target` and its local sync state, read under the
    /// vault locks. Writes nothing and builds no `SyncTxn`.
    ///
    /// The file key and the sync keyring are unwrapped before the locks, as
    /// in [`Self::write`], with no second unlock for a key id the keyring
    /// lacks. Under the locks the vault is reloaded and verified, and
    /// classified against its sync state.
    pub(crate) fn read_locked<R>(
        &self,
        target: &Target,
        unlock: Unlock<'_>,
        f: impl FnOnce(LockedRead) -> Result<R, Error>,
    ) -> Result<R, Error> {
        let UnlockedKeys {
            id,
            file_key,
            keyring,
        } = unlock.keys(&self.root, &target.path, &*self.signer)?;
        let entry = self.locks.entry(id, &target.path);
        let mut locked = self.lock_entry(&entry, id)?;
        let path = locked.state.resolve(id, &target.path)?;
        let vault = EncryptedVault::load(&path, &*self.signer)?;
        if vault.id != id {
            return Err(Error::VaultNotFound(path.display().to_string()));
        }
        let local = LocalSyncState::load(&self.root, id, &*self.signer);
        let (case, trusted) =
            SyncLoad::classify_trusted(&vault, local, keyring.as_ref(), &*self.signer)?;
        f(LockedRead {
            id,
            file_key,
            vault,
            case,
            trusted,
            keyring,
        })
    }

    /// Write `root` as the root of the synced folder in the sidecar of the
    /// vault `target`, under the vault locks, for a synced vault whose folder
    /// is chosen again (D18 of doc 18). Runs with no key, as
    /// [`Self::copy_staged`] does. The caller calls `SyncManager::refresh`.
    ///
    /// The vault is verified, and the sync state is verified under
    /// `device-signing-key`. A vault that holds no replica id fails with
    /// `SyncDisableInProgress` if its sync state is `leaving`, and with
    /// `SyncNotEnabled` otherwise. A `leaving` sync state fails with
    /// `SyncDisableInProgress`, and one of a newer format with
    /// `SyncStateVersionSkew`. A sync state that is missing, fails its
    /// signature, or holds another vault id or replica id fails with
    /// `SyncRootNotSet`. The folder must then hold `meta.json` of the vault
    /// ([`SyncSetup::check_folder`]). Only the root of the sidecar changes. A
    /// root already set is replaced. A sidecar that fails to parse is read as
    /// empty, as a transaction reads it, and is saved with the new root.
    pub fn set_sync_root(&self, target: &Target, root: &TransportRoot) -> Result<(), Error> {
        let id = EncryptedVault::load(&target.path, &*self.signer)?.id;
        let transport = SyncSetup::transport(self, root)?;

        let entry = self.locks.entry(id, &target.path);
        let mut locked = self.lock_entry(&entry, id)?;
        let path = locked.state.resolve(id, &target.path)?;
        let vault = EncryptedVault::load(&path, &*self.signer)?;
        if vault.id != id {
            return Err(Error::VaultNotFound(path.display().to_string()));
        }
        let not_set = |reason: &str| Err(Error::SyncRootNotSet(reason.to_string()));
        let local = match LocalSyncState::load(&self.root, id, &*self.signer) {
            Ok(local) => local,
            Err(LocalStateError::Read(e)) => return Err(Error::SyncStateReadError(e)),
            Err(LocalStateError::SigningKey(e)) => return Err(e),
            Err(LocalStateError::VersionSkew(message)) if vault.replica_id.is_some() => {
                return Err(Error::SyncStateVersionSkew(message));
            },
            Err(_) if vault.replica_id.is_none() => return Err(Error::SyncNotEnabled),
            Err(LocalStateError::Missing) => return not_set("sync state is missing"),
            Err(e) => return not_set(&format!("sync state is not valid: {e}")),
        };
        let Some(replica_id) = vault.replica_id else {
            return Err(if local.leaving {
                Error::SyncDisableInProgress
            } else {
                Error::SyncNotEnabled
            });
        };
        if local.leaving {
            return Err(Error::SyncDisableInProgress);
        }
        if local.vault_id != id || local.replica_id.0 != replica_id {
            return not_set("sync state belongs to another vault or replica");
        }

        SyncSetup::check_folder(&*transport, id)?;
        let mut sidecar = Sidecar::read(&self.root, id)?;
        sidecar.transport = Some(root.clone());
        sidecar.save(&self.root, id)?;
        log::info!("Vault {id} syncs with the synced folder {root}");
        Ok(())
    }

    /// New recovery kit for the current key of the trusted sync state of the
    /// vault `target`, read under the vault locks. Writes nothing.
    /// [`RecoveryKit::confirm_saved`] adds the recipient after the user saves
    /// the kit.
    ///
    /// A kit is refused with `RecoveryKitNotAdded` wherever
    /// `confirm_saved` would refuse its recipient before any join: a vault
    /// whose sync state a transaction builds no `SyncTxn` on, and a sync
    /// stopped by drift that the next transaction does not resume. A vault
    /// that already holds a recipient of the current key gets a new kit,
    /// such as for a kit that was lost, and the earlier kit still opens the
    /// key.
    pub(crate) fn create_kit(
        &self,
        target: &Target,
        unlock: Unlock<'_>,
    ) -> Result<RecoveryKit, Error> {
        self.read_locked(target, unlock, |read| {
            let refused = |reason: &str| Err(Error::RecoveryKitNotAdded(reason.to_string()));
            let (Some(trusted), Some(keyring)) = (&read.trusted, &read.keyring) else {
                return refused(&read.case.to_string());
            };
            if !read.case.builds_txn() {
                return refused(&read.case.to_string());
            }
            // A sync stopped by drift on another build is resumed by the
            // recovery merge of the next transaction.
            if trusted.local.stopped_build.is_some()
                && Repair::of(&trusted.local, false, false).is_none()
            {
                return refused("sync is stopped");
            }
            let key_id = trusted.local.key_id;
            let Some(key) = keyring.get(key_id) else {
                return refused("keyring lacks the current key");
            };
            Ok(RecoveryKit::create(read.id, key_id, key))
        })
    }

    /// Enable sync of the vault `target` with `setup`, after the user
    /// confirmed that its kit is saved (`sync/setup.rs`). Returns the ids of
    /// the items whose later duplicate websites were removed.
    ///
    /// The file key, the wrapped keyring, and the public key of
    /// `vault-encryption-key` are read before the locks. Under the locks the
    /// vault is reloaded and verified, and a vault that syncs and a folder
    /// that now holds the vault (`SyncFolderHasVault`) are refused again.
    /// `meta.json` is written next, and a failed write fails the setup before
    /// any local save. Each later website of an item with two websites of one
    /// URL is removed (D15). The first state is built from an empty state
    /// under one write id: every vault entry, the display name and the public
    /// keys of this Mac, and the kit recipient. The sidecar with the root is
    /// saved first, then the staged file, the sync state at generation 1, and
    /// the vault at generation 1 with the replica id, then `key.json` with the
    /// `Age` wrapping of the kit recipient, then the staged file is copied.
    /// Sync is enabled once the saves succeed. A failed `key.json` write or
    /// copy pauses sync with `PublishFailed`, and the next transaction or
    /// [`Self::copy_staged`] completes it.
    pub(crate) fn enable_sync(
        &self,
        target: &Target,
        unlock: Unlock<'_>,
        setup: &SyncSetup,
    ) -> Result<Committed<Vec<ItemId>>, Error> {
        let keyring = SyncKeyring::new(vec![(FIRST_KEY_ID, setup.key().clone())])?;
        let SetupKeys {
            id,
            file_key,
            sync_keys,
            encryption,
            ..
        } = unlock.setup_keys(
            &self.root,
            SetupFile::Existing(&target.path),
            &*self.signer,
            &keyring,
        )?;
        if id != setup.vault_id() {
            return Err(Error::VaultNotFound(target.path.display().to_string()));
        }
        let keys = self.replica_keys(encryption)?;
        let transport = SyncSetup::transport(self, setup.root())?;

        let vault_lock = self.locks.entry(id, &target.path);
        let mut locked = self.lock_entry(&vault_lock, id)?;
        let path = locked.state.resolve(id, &target.path)?;
        let contents = EncryptedVault::read_file(&path)?;
        let enc_vault = EncryptedVault::parse(&contents, &*self.signer)?;
        if enc_vault.id != id {
            return Err(Error::VaultNotFound(path.display().to_string()));
        }
        SyncSetup::check_not_synced(&self.root, &enc_vault, &*self.signer)?;
        if SyncSetup::folder_holds(&*transport, id)? {
            return Err(Error::SyncFolderHasVault);
        }
        let mut vault = Vault::from_unlocked_key(&file_key, enc_vault)?;

        // The bytes of `meta.json` are a function of the vault id, so a file
        // left by a failed setup is the file of the next one.
        transport.write_meta(id, &MetaFile::new(id).to_bytes())?;

        let removed = vault.remove_duplicate_websites();
        if !removed.is_empty() {
            let count = removed.len();
            log::info!("Vault {id} sync setup removed duplicate websites of {count} items");
        }

        let replica = setup.replica_id();
        let mut local = LocalSyncState::new(id, replica, FIRST_KEY_ID);
        local.sync_keys = sync_keys;
        let sidecar = Sidecar {
            transport: Some(setup.root().clone()),
            ..Sidecar::default()
        };
        let mut sync = SyncTxn::first(local, keyring, sidecar);
        sync.set_blob_store(BlobStore::of(&self.root, id));
        #[cfg(test)]
        sync.set_apply_fault(self.apply_fault);
        let now = Timestamp::now().as_second() + self.clock_offset;
        let session = locked.state.session(replica, sync.loaded());
        let recovery = setup.kit().recovery_add();
        sync.record_first(
            &vault,
            setup.name().to_string(),
            keys,
            &recovery,
            session,
            now,
        )?;
        // The vault shows the view of the first state, so the next diff finds
        // no edits.
        sync.apply_recorded(&mut vault)?;
        vault.set_sync(sync.next_generation(), Some(replica.0));
        let vh = VaultHandle::unlocked_with_keyring(path.clone(), vault, sync.keyring().clone());

        // The root is saved before the sync state, so it is kept if the
        // process stops after the saves.
        sync.save_sidecar(&self.root);
        sync.stage(&self.root)?;
        let mut saved = None;
        let result = vault_file::commit(&path, &contents, &vh, &*self.signer, |old| {
            self.retain(id, old);
            saved = Some(sync.save(&self.root, &*self.signer, true)?);
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
        let changed = result?;
        let replica_id = replica.0;
        log::info!("Enabled sync of vault {id} as replica {replica_id}");
        let _ = sync.write_key_file(&*transport, None);
        sync.publish(&*transport);
        sync.settle_status();
        sync.save_sidecar(&self.root);
        let save_count = if changed {
            vault_lock.record_save()
        } else {
            vault_lock.save_count()
        };
        Ok(Committed {
            value: removed,
            vault: vh,
            vault_id: id,
            previous_key: target.key.clone(),
            changed,
            save_count,
            sync_status: Some(sync.status()),
            recovery_kit_missing: sync.recovery_kit_missing(),
        })
    }

    /// Public keys of this Mac in its own `replica_keys` register:
    /// `encryption`, the public key of `vault-encryption-key`, and the key of
    /// the signer.
    fn replica_keys(&self, encryption: PublicKey) -> Result<ReplicaKeys, Error> {
        let signing = self.signer.verifying_key()?.to_encoded_point(false);
        Ok(ReplicaKeys {
            encryption,
            signing: PublicKey(signing.as_bytes().to_vec()),
        })
    }

    /// Join the sync key `join` into the vault file `file`, with the synced
    /// folder `root`, as the Mac named `name` (`sync/join_sync.rs`). Returns
    /// the ids of the items whose later duplicate websites were removed.
    ///
    /// The file key, the wrapped keyring, the public key of
    /// `vault-encryption-key`, and the keyring of the local sync state are
    /// read before the locks. Under the locks, `meta.json` must hold the
    /// vault ([`SyncSetup::check_folder`]). An existing vault is reloaded and
    /// verified, and refused while its sync state syncs
    /// ([`SyncSetup::check_joinable`]). Each later website of an item with
    /// two websites of one URL is removed (D15). A new vault refuses a path
    /// that holds a file, and a vault id that the vault locks track at
    /// another path.
    ///
    /// The sync state is new, with the replica id and the one key of `join`,
    /// at generation `v + 1` for an existing vault at `v` and 1 for a new
    /// vault. Every local peer file is joined, and the files that are not
    /// local yet are requested. An existing vault runs the recovery merge and
    /// takes the view. A new vault is built from the view. A view that fails
    /// to apply and a diff that fails fail the join. The Mac that paired is
    /// pinned with `pairing`, then the other peers at first use, and the own
    /// registers are recorded under one write id. The sidecar with the root
    /// is saved first, replacing any earlier sidecar, then the staged file,
    /// the sync state, and the vault, then `key.json` with the `Age`
    /// wrappings of the recovery recipients, then the staged file is copied.
    /// A failed `key.json` write or copy pauses sync with `PublishFailed`.
    pub(crate) fn join_sync(
        &self,
        join: &JoinKey,
        file: JoinFile<'_>,
        root: &TransportRoot,
        name: &str,
        unlock: Unlock<'_>,
    ) -> Result<Committed<Vec<ItemId>>, Error> {
        let keyring = SyncKeyring::new(vec![(join.key_id, join.key.clone())])?;
        let (setup_file, caller_path) = match &file {
            JoinFile::Existing(target) => (SetupFile::Existing(&target.path), &target.path),
            JoinFile::New { path, .. } => (SetupFile::New(join.vault_id), path),
        };
        let SetupKeys {
            id,
            file_key,
            sync_keys,
            encryption,
            local_keyring,
        } = unlock.setup_keys(&self.root, setup_file, &*self.signer, &keyring)?;
        if id != join.vault_id {
            return Err(Error::VaultNotFound(caller_path.display().to_string()));
        }
        let keys = self.replica_keys(encryption)?;
        let transport = SyncSetup::transport(self, root)?;

        let vault_lock = self.locks.entry(id, caller_path);
        let mut locked = self.lock_entry(&vault_lock, id)?;
        SyncSetup::check_folder(&*transport, id)?;
        let (path, loaded) = match &file {
            JoinFile::Existing(target) => {
                let path = locked.state.resolve(id, &target.path)?;
                let contents = EncryptedVault::read_file(&path)?;
                let enc_vault = EncryptedVault::parse(&contents, &*self.signer)?;
                if enc_vault.id != id {
                    return Err(Error::VaultNotFound(path.display().to_string()));
                }
                SyncSetup::check_joinable(
                    &self.root,
                    id,
                    Some(&enc_vault),
                    local_keyring.as_ref(),
                    &*self.signer,
                )?;
                let generation = enc_vault.generation;
                let vault = Box::new(Vault::from_unlocked_key(&file_key, enc_vault)?);
                let loaded = JoinLoaded::Existing {
                    contents,
                    vault,
                    generation,
                };
                (path, loaded)
            },
            JoinFile::New { path, choose_key } => {
                vault_file::check_create_path(locked.state.path(), id, path)?;
                if path.exists() {
                    return Err(Error::DuplicateVaultId(format!(
                        "A vault file already exists at {}",
                        path.display()
                    )));
                }
                SyncSetup::check_joinable(&self.root, id, None, None, &*self.signer)?;
                (path.clone(), JoinLoaded::New(*choose_key))
            },
        };

        let replica = join.replica_id;
        let mut local = LocalSyncState::new(id, replica, join.key_id);
        local.sync_keys = sync_keys;
        let sidecar = Sidecar {
            transport: Some(root.clone()),
            ..Sidecar::default()
        };
        let mut sync = SyncTxn::first(local, keyring, sidecar);
        sync.set_blob_store(BlobStore::of(&self.root, id));
        #[cfg(test)]
        sync.set_apply_fault(self.apply_fault);
        // The sync state starts at 0, so an existing vault at `v` is saved at
        // `v + 1` and a new vault at 1.
        if let JoinLoaded::Existing { generation, .. } = &loaded {
            sync.set_newer_vault(*generation);
        }
        let now = Timestamp::now().as_second() + self.clock_offset;
        let session = locked.state.session(replica, sync.loaded());
        let epoch = vault_lock.pending_epoch();
        sync.join_peers(&*transport, session);
        if sync.listed_every_peer() {
            vault_lock.clear_pending(epoch);
        }
        sync.request_downloads(&*transport);

        let mut removed = Vec::new();
        let (mut vault, contents) = match loaded {
            JoinLoaded::Existing {
                contents,
                mut vault,
                ..
            } => {
                removed = vault.remove_duplicate_websites();
                if !removed.is_empty() {
                    let count = removed.len();
                    log::info!("Vault {id} join removed duplicate websites of {count} items");
                }
                sync.record_merge(&vault, session, now)?;
                sync.apply_merged(&mut vault)?;
                (*vault, Some(contents))
            },
            JoinLoaded::New(choose_key) => (sync.joined_vault(choose_key, &file_key)?, None),
        };
        if let Some((peer, peer_keys)) = &join.paired {
            let pin = sync.pin_paired(*peer, peer_keys);
            let peer = peer.0;
            log::info!("Vault {id} pins the keys of replica {peer} at pairing: {pin:?}");
        }
        sync.pin_first_use();
        sync.record_own(name.to_string(), keys, session, now)?;
        vault.set_sync(sync.next_generation(), Some(replica.0));
        let vh = VaultHandle::unlocked_with_keyring(path.clone(), vault, sync.keyring().clone());

        // The root is saved before the sync state, so it is kept if the
        // process stops after the saves.
        sync.save_sidecar(&self.root);
        sync.stage(&self.root)?;
        let mut saved = None;
        let result = match &contents {
            Some(contents) => vault_file::commit(&path, contents, &vh, &*self.signer, |old| {
                self.retain(id, old);
                saved = Some(sync.save(&self.root, &*self.signer, true)?);
                Ok(())
            }),
            None => self.create_joined(&vh, || {
                saved = Some(sync.save(&self.root, &*self.signer, true)?);
                Ok(())
            }),
        };
        match saved {
            Some(hash) => locked.state.record_saved_state(hash),
            None if result.is_err() => {
                sync.discard_staged(&self.root);
                locked.state.end_actor();
            },
            None => {},
        }
        let changed = result?;
        locked.state.set_path(path);
        let replica_id = replica.0;
        log::info!("Joined sync of vault {id} as replica {replica_id}");
        let _ = sync.write_key_file(&*transport, None);
        sync.publish(&*transport);
        sync.settle_status();
        sync.save_sidecar(&self.root);
        let save_count = if changed {
            vault_lock.record_save()
        } else {
            vault_lock.save_count()
        };
        let previous_key = match &file {
            JoinFile::Existing(target) => target.key.clone(),
            JoinFile::New { .. } => vh.key.clone(),
        };
        Ok(Committed {
            value: removed,
            vault: vh,
            vault_id: id,
            previous_key,
            changed,
            save_count,
            sync_status: Some(sync.status()),
            recovery_kit_missing: sync.recovery_kit_missing(),
        })
    }

    /// Write `vh` as a new vault file of a join, after `before_write`, which
    /// saves the sync state. A file that exists at its path is never
    /// replaced. An error from `before_write` writes no vault file. Returns
    /// whether the file was written.
    fn create_joined(
        &self,
        vh: &VaultHandle,
        before_write: impl FnOnce() -> Result<(), Error>,
    ) -> Result<bool, Error> {
        let contents = vh.file_contents(&*self.signer)?;
        before_write()?;
        if let Some(dir) = vh.path.parent() {
            fs::create_dir_all(dir).map_err(Error::VaultDirCreateError)?;
        }
        vault_file::write_new(vh, &contents)?;
        Ok(true)
    }

    /// Write the retained version `vault` at `path` over the refused file
    /// `refused` of a vault with the trusted sync state `sync`, as
    /// [`Self::restore_refused`] does. Own and peer files are joined first.
    /// Each difference of the version against the view is then recorded as
    /// an edit, and an item or credential the version lacks is moved to the
    /// trash. If the sync state changes, the vault shows its view, the sync
    /// state is saved at the next generation before the vault, and the staged
    /// file is published. Otherwise the vault takes the sync state generation,
    /// and the sync state is saved at that generation only if a peer was
    /// pinned. Peers are pinned at first use after the joins and the apply.
    /// If the diff or the apply fails,
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
            sync.request_downloads(&**transport);
        }
        // A restore is not checked, so it is never refused.
        let edit = EditRequest::default();
        sync.record(&mut vault, session, now, &SyncRequest::Restore, &edit)?;
        if sync.state_changed() {
            sync.apply_restored(&mut vault)?;
        }
        sync.pin_first_use();
        // A diff or apply failure saves the version only, at the next
        // generation, so the next transaction runs the `v > s` repair. A
        // change of the pins alone saves the sync state header at `s`.
        let generation = if sync.state_changed() {
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
                let advance = sync.state_changed();
                saved = Some(sync.save(&self.root, &*self.signer, advance)?);
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
        let mut committed = result?;
        if let Some(transport) = &transport {
            let _ = sync.write_key_file(&**transport, None);
            sync.publish(&**transport);
            if sync.syncs() {
                sync.heal_blobs(&**transport);
            }
        }
        sync.settle_status();
        sync.save_sidecar(&self.root);
        committed.recovery_kit_missing = sync.recovery_kit_missing();
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
            recovery_kit_missing: false,
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

    /// Fetch blob `blob` of vault `id` from the synced folder into the local
    /// blob store (`sync/blobs.rs`). Takes no lock, since the blob is written
    /// by temp file and rename and its name fixes its bytes. The folder is
    /// resolved from the root in the sidecar. A vault with no root fails with
    /// `FileMissing`, and a root that cannot be resolved with its error.
    pub(crate) fn fetch_blob(&self, id: Uuid, blob: FileHash) -> Result<(), Error> {
        let sidecar = Sidecar::read(&self.root, id)?;
        let Some(transport) = self.transports.resolve(sidecar.transport.as_ref())? else {
            return Err(Error::FileMissing(blob.to_string()));
        };
        blobs::fetch(&*transport, id, &BlobStore::of(&self.root, id), blob)
    }

    /// Local blob store of vault `id`, in `files/{short id}` under the app
    /// data directory.
    pub(crate) fn blob_store(&self, id: Uuid) -> BlobStore {
        BlobStore::of(&self.root, id)
    }

    /// Delete the local file blobs of vault `id` that no record references
    /// in `vh`, as saved, or in a retained version (`files/gc.rs`). Runs
    /// under the vault locks, after the save and the retention. A retained
    /// version is read with the file key of `vh`. A version that fails to
    /// read, such as one under an earlier file key, keeps every blob. A
    /// failure is logged and does not fail the save.
    ///
    /// The blobs of `staged_blobs` of the saved sync state are kept, since
    /// the staged state references them. A synced vault whose sync state fails
    /// to load deletes nothing.
    fn collect_blobs(&self, id: Uuid, vh: &VaultHandle) {
        let collect = || -> Result<usize, Error> {
            let vault = vh.get_unlocked_vault()?;
            let keep = match vault.replica_id() {
                Some(_) => {
                    LocalSyncState::load(&self.root, id, &*self.signer)
                        .map_err(|e| Error::SyncStateEncodeError(e.to_string()))?
                        .staged_blobs
                },
                None => Vec::new(),
            };
            let store = BlobStore::of(&self.root, id);
            let retained = || {
                let versions = self.versions(id);
                let list = versions.list().map_err(Error::VaultReadError)?;
                let file_key = vault.unlocked_key();
                Ok(list.into_iter().map(move |version| {
                    let contents = EncryptedVault::read_file(&versions.file(&version.name))?;
                    let enc_vault = EncryptedVault::parse(&contents, &*self.signer)?;
                    Vault::from_unlocked_key(&file_key, enc_vault)
                }))
            };
            gc::collect(&store, &keep, vault, retained)
        };
        match collect() {
            Ok(0) => {},
            Ok(count) => log::info!("Deleted {count} unreferenced file blobs of vault {id}"),
            Err(e) => log::warn!("Failed to collect the file blobs of vault {id}: {e}"),
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
