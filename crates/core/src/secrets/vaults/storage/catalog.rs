use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::{fs, io};

use jiff::Zoned;
use jiff::civil::Date;
use uuid::Uuid;

use crate::core::auth::AuthContext;
use crate::core::config::APP_CONFIG;
use crate::core::dirs::vaults_dir;
use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::vaults::bundle::{
    ExportMode, ExportReport, FileKeyWrapper, ImportAction, ImportSelection, ImportableBundle,
};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::encrypted_vault::{EncryptedVault, VaultFileKey, VaultHeader};
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::format::signing::VaultSigner;
use crate::secrets::vaults::model::Vault;
use crate::secrets::vaults::storage::device_keys::{
    DeviceKeys, KeyProbe, KeyState, KeychainKeys, OnNewHardware, VaultFiles, ensure_device_keys,
};
use crate::secrets::vaults::storage::handle::{
    ExportProgress, VaultHandle, export_bundle, get_vault_encryption_key_on, normalized_key,
    validate_key,
};
use crate::secrets::vaults::storage::resign::{Resign, Resigned};
#[cfg(test)]
use crate::secrets::vaults::storage::test_keys::TestKeys;
use crate::secrets::vaults::storage::txn::{
    Committed, Disabled, RetainedVersion, Target, Unlock, VaultWriter,
};
use crate::secrets::vaults::storage::unreadable::{MovedVault, SyncedVault, Unreadable};
use crate::secrets::vaults::sync::join_sync::{JoinFile, JoinInto, JoinKey, PairingImport};
use crate::secrets::vaults::sync::keys::SyncKeyWrapper;
use crate::secrets::vaults::sync::load::SyncLoad;
use crate::secrets::vaults::sync::local_state::LocalSyncState;
use crate::secrets::vaults::sync::model::ItemId;
use crate::secrets::vaults::sync::pairing::PendingPairing;
use crate::secrets::vaults::sync::pairing::prompt::PairingPrompt;
use crate::secrets::vaults::sync::recovery::RecoveryKit;
use crate::secrets::vaults::sync::recovery::import::RecoveredKey;
use crate::secrets::vaults::sync::report::SyncReport;
use crate::secrets::vaults::sync::setup::SyncSetup;
use crate::secrets::vaults::sync::sidecar::Sidecar;
use crate::secrets::vaults::sync::transport::TransportRoot;
use crate::secrets::vaults::sync::wrapping::PairingKeys;

/// This struct tracks vault files on disk: the vaults directory, the external
/// vaults, and the retained versions and lock files. Operations read the
/// necessary files and does not keep the unlocked vaults. The app's unlocked
/// copies are kept by [`super::manager::VaultsManager`].
#[derive(Clone)]
pub struct VaultCatalog {
    vaults_dir: PathBuf,
    files: VaultWriter,
    /// External vault paths. `None` reads the app config each time.
    external: Option<Vec<PathBuf>>,
    unlocker: Arc<dyn Unlocker>,
    /// The Secure Enclave keys. Only `create` and `import` create them.
    keys: Arc<dyn DeviceKeys>,
}

/// Vault files found by [`VaultCatalog::scan`].
#[derive(Default)]
pub struct VaultScanResult {
    /// Listed vaults by key, locked.
    pub vaults: BTreeMap<String, VaultHandle>,
    /// Vault ids held by more than one file, ordered by id.
    pub duplicates: Vec<DuplicateVaults>,
    /// Vault keys claimed by more than one file, ordered by key.
    pub duplicate_keys: Vec<DuplicateVaultKeys>,
    /// Local sync states with no vault file, ordered by path.
    pub missing: Vec<MissingVault>,
}

/// Local sync state whose vault id no vault file holds. A sync state that
/// verifies and is `leaving` is a disable in progress, not a missing vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissingVault {
    pub id: Uuid,
    /// Path of the sync state file.
    pub path: PathBuf,
}

/// Vault files that hold one vault id, or ids whose short forms differ only in
/// letter case. None of them is listed or tracked in the vault locks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplicateVaults {
    /// Smallest vault id of the files.
    pub id: Uuid,
    /// Paths of the files, ordered by path.
    pub paths: Vec<PathBuf>,
}

/// Vault files that claim one vault key. None of them is listed or tracked in
/// the vault locks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplicateVaultKeys {
    pub key: String,
    /// Paths of the files, ordered by path.
    pub paths: Vec<PathBuf>,
}

/// Unlocks a loaded vault, and wraps the file keys of imported vaults.
/// Implemented as a trait so it can be swapped out in tests.
pub trait Unlocker: Send + Sync {
    /// Unlock `vw` on `context`, with the sync files under the app data
    /// directory `root`.
    fn unlock(&self, vw: &mut VaultHandle, root: &Path, context: AuthContext) -> Result<(), Error>;

    /// Transaction with no requested change on the vault `target` through
    /// `files`, unlocked on `context`, for a read. The app unlocks with
    /// `Unlock::Context`, and the tests with `Unlock::Test`.
    fn read_transaction(
        &self,
        files: &VaultWriter,
        target: &Target,
        context: AuthContext,
    ) -> Result<Committed<()>, Error>;

    /// Wrapper of the raw file keys of imported vaults, read on `context`.
    fn file_key_wrapper(&self, context: AuthContext) -> Result<FileKeyWrapper, Error>;

    /// New empty vault with key `key`, with a file key wrapped on `context`.
    fn new_vault(
        &self,
        name: Option<String>,
        key: String,
        context: AuthContext,
    ) -> Result<Vault, Error>;
}

/// Unlock with the file key in the keychain. This can prompt.
struct KeychainUnlocker;

impl Unlocker for KeychainUnlocker {
    fn unlock(&self, vw: &mut VaultHandle, root: &Path, context: AuthContext) -> Result<(), Error> {
        vw.unlock_on(root, context)
    }

    fn read_transaction(
        &self,
        files: &VaultWriter,
        target: &Target,
        context: AuthContext,
    ) -> Result<Committed<()>, Error> {
        files.write(target, Unlock::Context(context), |_| Ok(()))
    }

    /// Wrap each raw file key with the vault encryption key, read once.
    fn file_key_wrapper(&self, context: AuthContext) -> Result<FileKeyWrapper, Error> {
        let managed_key = get_vault_encryption_key_on(context)?;
        Ok(Box::new(move |raw: &[u8]| {
            Ok(VaultFileKey::new(
                managed_key
                    .encrypt(raw)
                    .ok_or(Error::VaultFileKeyEncryptionError)?
                    .into_bytes(),
            ))
        }))
    }

    fn new_vault(
        &self,
        name: Option<String>,
        key: String,
        context: AuthContext,
    ) -> Result<Vault, Error> {
        Vault::new(name, key, get_vault_encryption_key_on(context)?)
    }
}

impl Default for VaultCatalog {
    fn default() -> Self {
        Self::app()
    }
}

impl VaultCatalog {
    /// The app's vaults directory and data directory, and the external vaults
    /// in the app config.
    pub fn app() -> Self {
        Self {
            vaults_dir: vaults_dir(),
            files: VaultWriter::app(),
            external: None,
            unlocker: Arc::new(KeychainUnlocker),
            keys: Arc::new(KeychainKeys),
        }
    }

    /// Vaults in `vaults_dir` and `external`, with lock files under `files`.
    /// [`Self::unlock`] uses `unlocker`. Both keys are present, as
    /// `TestKeys::both` holds them. [`Self::with_keys`] replaces them.
    #[cfg(test)]
    pub fn with_unlocker(
        vaults_dir: PathBuf,
        files: VaultWriter,
        external: Vec<PathBuf>,
        unlocker: Arc<dyn Unlocker>,
    ) -> Self {
        Self {
            vaults_dir,
            files,
            external: Some(external),
            unlocker,
            keys: Arc::new(TestKeys::both()),
        }
    }

    /// This catalog over the keys `keys`.
    #[cfg(test)]
    pub(crate) fn with_keys(mut self, keys: Arc<dyn DeviceKeys>) -> Self {
        self.keys = keys;
        self
    }

    pub fn vaults_dir(&self) -> &Path {
        &self.vaults_dir
    }

    pub fn files(&self) -> &VaultWriter {
        &self.files
    }

    /// Signer for vault files, held by [`Self::files`].
    pub fn signer(&self) -> &Arc<dyn VaultSigner> {
        self.files.signer()
    }

    /// External vault paths.
    fn external_vaults(&self) -> Vec<PathBuf> {
        match &self.external {
            Some(external) => external.clone(),
            None => APP_CONFIG
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .external_vaults
                .iter()
                .map(|config| config.path.clone())
                .collect(),
        }
    }

    /// Where the vault files of this Mac are: the vaults directory, the
    /// retained versions and sync files under the data directory, and the
    /// external vaults.
    pub(super) fn vault_files(&self) -> VaultFiles {
        VaultFiles::new(
            self.vaults_dir.clone(),
            self.files.root(),
            self.external_vaults(),
        )
    }

    /// Key state of this Mac, probed without a prompt. Vault files of 0.2.0
    /// are upgraded first, since they are unsigned.
    pub fn key_state(&self) -> KeyState {
        self.upgrade_legacy_vaults(); // MIGRATE_V1
        KeyState::probe(self.keys.as_ref(), &self.vault_files())
    }

    // MIGRATE_V1
    /// Upgrade the vault files that 0.2.0 wrote. Creates
    /// `device-signing-key` if only such files exist. See `txn/legacy_v1.rs`.
    fn upgrade_legacy_vaults(&self) {
        self.files.upgrade_legacy_vaults(
            self.keys.as_ref(),
            &self.vault_files(),
            &self.vault_paths(),
        );
    }

    /// Create the missing keys on `context` if no vault file exists, and on
    /// new hardware as `on_new_hardware` states. See [`ensure_device_keys`].
    fn ensure_keys(
        &self,
        context: AuthContext,
        on_new_hardware: OnNewHardware,
    ) -> Result<(), Error> {
        ensure_device_keys(
            self.keys.as_ref(),
            &self.vault_files(),
            context,
            on_new_hardware,
        )
    }

    /// Synced vaults of the local sync states, read without verifying them,
    /// for the pairing and recovery kit offer on new hardware.
    pub fn unverified_synced_vaults(&self) -> Vec<SyncedVault> {
        Unreadable::synced_vaults(self.files.root())
    }

    /// Confirmed re-sign after signing key loss. Creates
    /// `device-signing-key` and signs every vault file and retained version
    /// again. Fails with `ResignNotOffered` unless the key state is
    /// `SigningKeyLost`. See [`Resign::confirm`].
    pub fn resign(&self) -> Result<Resigned, Error> {
        Resign::confirm(self.keys.as_ref(), self)
    }

    /// Every vault by key, locked. Same as the vaults of [`Self::scan`].
    pub fn list(&self) -> BTreeMap<String, VaultHandle> {
        self.scan().vaults
    }

    /// Whether a vault whose key is not in `excluded` has a peer change that
    /// waits for the next read to join it. Reads no vault file if no pending
    /// flag is set.
    pub fn has_pending_peer_changes(&self, excluded: &BTreeSet<String>) -> bool {
        let locks = self.files.locks();
        if locks.pending_ids().is_empty() {
            return false;
        }
        self.read_all()
            .iter()
            .any(|(id, vh)| locks.is_pending(*id) && !excluded.contains(&vh.key))
    }

    /// Scan the vault files. Every vault by key, locked, the vault ids held by
    /// more than one file, the vault keys claimed by more than one file, and
    /// the local sync states with no vault file. The key of each vault is
    /// read from its file. Files that fail to load are skipped.
    ///
    /// Every header is read before any path is tracked in the vault locks.
    /// Files that share a vault id or a vault key are not listed and not
    /// tracked, so no handle from this list can write to them. A file that
    /// shares both is reported in both lists.
    pub fn scan(&self) -> VaultScanResult {
        let found = self.read_all();
        let duplicates = Self::duplicate_ids(&found);
        let duplicate_keys = Self::duplicate_keys(&found);
        let missing = self.missing_vaults(&Self::folded_ids(&found));
        for duplicate in &duplicates {
            log::error!(
                "Skipping vault {}, vault id in use by multiple files: {:?}",
                ShortId::new(duplicate.id),
                duplicate.paths
            );
        }
        for duplicate in &duplicate_keys {
            log::error!(
                "Skipping vault key {}, claimed by multiple files: {:?}",
                duplicate.key,
                duplicate.paths
            );
        }
        let refused: BTreeSet<&Path> = duplicates
            .iter()
            .flat_map(|duplicate| &duplicate.paths)
            .chain(duplicate_keys.iter().flat_map(|duplicate| &duplicate.paths))
            .map(PathBuf::as_path)
            .collect();

        let mut vaults = BTreeMap::new();
        for (id, vh) in found {
            if refused.contains(vh.path.as_path()) {
                continue;
            }
            self.files.locks().track(id, &vh.path);
            vaults.insert(vh.key.clone(), vh);
        }

        VaultScanResult {
            vaults,
            duplicates,
            duplicate_keys,
            missing,
        }
    }

    /// Local sync states whose vault id is not in `held`, the folded short
    /// ids of the vault files. Each is read and verified. One that verifies
    /// and is `leaving` is skipped. One that fails to load is listed.
    fn missing_vaults(&self, held: &BTreeSet<String>) -> Vec<MissingVault> {
        let root = self.files.root();
        LocalSyncState::list(root)
            .into_iter()
            .filter(|(id, _)| !held.contains(&ShortId::folded(*id)))
            .filter(|(id, _)| {
                LocalSyncState::load(root, *id, self.signer().as_ref())
                    .map_or(true, |state| !state.leaving)
            })
            .map(|(id, path)| MissingVault { id, path })
            .collect()
    }

    /// Every vault file in the vaults directory and every external vault
    /// file, with its vault id, locked, ordered by path. Only the headers are
    /// read, and nothing is tracked in the vault locks. A path to a file
    /// already read, such as an external vault path that points into the
    /// vaults directory, is skipped. Files that fail to load are logged and
    /// skipped.
    pub(super) fn read_all(&self) -> Vec<(Uuid, VaultHandle)> {
        self.upgrade_legacy_vaults(); // MIGRATE_V1
        let paths = self.vault_paths();

        let mut seen = BTreeSet::new();
        let mut found = Vec::new();
        for path in paths {
            if !seen.insert(Self::canonical(&path)) {
                continue;
            }
            match VaultHeader::peek(&path) {
                Ok(header) => found.push((header.id, VaultHandle::from_header(&path, header))),
                Err(e) => log::error!("Skipping {}, failed to load: {e:?}", path.display()),
            }
        }
        found.sort_by(|(_, a), (_, b)| a.path.cmp(&b.path));
        found
    }

    /// Paths of the `.json` files in the vaults directory, ordered, then the
    /// external vault paths. A path can be listed twice, and a listed external
    /// path can be missing.
    fn vault_paths(&self) -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = fs::read_dir(&self.vaults_dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json")
            })
            .collect();
        paths.sort();
        paths.extend(self.external_vaults());
        paths
    }

    /// Path with links and `..` resolved, or `path` if it cannot be resolved.
    fn canonical(path: &Path) -> PathBuf {
        path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
    }

    /// Vault ids held by more than one of `found`, ordered by id. Files are
    /// grouped by the folded short id, so ids that differ only in letter case
    /// are duplicates. They would name one `{id}.json` file on a file system
    /// that ignores case. Equal ids have equal folded forms.
    fn duplicate_ids(found: &[(Uuid, VaultHandle)]) -> Vec<DuplicateVaults> {
        let mut groups: BTreeMap<String, DuplicateVaults> = BTreeMap::new();
        for (id, vh) in found {
            let group = groups
                .entry(ShortId::folded(*id))
                .or_insert_with(|| DuplicateVaults {
                    id: *id,
                    paths: Vec::new(),
                });
            group.id = group.id.min(*id);
            group.paths.push(vh.path.clone());
        }
        let mut duplicates: Vec<DuplicateVaults> = groups
            .into_values()
            .filter(|group| group.paths.len() > 1)
            .collect();
        duplicates.sort_by_key(|duplicate| duplicate.id);
        duplicates
    }

    /// Vault keys claimed by more than one of `found`, ordered by key. Keys
    /// are compared as stored, since a stored key is always normalized.
    fn duplicate_keys(found: &[(Uuid, VaultHandle)]) -> Vec<DuplicateVaultKeys> {
        let mut groups: BTreeMap<&str, Vec<PathBuf>> = BTreeMap::new();
        for (_, vh) in found {
            groups
                .entry(vh.key.as_str())
                .or_default()
                .push(vh.path.clone());
        }
        groups
            .into_iter()
            .filter(|(_, paths)| paths.len() > 1)
            .map(|(key, paths)| DuplicateVaultKeys {
                key: key.to_string(),
                paths,
            })
            .collect()
    }

    /// Normalized `key`, if no vault file claims it. A file that is not listed
    /// for a duplicate id or key still claims its key. The file at `own`, the
    /// vault that takes the key, is not counted. Fails with `InvalidVaultKey`.
    ///
    /// The check reads the files and is not atomic with the write that
    /// follows it. Two writers that take one key at the same time both pass,
    /// and the next scan reports both files.
    pub fn unclaimed_key(&self, key: &str, own: Option<&Path>) -> Result<String, Error> {
        let key = normalized_key(key).ok_or_else(|| Error::InvalidVaultKey(key.to_string()))?;
        if self.claimed_keys(own).contains(&key) {
            return Err(Self::claimed(&key));
        }
        Ok(key)
    }

    /// Ids of `ids` that a vault file on this Mac holds, for an import to ask
    /// about before it runs. Ids are compared by their folded short ids, as
    /// [`Self::scan`] groups them, so an id whose short form differs only in
    /// letter case is held. Every file with a header counts, external vaults
    /// included, and files refused for a duplicate id or key, unsigned, or
    /// signed by another key. Only headers are read. No keychain call is made
    /// and nothing is tracked.
    pub fn existing_ids(&self, ids: impl IntoIterator<Item = Uuid>) -> BTreeSet<Uuid> {
        let held = Self::folded_ids(&self.read_all());
        ids.into_iter()
            .filter(|id| held.contains(&ShortId::folded(*id)))
            .collect()
    }

    /// Folded short ids of `found`.
    fn folded_ids(found: &[(Uuid, VaultHandle)]) -> BTreeSet<String> {
        found.iter().map(|(id, _)| ShortId::folded(*id)).collect()
    }

    /// Keys claimed by every vault file except the file at `own`.
    fn claimed_keys(&self, own: Option<&Path>) -> BTreeSet<String> {
        let own = own.map(Self::canonical);
        self.read_all()
            .into_iter()
            .filter(|(_, vh)| own.as_ref() != Some(&Self::canonical(&vh.path)))
            .map(|(_, vh)| vh.key)
            .collect()
    }

    fn claimed(key: &str) -> Error {
        Error::InvalidVaultKey(format!("A vault with key '{key}' already exists"))
    }

    /// Menu labels of every vault, `name (key)` or the key alone, mapped to
    /// the key. Sorted by label.
    pub fn labels(&self) -> BTreeMap<String, String> {
        self.list()
            .into_iter()
            .map(|(key, vw)| match vw.vault_name() {
                Some(name) => (format!("{name} ({key})"), key),
                None => (key.clone(), key),
            })
            .collect()
    }

    /// Load one vault by key, locked, through [`Self::scan`]. A key claimed by
    /// two files fails with `DuplicateVaultKey`. A key whose file shares its
    /// vault id with another file fails with `DuplicateVaultId`. Every header
    /// is read on each call.
    pub fn load(&self, key: &str) -> Result<VaultHandle, Error> {
        let mut scan = self.scan();
        if let Some(vh) = scan.vaults.remove(key) {
            return Ok(vh);
        }
        if let Some(duplicate) = scan.duplicate_keys.iter().find(|d| d.key == key) {
            return Err(Error::DuplicateVaultKey(Self::joined(&duplicate.paths)));
        }
        // The key is not in a duplicate key group, so at most one file claims
        // it. Read the headers again to find whether that file was refused
        // for its id.
        let refused_for_id = scan.duplicates.iter().find(|duplicate| {
            duplicate
                .paths
                .iter()
                .any(|path| VaultHeader::peek(path).is_ok_and(|header| header.key == key))
        });
        match refused_for_id {
            Some(duplicate) => Err(Error::DuplicateVaultId(Self::joined(&duplicate.paths))),
            None => Err(Error::VaultNotFound(key.to_string())),
        }
    }

    fn joined(paths: &[PathBuf]) -> String {
        paths
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(" and ")
    }

    /// Load one vault by key and unlock it on `context`. This can prompt.
    pub fn open(&self, key: &str, context: AuthContext) -> Result<VaultHandle, Error> {
        let mut vw = self.load(key)?;
        self.unlock(&mut vw, context)?;
        Ok(vw)
    }

    /// Unlock `vw` on `context`. This can prompt. See [`Self::unlock_counted`].
    pub fn unlock(&self, vw: &mut VaultHandle, context: AuthContext) -> Result<(), Error> {
        self.unlock_counted(vw, context).map(|_| ())
    }

    /// Unlock `vw` on `context` for a read, and return the save count at
    /// which the unlocked copy is current. This can prompt.
    ///
    /// If [`VaultWriter::read_joins`] holds, the read runs a transaction with
    /// no requested change on the same context and serves the vault it saved.
    /// If that transaction fails, the failure is logged and the vault is
    /// unlocked as before. If the unlock fails with `SyncRepairNeeded`, the
    /// read runs the same transaction, which rebuilds `v < s` and a sync
    /// state of another replica id, and repairs `v > s`. A repair transaction
    /// that fails fails the read with its error, so a sync state of another
    /// vault id is still refused (D8, D10). The transaction runs with the
    /// vault locks and adds no prompt, since the context is authenticated by
    /// the read.
    pub fn unlock_counted(&self, vw: &mut VaultHandle, context: AuthContext) -> Result<u64, Error> {
        let id = vw.peek_vault_id().ok();
        if let Some(id) = id.filter(|id| self.files.read_joins(*id)) {
            match self.read_transaction(vw, context.clone()) {
                Ok(save_count) => return Ok(save_count),
                Err(e) => log::warn!("Failed to join vault {id} before a read: {e}"),
            }
        }
        let save_count = id.and_then(|id| self.files.locks().save_count(id));
        match self.unlocker.unlock(vw, self.files.root(), context.clone()) {
            Ok(()) => Ok(save_count.unwrap_or_default()),
            Err(Error::SyncRepairNeeded(reason)) => {
                let key = &vw.key;
                log::warn!("Vault {key} needs a sync repair at a read, running it: {reason}");
                self.read_transaction(vw, context)
            },
            Err(e) => Err(e),
        }
    }

    /// Run a transaction with no requested change on `vw` for a read, and
    /// put the vault it saved, unlocked, in place of `vw`. Returns the save
    /// count of the transaction.
    fn read_transaction(&self, vw: &mut VaultHandle, context: AuthContext) -> Result<u64, Error> {
        let committed = self
            .unlocker
            .read_transaction(&self.files, &Target::of(vw), context)?;
        *vw = committed.vault;
        Ok(committed.save_count)
    }

    /// Create and write a new vault with key `key`, normalized. A key that
    /// another vault file claims is refused before the keychain is read.
    /// Creates both Secure Enclave keys first if no vault file exists. On new
    /// hardware it first moves the vault files to `unreadable/`, then creates
    /// the missing keys ([`Self::ensure_keys`]). Returns the vault unlocked.
    pub fn create(&self, name: Option<String>, key: &str) -> Result<VaultHandle, Error> {
        let key = self.unclaimed_key(key, None)?;
        self.ensure_keys(AuthContext::SharedThreadLocal, OnNewHardware::MoveFiles)?;
        let vault = self
            .unlocker
            .new_vault(name, key, AuthContext::SharedThreadLocal)?;
        self.create_vault(vault)
    }

    /// [`Self::create`] on `context`, such as the context of a broker request.
    /// On new hardware it fails with `NewHardware` and moves no file.
    pub fn create_on(
        &self,
        name: Option<String>,
        key: &str,
        context: AuthContext,
    ) -> Result<VaultHandle, Error> {
        let key = self.unclaimed_key(key, None)?;
        self.ensure_keys(context.clone(), OnNewHardware::Fail)?;
        let vault = self.unlocker.new_vault(name, key, context)?;
        self.create_vault(vault)
    }

    /// Write `vault` as a new file in the vaults directory, named by its id.
    /// Returns it unlocked.
    fn create_vault(&self, vault: Vault) -> Result<VaultHandle, Error> {
        let vh = VaultHandle::new_in(&self.vaults_dir, vault);
        self.files.create(&vh)?;
        Ok(vh)
    }

    /// Move a vault file to the Trash under the vault locks, so a save in
    /// progress cannot recreate it. A vault that holds a replica id is
    /// disabled first with the shared context, so the delete of a synced
    /// vault needs the app unlocked (C10 of doc 18). See
    /// [`Self::delete_with`].
    pub fn delete(&self, key: &str) -> Result<(), Error> {
        self.delete_with(key, Unlock::App, Self::move_to_trash)
    }

    /// [`Self::delete`] with the keys of the disable from `unlock`, and the
    /// file removed with `remove`. The replica id is read from the vault
    /// file without a key, so the delete of a vault that is not synced reads
    /// no key. A synced vault is disabled with [`VaultWriter::disable_sync`]
    /// before the file is removed. A final file that waits for the synced
    /// folder stays in its `leaving` sync state, and the `SyncManager`
    /// copies it.
    pub(crate) fn delete_with(
        &self,
        key: &str,
        unlock: Unlock<'_>,
        remove: impl FnOnce(&Path) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let vw = self.load(key)?;
        // A file whose replica id fails to parse is deleted as before.
        if VaultHeader::peek_replica_id(&vw.path)
            .ok()
            .flatten()
            .is_some()
        {
            let target = Target::new(key, vw.path.clone());
            self.files.disable_sync(&target, unlock)?;
        }
        self.files.delete(&vw.path, remove)
    }

    /// Disable sync of vault `key` (D8 and D9 of doc 18). See
    /// [`VaultWriter::disable_sync`]. The caller then calls
    /// `SyncManager::refresh`, so a final file that waits is copied when the
    /// synced folder can be reached.
    pub fn disable_sync(
        &self,
        key: &str,
        unlock: Unlock<'_>,
    ) -> Result<Committed<Disabled>, Error> {
        let vw = self.load(key)?;
        self.files
            .disable_sync(&Target::new(key, vw.path.clone()), unlock)
    }

    /// Disable sync of vault `id`, whose vault file is missing (D9 of doc
    /// 18). A vault id that a vault file on this Mac holds is refused with
    /// `VaultIdExists`. See [`VaultWriter::disable_missing`].
    pub fn disable_missing(&self, id: Uuid, unlock: Unlock<'_>) -> Result<Disabled, Error> {
        if !self.existing_ids([id]).is_empty() {
            return Err(Error::VaultIdExists(ShortId::encode_uuid(id)));
        }
        self.files.disable_missing(id, unlock)
    }

    /// Sync report of vault `key`, read under the vault locks. Writes
    /// nothing. See [`SyncReport::read`].
    pub fn sync_report(&self, key: &str, unlock: Unlock<'_>) -> Result<SyncReport, Error> {
        let vw = self.load(key)?;
        SyncReport::read(&self.files, &Target::new(key, vw.path.clone()), unlock)
    }

    /// Write `root` as the synced folder of vault `key`, chosen again (D18 of
    /// doc 18). The caller calls `SyncManager::refresh`. See
    /// [`VaultWriter::set_sync_root`].
    pub fn set_sync_root(&self, key: &str, root: &TransportRoot) -> Result<(), Error> {
        let vw = self.load(key)?;
        self.files
            .set_sync_root(&Target::new(key, vw.path.clone()), root)
    }

    /// New recovery kit for the current sync key of vault `key`, such as for
    /// a vault with no recipient of the current key. Writes nothing. The
    /// caller adds it with [`RecoveryKit::confirm_saved`] after the user
    /// saves it. See [`VaultWriter::create_kit`].
    pub fn create_kit(&self, key: &str, unlock: Unlock<'_>) -> Result<RecoveryKit, Error> {
        let vw = self.load(key)?;
        self.files
            .create_kit(&Target::new(key, vw.path.clone()), unlock)
    }

    /// Vault files moved to `unreadable/` on new hardware, by unverified
    /// header, for the Settings list. See [`Unreadable::moved_vaults`].
    pub fn moved_vaults(&self) -> Vec<MovedVault> {
        Unreadable::moved_vaults(self.files.root())
    }

    /// Unlock each of `keys` on `context` and export them into one bundle file
    /// at `path`. Passkeys are included only if `include_passkeys` is set.
    /// File blobs are included, and a synced vault fetches the ones it lacks.
    /// The report lists the blobs that could not be included
    /// ([`export_bundle`]).
    pub fn export(
        &self,
        keys: &[String],
        path: &Path,
        export_mode: ExportMode,
        include_passkeys: bool,
        context: AuthContext,
        progress: impl FnMut(ExportProgress),
    ) -> Result<ExportReport, Error> {
        let vaults = keys
            .iter()
            .map(|key| self.open(key, context.clone()))
            .collect::<Result<Vec<_>, _>>()?;
        let refs: Vec<&VaultHandle> = vaults.iter().collect();
        export_bundle(
            &refs,
            path,
            export_mode,
            include_passkeys,
            &self.files,
            progress,
        )
    }

    /// Import the selected vaults of an opened bundle, re-wrapping each file
    /// key using `context`. `selection` maps a bundle vault id to an import key
    /// and an action. Copied vaults are given a new vault id. Returns the
    /// imported vaults (locked).
    ///
    /// Creates both Secure Enclave keys first if no vault file exists. With a
    /// vault file present it creates none, and on new hardware it fails with
    /// `NewHardware` and moves no file.
    ///
    /// The id and key checks read the headers of all vault files before the
    /// keychain is read. A vault imported with an id is rejected if an existing
    /// vault uses the id ([`Self::existing_ids`]). Keys already in use are
    /// rejected. The checks are not atomic with the writes.
    pub fn import(
        &self,
        bundle: ImportableBundle,
        selection: &BTreeMap<Uuid, ImportSelection>,
        context: AuthContext,
    ) -> Result<Vec<VaultHandle>, Error> {
        let found = self.read_all();
        let held = Self::folded_ids(&found);
        let existing: Vec<String> = selection
            .iter()
            .filter(|(id, selected)| {
                selected.action == ImportAction::Default && held.contains(&ShortId::folded(**id))
            })
            .map(|(id, _)| ShortId::encode_uuid(*id))
            .collect();
        if !existing.is_empty() {
            return Err(Error::VaultIdExists(existing.join(", ")));
        }

        // Keys are normalized before the check, since `import_with`
        // normalizes too, and a key that only collides after normalization
        // would otherwise pass.
        let claimed: BTreeSet<&str> = found.iter().map(|(_, vh)| vh.key.as_str()).collect();
        let mut targets = BTreeMap::new();
        for (id, selected) in selection {
            let key = normalized_key(&selected.key)
                .ok_or_else(|| Error::InvalidVaultKey(selected.key.clone()))?;
            if claimed.contains(key.as_str()) {
                return Err(Self::claimed(&key));
            }
            targets.insert(*id, ImportSelection::new(key, selected.action));
        }
        bundle.import_with(&targets, &self.vaults_dir, &self.files, || {
            self.ensure_keys(context.clone(), OnNewHardware::Fail)?;
            self.unlocker.file_key_wrapper(context)
        })
    }

    /// Retained versions of a vault, newest first.
    pub fn list_versions(&self, key: &str) -> Result<Vec<RetainedVersion>, Error> {
        let vh = self.load(key)?;
        self.files.list_versions(vh.peek_vault_id()?)
    }

    /// Delete every retained version of a vault. Returns the vault id and the
    /// number of versions deleted.
    pub fn erase_versions(&self, key: &str) -> Result<(Uuid, usize), Error> {
        let vh = self.load(key)?;
        let id = vh.peek_vault_id()?;
        Ok((id, self.files.erase_versions(id, &vh.path)?))
    }

    /// Rebuild vault `id` from its local sync state, for a vault file that is
    /// refused or missing, at `path` or else at its file in the vaults
    /// directory. See [`VaultWriter::rebuild`]. The vault key is the key in
    /// the file header at `path`, if it is valid and no other file claims it.
    /// Otherwise it is the normalized vault name of the sync state, or
    /// `vault`. If another file claims that key, `-{yyyymmdd}-{n}` with
    /// today's local date and the first free `n` from 1 is appended.
    pub fn rebuild(
        &self,
        id: Uuid,
        path: Option<&Path>,
        unlock: Unlock<'_>,
    ) -> Result<Committed<()>, Error> {
        let path = path.map_or_else(
            || VaultHandle::file_path(&self.vaults_dir, id),
            Path::to_path_buf,
        );
        let header_key = VaultHeader::peek(&path).ok().map(|header| header.key);
        let today = Zoned::now().date();
        self.files.rebuild(id, &path, unlock, |name| {
            Ok(self.rebuild_key(header_key, name, &path, today))
        })
    }

    /// Join the sync key `join` into the vault `into`, with the synced
    /// folder `root`, as the Mac named `name` (`sync/join_sync.rs`). See
    /// [`VaultWriter::join_sync`]. Returns the ids of the items whose later
    /// duplicate websites were removed.
    ///
    /// For `JoinInto::New`, a vault id that a vault file on this Mac holds is
    /// refused with `VaultIdExists` ([`Self::existing_ids`]). The new vault
    /// file is written in the vaults directory, named by its id, with the key
    /// that [`Self::rebuild_key`] gives for the vault name of the view. The
    /// caller then calls `SyncManager::refresh`, so the vault is watched.
    pub fn join_sync(
        &self,
        join: &JoinKey,
        into: JoinInto,
        root: &TransportRoot,
        name: &str,
        unlock: Unlock<'_>,
    ) -> Result<Committed<Vec<ItemId>>, Error> {
        let path = match into {
            JoinInto::Existing(target) => {
                return self
                    .files
                    .join_sync(join, JoinFile::Existing(&target), root, name, unlock);
            },
            JoinInto::New => VaultHandle::file_path(&self.vaults_dir, join.vault_id()),
        };
        if !self.existing_ids([join.vault_id()]).is_empty() {
            return Err(Error::VaultIdExists(ShortId::encode_uuid(join.vault_id())));
        }
        let today = Zoned::now().date();
        let choose_key =
            |view_name: Option<&str>| Ok(self.rebuild_key(None, view_name, &path, today));
        let file = JoinFile::New {
            path: path.clone(),
            choose_key: &choose_key,
        };
        self.files.join_sync(join, file, root, name, unlock)
    }

    /// Start a pairing of this Mac as the new Mac with the synced folder
    /// `root`, as the Mac named `name` (Device pairing steps 1 to 3). Returns
    /// the pairing and `vault-encryption-key`, which the caller hands to
    /// `SyncManager::pair` as its `PairingKeys`.
    ///
    /// The request map leaves out each vault whose join is refused (D14 of
    /// doc 18, [`Self::pairing_synced`]), so a vault whose sync state fails
    /// its signature or is missing is in the map for its re-link. If
    /// `vault-encryption-key` is present, it is read on `context` before the
    /// start, for the trust check. Otherwise the start creates it, and it is
    /// read after the start. Either way the caller reads it once. See
    /// `PendingPairing::start`, which moves every vault file to
    /// `unreadable/` on new hardware.
    pub fn start_pairing(
        &self,
        root: &TransportRoot,
        name: &str,
        context: AuthContext,
    ) -> Result<(PendingPairing, ManagedKey), Error> {
        self.start_pairing_with(root, name, context, |context| {
            self.keys.read_encryption_key(context)
        })
    }

    /// [`Self::start_pairing`] with the keys that `read` returns for a
    /// context, `None` if `vault-encryption-key` is missing.
    pub(crate) fn start_pairing_with<K: PairingKeys>(
        &self,
        root: &TransportRoot,
        name: &str,
        context: AuthContext,
        read: impl Fn(AuthContext) -> Result<Option<K>, Error>,
    ) -> Result<(PendingPairing, K), Error> {
        let transport = SyncSetup::transport(&self.files, root)?;
        let present = self.keys.probe_encryption_key() == KeyProbe::Present;
        let read_first = if present {
            read(context.clone())?
        } else {
            None
        };
        let synced = match &read_first {
            Some(keys) => self.pairing_synced(keys),
            None => BTreeSet::new(),
        };
        let pending = PendingPairing::start(
            &*transport,
            &synced,
            self.keys.as_ref(),
            &self.vault_files(),
            context.clone(),
            name,
        )?;
        // The request stays in the folder if the delete at quit does not
        // reach it. Dismissing it keeps this Mac from prompting for it.
        let request_id = pending.request().request_id;
        if let Err(e) = PairingPrompt::dismiss_request(root, self.files.root(), request_id) {
            log::warn!("Failed to dismiss own pairing request {request_id}: {e}");
        }
        let keys = match read_first {
            Some(keys) => keys,
            None => read(context)?.ok_or(Error::VaultEncryptionKeyMissing)?,
        };
        Ok((pending, keys))
    }

    /// Vault ids on this Mac whose join is refused, which a pairing request
    /// leaves out (D14 of doc 18).
    ///
    /// Each vault file and each local sync state is checked as the join
    /// checks it ([`SyncSetup::check_joinable`]). A vault file is verified,
    /// and the keyring of its sync state is unwrapped by `wrapper`. A sync
    /// state with no vault file is checked as the import of a new vault. A
    /// vault file that fails to load is left out, since its join fails too.
    fn pairing_synced(&self, wrapper: &impl SyncKeyWrapper) -> BTreeSet<Uuid> {
        let root = self.files.root();
        let signer = &**self.signer();
        let files = self.listed_targets();
        let ids: BTreeSet<Uuid> = files
            .keys()
            .copied()
            .chain(LocalSyncState::list(root).into_iter().map(|(id, _)| id))
            .collect();
        ids.into_iter()
            .filter(|id| {
                let joinable = match files.get(id) {
                    Some(target) => EncryptedVault::load(&target.path, signer).and_then(|vault| {
                        let keyring = SyncLoad::keyring(root, &vault, signer, wrapper);
                        SyncSetup::check_joinable(root, *id, Some(&vault), keyring.as_ref(), signer)
                    }),
                    None => SyncSetup::check_joinable(root, *id, None, None, signer),
                };
                // A vault paused by a separate enable or a declined rotation
                // is in the request, for the merge by pairing
                // (`SyncSetup::merge_state`).
                if matches!(joinable, Err(Error::SyncAlreadyEnabled))
                    && Sidecar::read(root, *id).is_ok_and(|sidecar| sidecar.merges_by_pairing())
                {
                    return false;
                }
                if let Err(e) = &joinable {
                    log::info!("Pairing leaves out vault {id}: {e}");
                }
                joinable.is_err()
            })
            .collect()
    }

    /// Import of the vaults in the request of `pending` with the synced
    /// folder `root`, as the Mac named `name` (D5 and D6 of doc 18). A vault
    /// id that a listed vault file holds joins that vault, and any other is
    /// imported as a new vault. Called after [`Self::start_pairing`], whose
    /// move on new hardware leaves no vault file.
    pub fn pairing_import(
        &self,
        pending: &PendingPairing,
        root: &TransportRoot,
        name: &str,
    ) -> PairingImport {
        let listed = self.listed_targets();
        let into = pending
            .request()
            .replicas
            .keys()
            .map(|vault_id| {
                let into = match listed.get(vault_id) {
                    Some(target) => JoinInto::Existing(target.clone()),
                    None => JoinInto::New,
                };
                (*vault_id, into)
            })
            .collect();
        PairingImport {
            name: name.to_string(),
            root: root.clone(),
            into,
        }
    }

    /// Target of each listed vault file, by vault id.
    fn listed_targets(&self) -> BTreeMap<Uuid, Target> {
        self.scan()
            .vaults
            .into_iter()
            .filter_map(|(key, vh)| {
                let id = vh.peek_vault_id().ok()?;
                Some((id, Target::new(key, vh.path.clone())))
            })
            .collect()
    }

    /// Import the sync key `key`, opened with a recovery kit, into the vault
    /// `into` with the synced folder `root`, as the Mac named `name` (D7 of
    /// doc 18). The UI calls `RecoveryImport::check` again while its wait is
    /// shown, and calls this after `Recovered`.
    ///
    /// The missing keys are created first with `OnNewHardware::MoveFiles`
    /// (P18 of doc 16). On new hardware every vault file moves to
    /// `unreadable/`, so no local vault holds the vault id, and the import
    /// builds a new vault whatever `into` states. The join reads
    /// `vault-encryption-key` on `context` once ([`Self::join_sync`]).
    pub fn import_recovered(
        &self,
        key: RecoveredKey,
        root: &TransportRoot,
        name: &str,
        into: JoinInto,
        context: AuthContext,
    ) -> Result<Committed<Vec<ItemId>>, Error> {
        self.import_recovered_with(
            key,
            root,
            name,
            into,
            context.clone(),
            Unlock::Context(context),
        )
    }

    /// [`Self::import_recovered`] with the keys of the join from `unlock`.
    pub(crate) fn import_recovered_with(
        &self,
        key: RecoveredKey,
        root: &TransportRoot,
        name: &str,
        into: JoinInto,
        context: AuthContext,
        unlock: Unlock<'_>,
    ) -> Result<Committed<Vec<ItemId>>, Error> {
        let new_hardware = self.key_state() == KeyState::NewHardware;
        self.ensure_keys(context, OnNewHardware::MoveFiles)?;
        let into = if new_hardware { JoinInto::New } else { into };
        self.join_sync(&JoinKey::recovered(key), into, root, name, unlock)
    }

    /// Key of a vault rebuilt at `path`, as [`Self::rebuild`] states.
    fn rebuild_key(
        &self,
        header_key: Option<String>,
        name: Option<&str>,
        path: &Path,
        today: Date,
    ) -> String {
        let claimed = self.claimed_keys(Some(path));
        if let Some(key) = header_key.filter(|key| validate_key(key) && !claimed.contains(key)) {
            return key;
        }
        let base = name
            .and_then(normalized_key)
            .unwrap_or_else(|| "vault".to_string());
        if !claimed.contains(&base) {
            return base;
        }
        let date = today.strftime("%Y%m%d");
        (1u64..)
            .map(|n| format!("{base}-{date}-{n}"))
            .find(|key| !claimed.contains(key))
            .expect("some index is free")
    }

    /// Move a file to the Trash with the macOS 15+ `trash` command, instead of
    /// deleting it permanently.
    fn move_to_trash(path: &Path) -> Result<(), Error> {
        let output = Command::new("trash")
            .arg(path)
            .output()
            .map_err(Error::VaultDeleteError)?;
        if !output.status.success() {
            return Err(Error::VaultDeleteError(io::Error::other(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
