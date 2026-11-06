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
use crate::secrets::vaults::bundle::{
    ExportMode, FileKeyWrapper, ImportAction, ImportSelection, ImportableBundle,
};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::encrypted_vault::{VaultFileKey, VaultHeader};
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::format::signing::VaultSigner;
use crate::secrets::vaults::model::Vault;
use crate::secrets::vaults::storage::device_keys::{
    DeviceKeys, KeyState, KeychainKeys, OnNewHardware, VaultFiles, ensure_device_keys,
};
use crate::secrets::vaults::storage::handle::{
    ExportProgress, VaultHandle, export_bundle, get_vault_encryption_key_on, normalized_key,
    validate_key,
};
use crate::secrets::vaults::storage::resign::{Resign, Resigned};
#[cfg(test)]
use crate::secrets::vaults::storage::test_keys::TestKeys;
use crate::secrets::vaults::storage::txn::{
    Committed, RetainedVersion, Target, Unlock, VaultWriter,
};
use crate::secrets::vaults::storage::unreadable::{SyncedVault, Unreadable};
use crate::secrets::vaults::sync::join_sync::{JoinFile, JoinInto, JoinKey};
use crate::secrets::vaults::sync::local_state::LocalSyncState;
use crate::secrets::vaults::sync::model::ItemId;
use crate::secrets::vaults::sync::transport::TransportRoot;

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
    pub(super) fn with_keys(mut self, keys: Arc<dyn DeviceKeys>) -> Self {
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

    /// Key state of this Mac, probed without a prompt.
    pub fn key_state(&self) -> KeyState {
        KeyState::probe(self.keys.as_ref(), &self.vault_files())
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

    /// Write `vault` as a new file in the vaults directory, named by its id.
    /// Returns it unlocked.
    fn create_vault(&self, vault: Vault) -> Result<VaultHandle, Error> {
        let vh = VaultHandle::new_in(&self.vaults_dir, vault);
        self.files.create(&vh)?;
        Ok(vh)
    }

    /// Move a vault file to the Trash under the vault locks, so a save in
    /// progress cannot recreate it.
    pub fn delete(&self, key: &str) -> Result<(), Error> {
        let vw = self.load(key)?;
        self.files.delete(&vw.path, Self::move_to_trash)
    }

    /// Unlock each of `keys` on `context` and export them into one bundle file
    /// at `path`. Passkeys are included only if `include_passkeys` is set.
    pub fn export(
        &self,
        keys: &[String],
        path: &Path,
        export_mode: ExportMode,
        include_passkeys: bool,
        context: AuthContext,
        progress: impl FnMut(ExportProgress),
    ) -> Result<(), Error> {
        let vaults = keys
            .iter()
            .map(|key| self.open(key, context.clone()))
            .collect::<Result<Vec<_>, _>>()?;
        let refs: Vec<&VaultHandle> = vaults.iter().collect();
        export_bundle(&refs, path, export_mode, include_passkeys, progress)
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
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use secrecy::{ExposeSecret, SecretString};
    use serde_json::{Value, json};
    use tempfile::TempDir;

    use super::*;
    use crate::audit::test_support::test_dir;
    use crate::audit::{self, Action, AuditFilter};
    use crate::secrets::vaults::bundle::{ImportIdentity, SOURCE_VAULT_ID};
    use crate::secrets::vaults::format::encrypted_vault::EncryptedVault;
    use crate::secrets::vaults::format::signing::TestSigner;
    use crate::secrets::vaults::model::fields::FieldKind;
    use crate::secrets::vaults::storage::manager::VaultsManager;
    use crate::secrets::vaults::storage::test_unlocker::KeyUnlocker;

    /// Catalog of one vault named "Personal" at key `personal`, in a temp
    /// directory. The unlocker holds its file key.
    struct Fixture {
        dir: TempDir,
        catalog: VaultCatalog,
    }

    impl Fixture {
        fn new() -> Self {
            Self::with_external(&[])
        }

        /// Same as [`Self::new`], with an external vault at
        /// `external/{name}.json` for each of `names`. The files are not
        /// written. The `personal` vault is written by another writer, so the
        /// catalog locks track no vault yet.
        fn with_external(names: &[&str]) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let vaults_dir = dir.path().join("vaults");
            let data_dir = dir.path().join("data");
            let mut vh = VaultHandle::new_for_test_at(vaults_dir.join("personal.json"));
            vh.set_vault_name("Personal".to_string()).unwrap();
            VaultWriter::isolated(data_dir.clone()).create(&vh).unwrap();
            let external = names
                .iter()
                .map(|name| Self::external_path_in(&dir, name))
                .collect();
            let unlock_keys = HashMap::from([(vh.vault_id().unwrap(), vh.unlocked_key().unwrap())]);
            let catalog = VaultCatalog::with_unlocker(
                vaults_dir,
                VaultWriter::isolated(data_dir),
                external,
                Arc::new(KeyUnlocker(unlock_keys)),
            );
            Self { dir, catalog }
        }

        fn external_path_in(dir: &TempDir, name: &str) -> PathBuf {
            dir.path().join("external").join(format!("{name}.json"))
        }

        /// Path of external vault `name`.
        fn external_path(&self, name: &str) -> PathBuf {
            Self::external_path_in(&self.dir, name)
        }

        /// Path of vault file `name` in the vaults directory.
        fn vault_path(&self, name: &str) -> PathBuf {
            self.catalog.vaults_dir().join(format!("{name}.json"))
        }

        /// Vault id of the `personal` vault.
        fn personal_id(&self) -> Uuid {
            VaultHeader::peek(&self.vault_path("personal")).unwrap().id
        }

        /// Whether the catalog locks track vault `id`.
        fn is_tracked(&self, id: Uuid) -> bool {
            self.catalog.files().locks().contains(id)
        }

        /// Write the `personal` vault file to `path` after `edit`, signed
        /// again by the test device key. `edit` receives the `vault` object
        /// inside the file envelope, with its key set to the file stem of
        /// `path`.
        fn write_copy(&self, path: &Path, edit: impl FnOnce(&mut Value)) {
            let data = fs::read_to_string(self.vault_path("personal")).unwrap();
            let mut file: Value = serde_json::from_str(&data).unwrap();
            let stem = path.file_stem().unwrap().to_string_lossy();
            file["vault"]["key"] = json!(stem);
            edit(&mut file["vault"]);
            let data = EncryptedVault::sign_file_for_test(&file, &TestSigner::device());
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, data).unwrap();
        }

        /// Write the `personal` vault object to `{name}.json` without its
        /// envelope, as a format 1 file is.
        fn write_without_envelope(&self, name: &str) {
            let data = fs::read_to_string(self.vault_path("personal")).unwrap();
            let file: Value = serde_json::from_str(&data).unwrap();
            let data = serde_json::to_string_pretty(&file["vault"]).unwrap();
            fs::write(self.vault_path(name), data).unwrap();
        }

        /// Write the `personal` vault file to `{name}.json` after `edit`, as
        /// [`Self::write_copy`] does.
        fn write_edited(&self, name: &str, edit: impl FnOnce(&mut Value)) {
            self.write_copy(&self.vault_path(name), edit);
        }

        /// Replace the `personal` vault items with an entry that fails to
        /// parse.
        fn break_items(&self) {
            self.write_edited("personal", |vault| {
                vault["items"] = json!({ "00000000-0000-0000-0000-000000000001": "not an item" });
            });
        }
    }

    /// Edit that gives a vault a new id and the key `key`.
    fn other_vault(key: &str) -> impl FnOnce(&mut Value) {
        let key = key.to_string();
        move |vault| {
            vault["id"] = json!(ShortId::encode_uuid(Uuid::new_v4()));
            vault["key"] = json!(key);
        }
    }

    #[test]
    fn vault_with_unparsable_items_is_listed_by_name() {
        let fx = Fixture::new();
        fx.break_items();

        let vaults = fx.catalog.list();

        let vh = vaults.get("personal").expect("vault is listed");
        assert_eq!(vh.vault_name(), Some("Personal"));
    }

    #[test]
    fn vault_with_unparsable_items_fails_to_unlock() {
        let fx = Fixture::new();
        fx.break_items();

        let err = fx
            .catalog
            .open("personal", AuthContext::SharedThreadLocal)
            .err()
            .expect("unlock fails");

        assert!(
            matches!(err, Error::VaultDeserializationError(_)),
            "{err:?}"
        );
    }

    #[test]
    fn file_without_id_is_not_listed() {
        let fx = Fixture::new();
        fx.write_edited("missing-id", |vault| {
            vault.as_object_mut().unwrap().remove("id");
        });

        let vaults = fx.catalog.list();

        assert_eq!(vaults.into_keys().collect::<Vec<_>>(), ["personal"]);
    }

    #[test]
    fn file_whose_id_is_not_a_uuid_is_not_listed() {
        let fx = Fixture::new();
        fx.write_edited("bad-id", |vault| vault["id"] = json!("not-a-uuid"));

        let vaults = fx.catalog.list();

        assert_eq!(vaults.into_keys().collect::<Vec<_>>(), ["personal"]);
    }

    #[test]
    fn files_in_vaults_dir_with_one_id_are_both_reported() {
        let fx = Fixture::new();
        fx.write_edited("copy", |_| {});

        let scan = fx.catalog.scan();

        assert_eq!(
            scan.duplicates,
            [DuplicateVaults {
                id: fx.personal_id(),
                paths: vec![fx.vault_path("copy"), fx.vault_path("personal")],
            }]
        );
    }

    #[test]
    fn files_whose_ids_differ_only_in_case_are_both_reported() {
        let fx = Fixture::new();
        let lower = "bhRFe93MKwHktZwXKG599a";
        let upper = "bhRFe93MKwHktZwXKG599A";
        fx.write_edited("lower", |vault| vault["id"] = json!(lower));
        fx.write_edited("upper", |vault| vault["id"] = json!(upper));
        let lower_id = ShortId::parse_uuid(lower).unwrap();
        let upper_id = ShortId::parse_uuid(upper).unwrap();
        assert_ne!(lower_id, upper_id);

        let scan = fx.catalog.scan();

        assert_eq!(
            scan.duplicates,
            [DuplicateVaults {
                id: lower_id.min(upper_id),
                paths: vec![fx.vault_path("lower"), fx.vault_path("upper")],
            }]
        );
        assert_eq!(scan.vaults.into_keys().collect::<Vec<_>>(), ["personal"]);
        assert!(!fx.is_tracked(lower_id));
        assert!(!fx.is_tracked(upper_id));
    }

    #[test]
    fn hyphenated_and_short_forms_of_one_id_are_both_reported() {
        let fx = Fixture::new();
        let short = ShortId::encode_uuid(fx.personal_id());
        fx.write_edited("short", |vault| vault["id"] = json!(short));
        let hyphenated = fx.personal_id().hyphenated().to_string().to_uppercase();
        fx.write_edited("upper", |vault| vault["id"] = json!(hyphenated));

        let scan = fx.catalog.scan();

        assert_eq!(
            scan.duplicates,
            [DuplicateVaults {
                id: fx.personal_id(),
                paths: vec![
                    fx.vault_path("personal"),
                    fx.vault_path("short"),
                    fx.vault_path("upper"),
                ],
            }]
        );
        assert!(scan.vaults.is_empty());
    }

    #[test]
    fn format1_file_is_not_listed() {
        let fx = Fixture::new();
        fx.write_without_envelope("legacy");

        let scan = fx.catalog.scan();

        assert_eq!(scan.vaults.into_keys().collect::<Vec<_>>(), ["personal"]);
        assert!(scan.duplicates.is_empty(), "{:?}", scan.duplicates);
    }

    #[test]
    fn external_vault_is_signed_and_verified() {
        let fx = Fixture::with_external(&["outside"]);
        let path = fx.external_path("outside");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let vh = VaultHandle::new_for_test_at(path.clone());
        fx.catalog.files().create(&vh).unwrap();
        let signer = fx.catalog.signer().as_ref();

        assert_eq!(
            EncryptedVault::load(&path, signer).unwrap().id,
            vh.vault_id().unwrap()
        );
        let committed = fx
            .catalog
            .files()
            .write_unlocked::<_, Error>(&vh, |vw| vw.add_item("item", "Item").map(|_| ()))
            .unwrap();
        assert!(committed.changed);
        EncryptedVault::load(&path, signer).unwrap();
        assert!(fx.catalog.list().contains_key("outside"));

        // An edit by hand under the old signature is refused at the next
        // write, and the file is not modified.
        let saved = fs::read_to_string(&path).unwrap();
        let edited = saved.replacen("\"key\": \"outside\"", "\"key\": \"edited\"", 1);
        assert_ne!(edited, saved);
        fs::write(&path, &edited).unwrap();
        let result = fx
            .catalog
            .files()
            .write_unlocked::<_, Error>(&vh, |vw| vw.add_item("other", "Other").map(|_| ()));
        assert!(matches!(result, Err(Error::VaultSignatureInvalid)));
        assert_eq!(fs::read_to_string(&path).unwrap(), edited);
    }

    #[test]
    fn unsigned_file_that_claims_key_of_vault_refuses_both() {
        // The scan reads headers without verifying them, so an unsigned file
        // claims a key as a signed one does.
        let fx = Fixture::new();
        fx.write_edited("forged", other_vault("personal"));
        let path = fx.vault_path("forged");
        let mut fields: BTreeMap<String, Box<serde_json::value::RawValue>> =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        fields.remove("signature").unwrap();
        fs::write(&path, serde_json::to_string_pretty(&fields).unwrap()).unwrap();

        let scan = fx.catalog.scan();

        assert_eq!(
            scan.duplicate_keys,
            [DuplicateVaultKeys {
                key: "personal".to_string(),
                paths: vec![path, fx.vault_path("personal")],
            }]
        );
        assert!(scan.vaults.is_empty());
    }

    #[test]
    fn internal_and_external_files_with_one_id_are_both_reported() {
        let fx = Fixture::with_external(&["outside"]);
        fx.write_copy(&fx.external_path("outside"), |_| {});

        let scan = fx.catalog.scan();

        assert_eq!(
            scan.duplicates,
            [DuplicateVaults {
                id: fx.personal_id(),
                paths: vec![fx.external_path("outside"), fx.vault_path("personal")],
            }]
        );
        assert!(scan.vaults.is_empty());
        assert!(!fx.is_tracked(fx.personal_id()));
    }

    #[test]
    fn files_with_one_id_are_neither_listed_nor_tracked() {
        let fx = Fixture::new();
        fx.write_edited("copy", |_| {});

        let vaults = fx.catalog.list();

        assert!(vaults.is_empty(), "{:?}", vaults.keys());
        assert!(!fx.is_tracked(fx.personal_id()));
    }

    #[test]
    fn vault_with_another_id_is_listed_beside_duplicates() {
        let fx = Fixture::new();
        fx.write_edited("copy", |_| {});
        let work_id = Uuid::new_v4();
        fx.write_edited("work", |vault| vault["id"] = json!(work_id));

        let scan = fx.catalog.scan();

        assert_eq!(scan.vaults.into_keys().collect::<Vec<_>>(), ["work"]);
        assert!(fx.is_tracked(work_id));
        assert_eq!(scan.duplicates.len(), 1);
        assert_eq!(scan.duplicates[0].id, fx.personal_id());
    }

    #[test]
    fn external_link_to_listed_file_is_not_a_duplicate() {
        let fx = Fixture::with_external(&["alias"]);
        let link = fx.external_path("alias");
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(fx.vault_path("personal"), &link).unwrap();

        let scan = fx.catalog.scan();

        assert!(scan.duplicates.is_empty(), "{:?}", scan.duplicates);
        assert!(scan.duplicate_keys.is_empty(), "{:?}", scan.duplicate_keys);
        assert_eq!(scan.vaults.into_keys().collect::<Vec<_>>(), ["personal"]);
        assert!(fx.is_tracked(fx.personal_id()));
    }

    #[test]
    fn vault_key_is_read_from_file_and_not_from_file_name() {
        let fx = Fixture::new();
        fx.write_edited("misnamed", other_vault("work"));

        let vaults = fx.catalog.list();

        assert_eq!(vaults.into_keys().collect::<Vec<_>>(), ["personal", "work"]);
    }

    #[test]
    fn file_without_key_is_not_listed() {
        let fx = Fixture::new();
        fx.write_edited("keyless", |vault| {
            vault["id"] = json!(ShortId::encode_uuid(Uuid::new_v4()));
            vault.as_object_mut().unwrap().remove("key");
        });

        let scan = fx.catalog.scan();

        assert_eq!(scan.vaults.into_keys().collect::<Vec<_>>(), ["personal"]);
        assert!(scan.duplicate_keys.is_empty(), "{:?}", scan.duplicate_keys);
    }

    #[test]
    fn files_that_claim_one_key_are_both_reported() {
        let fx = Fixture::new();
        fx.write_edited("other", other_vault("personal"));
        let other_id = VaultHeader::peek(&fx.vault_path("other")).unwrap().id;

        let scan = fx.catalog.scan();

        assert_eq!(
            scan.duplicate_keys,
            [DuplicateVaultKeys {
                key: "personal".to_string(),
                paths: vec![fx.vault_path("other"), fx.vault_path("personal")],
            }]
        );
        assert!(scan.duplicates.is_empty(), "{:?}", scan.duplicates);
        assert!(scan.vaults.is_empty(), "{:?}", scan.vaults.keys());
        assert!(!fx.is_tracked(fx.personal_id()));
        assert!(!fx.is_tracked(other_id));
    }

    #[test]
    fn internal_and_external_files_that_claim_one_key_are_both_reported() {
        let fx = Fixture::with_external(&["outside"]);
        fx.write_copy(&fx.external_path("outside"), other_vault("personal"));

        let scan = fx.catalog.scan();

        assert_eq!(
            scan.duplicate_keys,
            [DuplicateVaultKeys {
                key: "personal".to_string(),
                paths: vec![fx.external_path("outside"), fx.vault_path("personal")],
            }]
        );
        assert!(scan.vaults.is_empty(), "{:?}", scan.vaults.keys());
        assert!(!fx.is_tracked(fx.personal_id()));
    }

    #[test]
    fn file_with_duplicate_id_and_key_is_reported_for_each() {
        let fx = Fixture::new();
        fx.write_edited("copy", |vault| vault["key"] = json!("personal"));
        let paths = vec![fx.vault_path("copy"), fx.vault_path("personal")];

        let scan = fx.catalog.scan();

        assert_eq!(
            scan.duplicates,
            [DuplicateVaults {
                id: fx.personal_id(),
                paths: paths.clone(),
            }]
        );
        assert_eq!(
            scan.duplicate_keys,
            [DuplicateVaultKeys {
                key: "personal".to_string(),
                paths,
            }]
        );
        assert!(scan.vaults.is_empty());
    }

    #[test]
    fn file_whose_key_differs_only_in_case_is_not_listed() {
        let fx = Fixture::new();
        fx.write_edited("upper", other_vault("Personal"));

        let scan = fx.catalog.scan();

        // A stored key must already be normalized, so `Personal` is refused
        // as an invalid key and does not claim `personal`.
        assert_eq!(scan.vaults.into_keys().collect::<Vec<_>>(), ["personal"]);
        assert!(scan.duplicate_keys.is_empty(), "{:?}", scan.duplicate_keys);
    }

    #[test]
    fn load_refuses_key_whose_id_is_held_by_two_files() {
        let fx = Fixture::new();
        fx.write_edited("copy", |_| {});

        for key in ["personal", "copy"] {
            let result = fx.catalog.load(key);
            assert!(
                matches!(result, Err(Error::DuplicateVaultId(_))),
                "{key}: {:?}",
                result.err()
            );
        }
        assert!(!fx.is_tracked(fx.personal_id()));
    }

    #[test]
    fn load_refuses_key_held_by_two_files() {
        let fx = Fixture::new();
        fx.write_edited("other", other_vault("personal"));

        let result = fx.catalog.load("personal");

        assert!(
            matches!(result, Err(Error::DuplicateVaultKey(_))),
            "{:?}",
            result.err()
        );
        assert!(!fx.is_tracked(fx.personal_id()));
    }

    #[test]
    fn load_finds_vault_by_key_stored_in_file() {
        let fx = Fixture::new();
        fx.write_edited("misnamed", other_vault("work"));

        let vh = fx.catalog.load("work").unwrap();

        assert_eq!(vh.path, fx.vault_path("misnamed"));
        assert!(matches!(
            fx.catalog.load("misnamed"),
            Err(Error::VaultNotFound(_))
        ));
    }

    #[test]
    fn write_through_key_of_one_of_two_files_with_one_id_fails_and_writes_nothing() {
        let fx = Fixture::new();
        fx.write_edited("copy", |_| {});
        let before = [
            fs::read_to_string(fx.vault_path("personal")).unwrap(),
            fs::read_to_string(fx.vault_path("copy")).unwrap(),
        ];
        let manager = Mutex::new(VaultsManager::with(fx.catalog.clone()));

        for key in ["personal", "copy"] {
            let result = VaultsManager::write_vault::<_, _, Error>(&manager, key, |vh| {
                vh.add_item("item", "Item").map(|_| ())
            });
            assert!(
                matches!(result, Err(Error::DuplicateVaultId(_))),
                "{key}: {:?}",
                result.err()
            );
        }

        let after = [
            fs::read_to_string(fx.vault_path("personal")).unwrap(),
            fs::read_to_string(fx.vault_path("copy")).unwrap(),
        ];
        assert_eq!(after, before);
        let versions = fx.catalog.files().list_versions(fx.personal_id()).unwrap();
        assert!(versions.is_empty());
    }

    #[test]
    fn created_vault_is_named_by_id_and_holds_its_key() {
        let fx = Fixture::new();
        let key = fx.catalog.unclaimed_key("Work Vault", None).unwrap();
        let mut vault = Vault::new_for_test();
        vault.set_key(key);

        let vh = fx.catalog.create_vault(vault).unwrap();

        let id = vh.vault_id().unwrap();
        let name = format!("{}.json", ShortId::encode_uuid(id));
        assert_eq!(vh.path, fx.catalog.vaults_dir().join(name));
        let header = VaultHeader::peek(&vh.path).unwrap();
        assert_eq!(header.id, id);
        assert_eq!(header.key, "work-vault");
        assert_eq!(fx.catalog.load("work-vault").unwrap().path, vh.path);
    }

    #[test]
    fn create_refuses_key_another_vault_holds_in_any_letter_case() {
        let fx = Fixture::new();

        // `normalized_key` lowercases and replaces whitespace with `-`, so
        // each of these is `personal`. The check runs before the keychain is
        // read.
        for key in ["personal", "Personal", " PERSONAL "] {
            let result = fx.catalog.create(None, key);
            assert!(
                matches!(&result, Err(Error::InvalidVaultKey(message)) if message.contains("already exists")),
                "{key}: {:?}",
                result.err()
            );
        }
        assert_eq!(fs::read_dir(fx.catalog.vaults_dir()).unwrap().count(), 1);
    }

    #[test]
    fn key_of_file_refused_for_its_id_is_still_claimed() {
        let fx = Fixture::new();
        fx.write_edited("copy", |_| {});

        assert!(fx.catalog.unclaimed_key("copy", None).is_err());
        assert!(fx.catalog.unclaimed_key("personal", None).is_err());
        assert_eq!(fx.catalog.unclaimed_key("work", None).unwrap(), "work");
    }

    #[test]
    fn key_of_another_vault_is_claimed_and_own_key_is_not() {
        let fx = Fixture::new();
        fx.write_edited("work", other_vault("work"));
        let own = fx.vault_path("personal");

        assert!(fx.catalog.unclaimed_key("work", Some(&own)).is_err());
        assert_eq!(
            fx.catalog.unclaimed_key("personal", Some(&own)).unwrap(),
            "personal"
        );
    }

    #[test]
    fn import_refuses_key_another_vault_holds_and_writes_nothing() {
        let fx = Fixture::new();
        let id = Uuid::new_v4();
        let bundle = ImportableBundle::for_test(&[id]);
        let selection = BTreeMap::from([(id, import_as("PERSONAL"))]);

        let result = fx
            .catalog
            .import(bundle, &selection, AuthContext::SharedThreadLocal);

        assert!(
            matches!(&result, Err(Error::InvalidVaultKey(message)) if message.contains("already exists")),
            "{:?}",
            result.err()
        );
        assert_eq!(fs::read_dir(fx.catalog.vaults_dir()).unwrap().count(), 1);
    }

    /// Selection of a vault imported under its bundle id as `key`.
    fn import_as(key: &str) -> ImportSelection {
        ImportSelection::new(key, ImportAction::Default)
    }

    /// Unlocker that fails the test if it is called, so a call through it
    /// would read the keychain in the app.
    struct NoKeychain;

    impl Unlocker for NoKeychain {
        fn unlock(
            &self,
            _vw: &mut VaultHandle,
            _root: &Path,
            _context: AuthContext,
        ) -> Result<(), Error> {
            panic!("unlock was called");
        }

        fn read_transaction(
            &self,
            _files: &VaultWriter,
            _target: &Target,
            _context: AuthContext,
        ) -> Result<Committed<()>, Error> {
            panic!("read transaction was called");
        }

        fn file_key_wrapper(&self, _context: AuthContext) -> Result<FileKeyWrapper, Error> {
            panic!("file key wrapper was requested");
        }

        fn new_vault(
            &self,
            _name: Option<String>,
            _key: String,
            _context: AuthContext,
        ) -> Result<Vault, Error> {
            panic!("new vault was requested");
        }
    }

    impl Fixture {
        /// Catalog of the fixture files whose unlocker fails the test if it
        /// is called.
        fn without_keychain(&self) -> VaultCatalog {
            VaultCatalog::with_unlocker(
                self.catalog.vaults_dir().to_path_buf(),
                VaultWriter::isolated(self.dir.path().join("data")),
                self.catalog.external.clone().unwrap_or_default(),
                Arc::new(NoKeychain),
            )
        }

        /// Write `value` to `item/token` of the `personal` vault.
        fn write_personal(&self, value: &str) {
            let vh = self.catalog.open("personal", AuthContext::OneTime).unwrap();
            self.catalog
                .files()
                .write_unlocked::<_, Error>(&vh, |vw| {
                    vw.add_item("item", "Item")?;
                    vw.add_secret(
                        "item",
                        "token",
                        "Token",
                        FieldKind::default(),
                        SecretString::from(value.to_string()),
                    )
                })
                .unwrap();
        }

        /// Export the `personal` vault, with passkeys, to a bundle file and
        /// open it.
        fn export_personal(&self) -> ImportableBundle {
            let identity = age::x25519::Identity::generate();
            let path = self.dir.path().join("personal.axovault");
            let mode = ExportMode::Recipient(identity.to_public().to_string());
            let keys = ["personal".to_string()];
            self.catalog
                .export(&keys, &path, mode, true, AuthContext::OneTime, |_| {})
                .unwrap();
            ImportableBundle::open(&path, ImportIdentity::Identity(identity)).unwrap()
        }

        /// Vault `key` as it is on disk, verified and unlocked.
        fn read(&self, key: &str) -> VaultHandle {
            self.catalog.open(key, AuthContext::OneTime).unwrap()
        }

        /// Value of `item/token` in vault `key`.
        fn token(&self, key: &str) -> Option<String> {
            self.read(key)
                .get_secret("item", "token")
                .unwrap()
                .map(|s| s.expose_secret().to_string())
        }

        /// Names of the files in the vaults directory.
        fn vault_file_names(&self) -> BTreeSet<String> {
            fs::read_dir(self.catalog.vaults_dir())
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        }
    }

    #[test]
    fn default_import_of_existing_id_writes_nothing_and_names_id() {
        let fx = Fixture::new();
        let other = Uuid::new_v4();
        let bundle = ImportableBundle::for_test(&[fx.personal_id(), other]);
        let selection = BTreeMap::from([
            (fx.personal_id(), import_as("restored")),
            (other, import_as("other")),
        ]);
        let before = fx.vault_file_names();

        // The refusal comes before the keychain is read.
        let result =
            fx.without_keychain()
                .import(bundle, &selection, AuthContext::SharedThreadLocal);

        let Err(Error::VaultIdExists(ids)) = result else {
            panic!("{:?}", result.err());
        };
        assert_eq!(ids, ShortId::encode_uuid(fx.personal_id()));
        assert_eq!(fx.vault_file_names(), before);
    }

    #[test]
    fn refusal_names_every_existing_id() {
        let fx = Fixture::new();
        fx.write_edited("work", other_vault("work"));
        let work_id = VaultHeader::peek(&fx.vault_path("work")).unwrap().id;
        let ids = [fx.personal_id(), work_id];
        let selection = BTreeMap::from([(ids[0], import_as("a")), (ids[1], import_as("b"))]);

        let result = fx.without_keychain().import(
            ImportableBundle::for_test(&ids),
            &selection,
            AuthContext::SharedThreadLocal,
        );

        let Err(Error::VaultIdExists(named)) = result else {
            panic!("{:?}", result.err());
        };
        for id in ids {
            assert!(named.contains(&ShortId::encode_uuid(id)), "{named}");
        }
    }

    #[test]
    fn copy_has_new_id_and_file_key_and_both_vaults_load_verified() {
        let _audit = test_dir();
        let fx = Fixture::new();
        fx.write_personal("secret");
        let source = fs::read_to_string(fx.vault_path("personal")).unwrap();
        let bundle = fx.export_personal();
        let selection = BTreeMap::from([(
            fx.personal_id(),
            ImportSelection::new("Personal Copy", ImportAction::Copy),
        )]);

        let imported = fx
            .catalog
            .import(bundle, &selection, AuthContext::SharedThreadLocal)
            .unwrap();

        let copy_id = imported[0].peek_vault_id().unwrap();
        assert_ne!(copy_id, fx.personal_id());
        let copy_name = format!("{}.json", ShortId::encode_uuid(copy_id));
        assert_eq!(imported[0].path, fx.catalog.vaults_dir().join(copy_name));
        let signer = fx.catalog.signer().as_ref();
        let copy = EncryptedVault::load(&imported[0].path, signer).unwrap();
        let original = EncryptedVault::load(&fx.vault_path("personal"), signer).unwrap();
        assert_eq!(copy.key, "personal-copy");
        assert_eq!(copy.name.as_deref(), Some("Personal"));
        assert_eq!(copy.generation, 0);
        assert_eq!(copy.replica_id, None);
        assert!(copy.file_key != original.file_key);
        assert_eq!(fx.token("personal-copy").as_deref(), Some("secret"));
        assert_eq!(fx.token("personal").as_deref(), Some("secret"));
        assert_eq!(
            fs::read_to_string(fx.vault_path("personal")).unwrap(),
            source
        );
        let scan = fx.catalog.scan();
        assert!(scan.duplicates.is_empty(), "{:?}", scan.duplicates);
        assert_eq!(
            scan.vaults.into_keys().collect::<Vec<_>>(),
            ["personal", "personal-copy"]
        );

        // The event names the copy and the bundle vault it was made from.
        let event = audit::read(&AuditFilter::default())
            .events
            .into_iter()
            .find(|event| event.action == Action::VaultImported)
            .unwrap();
        assert_eq!(event.detail["vault_id"], ShortId::encode_uuid(copy_id));
        assert_eq!(
            event.detail[SOURCE_VAULT_ID],
            ShortId::encode_uuid(fx.personal_id())
        );
    }

    #[test]
    fn copy_is_refused_under_key_of_its_source() {
        let fx = Fixture::new();
        let selection = BTreeMap::from([(
            fx.personal_id(),
            ImportSelection::new("personal", ImportAction::Copy),
        )]);

        let result = fx.without_keychain().import(
            ImportableBundle::for_test(&[fx.personal_id()]),
            &selection,
            AuthContext::SharedThreadLocal,
        );

        assert!(
            matches!(&result, Err(Error::InvalidVaultKey(message)) if message.contains("already exists")),
            "{:?}",
            result.err()
        );
        assert_eq!(fx.vault_file_names().len(), 1);
    }

    #[test]
    fn action_applies_to_its_vault_only() {
        let _audit = test_dir();
        let fx = Fixture::new();
        let other = Uuid::new_v4();
        let selection = BTreeMap::from([
            (
                fx.personal_id(),
                ImportSelection::new("personal-copy", ImportAction::Copy),
            ),
            (other, import_as("other")),
        ]);

        let imported = fx
            .catalog
            .import(
                ImportableBundle::for_test(&[fx.personal_id(), other]),
                &selection,
                AuthContext::SharedThreadLocal,
            )
            .unwrap();

        let ids: BTreeMap<String, Uuid> = imported
            .iter()
            .map(|vh| (vh.key.clone(), vh.peek_vault_id().unwrap()))
            .collect();
        assert_eq!(ids["other"], other);
        assert_ne!(ids["personal-copy"], fx.personal_id());
        assert_eq!(fx.read("other").vault_id().unwrap(), other);
        assert_eq!(
            fx.read("personal-copy").vault_id().unwrap(),
            ids["personal-copy"]
        );
        assert_eq!(fx.read("personal").vault_id().unwrap(), fx.personal_id());
    }

    #[test]
    fn id_check_finds_external_vault_that_is_not_tracked() {
        let fx = Fixture::with_external(&["outside"]);
        fx.write_copy(&fx.external_path("outside"), other_vault("outside"));
        let id = VaultHeader::peek(&fx.external_path("outside")).unwrap().id;
        assert!(!fx.is_tracked(id));

        let catalog = fx.without_keychain();
        assert_eq!(catalog.existing_ids([id]), BTreeSet::from([id]));
        let result = catalog.import(
            ImportableBundle::for_test(&[id]),
            &BTreeMap::from([(id, import_as("elsewhere"))]),
            AuthContext::SharedThreadLocal,
        );

        assert!(
            matches!(result, Err(Error::VaultIdExists(_))),
            "{:?}",
            result.err()
        );
        assert_eq!(fx.vault_file_names().len(), 1);
    }

    #[test]
    fn id_check_finds_id_that_differs_only_in_letter_case() {
        let fx = Fixture::new();
        let lower = "bhRFe93MKwHktZwXKG599a";
        let upper_id = ShortId::parse_uuid("bhRFe93MKwHktZwXKG599A").unwrap();
        fx.write_edited("lower", |vault| vault["id"] = json!(lower));

        let catalog = fx.without_keychain();
        assert_eq!(catalog.existing_ids([upper_id]), BTreeSet::from([upper_id]));
        let result = catalog.import(
            ImportableBundle::for_test(&[upper_id]),
            &BTreeMap::from([(upper_id, import_as("upper"))]),
            AuthContext::SharedThreadLocal,
        );

        assert!(
            matches!(result, Err(Error::VaultIdExists(_))),
            "{:?}",
            result.err()
        );
    }

    #[test]
    fn collision_report_lists_selected_ids_that_exist_without_keychain() {
        let fx = Fixture::new();
        // A file refused for a duplicate id and an unsigned file still hold
        // their ids.
        fx.write_edited("copy", |_| {});
        fx.write_edited("unsigned", other_vault("unsigned"));
        let path = fx.vault_path("unsigned");
        let unsigned_id = VaultHeader::peek(&path).unwrap().id;
        let mut fields: BTreeMap<String, Box<serde_json::value::RawValue>> =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        fields.remove("signature").unwrap();
        fs::write(&path, serde_json::to_string_pretty(&fields).unwrap()).unwrap();
        fx.write_edited("work", other_vault("work"));
        let work_id = VaultHeader::peek(&fx.vault_path("work")).unwrap().id;
        let absent = Uuid::new_v4();

        let existing = fx
            .without_keychain()
            .existing_ids([fx.personal_id(), unsigned_id, absent]);

        assert_eq!(existing, BTreeSet::from([fx.personal_id(), unsigned_id]));
        assert!(!existing.contains(&work_id));
    }
}
