use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::sync::{Mutex, MutexGuard};

use uuid::Uuid;

use crate::audit::SubjectIds;
use crate::core::auth::AuthContext;
use crate::secrets::vaults::bundle::{ImportSelection, ImportableBundle};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::files::{self, FileInput, FileSummary};
use crate::secrets::vaults::storage::catalog::{
    DuplicateVaultKeys, DuplicateVaults, MissingVault, VaultCatalog, VaultScanResult,
};
use crate::secrets::vaults::storage::device_keys::KeyState;
use crate::secrets::vaults::storage::handle::VaultHandle;
use crate::secrets::vaults::storage::txn::{Committed, Disabled, Target, Unlock};

/// The app's copies of its vaults, by key. A copy stays unlocked between
/// edits, so reading items does not decrypt the file again. Every change to a
/// vault file goes through [`VaultCatalog`], and the manager keeps the saved
/// copy.
#[derive(Default)]
pub struct VaultsManager {
    store: VaultCatalog,
    vaults: BTreeMap<String, VaultHandle>,
    /// Save count at which each unlocked copy was kept, by key. A copy whose
    /// count is no longer current is locked at its next use (D5).
    saves: BTreeMap<String, u64>,
    /// Vault ids held by more than one file when the manager was created.
    duplicates: Vec<DuplicateVaults>,
    /// Vault keys claimed by more than one file when the manager was created.
    duplicate_keys: Vec<DuplicateVaultKeys>,
    /// Local sync states with no vault file when the manager was created.
    missing: Vec<MissingVault>,
    /// Key state when the manager was created.
    key_state: KeyState,
}

impl VaultsManager {
    /// Lock a shared manager. A panic while it was held leaves the map usable.
    pub fn lock(manager: &Mutex<Self>) -> MutexGuard<'_, Self> {
        manager.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn new() -> Self {
        Self::with(VaultCatalog::app())
    }

    /// A manager of every vault in `store`, locked.
    pub fn with(store: VaultCatalog) -> Self {
        let VaultScanResult {
            vaults,
            duplicates,
            duplicate_keys,
            missing,
        } = store.scan();
        let key_state = store.key_state();
        Self {
            store,
            vaults,
            saves: BTreeMap::new(),
            duplicates,
            duplicate_keys,
            missing,
            key_state,
        }
    }

    /// Key state probed when the manager was created.
    pub fn key_state(&self) -> &KeyState {
        &self.key_state
    }

    pub fn store(&self) -> &VaultCatalog {
        &self.store
    }

    /// Vault ids held by more than one file. None of these files is in the
    /// manager.
    pub fn duplicates(&self) -> &[DuplicateVaults] {
        &self.duplicates
    }

    /// Vault keys claimed by more than one file. None of these files is in
    /// the manager.
    pub fn duplicate_keys(&self) -> &[DuplicateVaultKeys] {
        &self.duplicate_keys
    }

    /// Local sync states with no vault file.
    pub fn missing(&self) -> &[MissingVault] {
        &self.missing
    }

    pub fn iter_vault_keys(&self) -> impl Iterator<Item = String> + '_ {
        self.vaults.keys().cloned()
    }

    pub fn iter_vaults(&self) -> impl Iterator<Item = (&String, &VaultHandle)> {
        self.vaults.iter()
    }

    pub fn get_vault(&self, key: &str) -> Option<&VaultHandle> {
        self.vaults.get(key)
    }

    pub fn get_vault_mut(&mut self, key: &str) -> Option<&mut VaultHandle> {
        self.vaults.get_mut(key)
    }

    /// The copy of vault `key`, loaded from disk, locked, if this manager has
    /// none yet. A copy that a later save replaced, such as a transaction of
    /// the `SyncManager`, is locked first, so the next read reloads the file
    /// (D5).
    pub fn get_or_create_vault_mut(&mut self, key: &str) -> Result<&mut VaultHandle, Error> {
        self.relock_replaced(key);
        if !self.vaults.contains_key(key) {
            log::debug!("Vault {key} not loaded, reading it from disk");
            let vw = self.store.load(key).inspect_err(|e| {
                log::error!("Error reading vault: {:?}", e);
            })?;
            self.vaults.insert(key.to_string(), vw);
        }
        Ok(self.vaults.get_mut(key).unwrap())
    }

    /// Lock the copy of vault `key` if it was kept unlocked at a save count
    /// that is no longer current.
    fn relock_replaced(&mut self, key: &str) {
        let (Some(&saved), Some(vault)) = (self.saves.get(key), self.vaults.get_mut(key)) else {
            return;
        };
        let locks = self.store.files().locks();
        if vault
            .peek_vault_id()
            .is_ok_and(|id| locks.is_current(id, saved))
        {
            return;
        }
        log::debug!("Relocking vault {key}, which a later save replaced");
        vault.lock();
        self.saves.remove(key);
    }

    /// Record `vault`, kept under its key, as unlocked at save count
    /// `save_count` if that count is current. Otherwise lock it.
    fn keep_count(&mut self, vault: &mut VaultHandle, vault_id: Uuid, save_count: u64) {
        if self.store.files().locks().is_current(vault_id, save_count) {
            self.saves.insert(vault.key.clone(), save_count);
        } else {
            vault.lock();
            self.saves.remove(&vault.key);
        }
    }

    /// Drop every decrypted vault from memory. Pair with `invalidate_auth` so
    /// that reading items again costs both a decryption and a new unlock by the
    /// app.
    pub fn lock_all(&mut self) {
        for (key, vault) in self.vaults.iter_mut() {
            log::debug!("Locking vault {key}");
            vault.lock();
        }
        self.saves.clear();
    }

    /// Drop one decrypted vault from memory, so the next read reloads it from
    /// disk. Used after a broker request writes to a vault this manager also
    /// holds, since that write goes straight to disk and does not touch this
    /// copy.
    pub fn relock(&mut self, key: &str) {
        if let Some(vault) = self.vaults.get_mut(key) {
            log::debug!("Relocking vault {key} after a broker write");
            vault.lock();
        }
    }

    /// Create a vault and keep it, unlocked.
    pub fn add_vault(
        &mut self,
        name: Option<String>,
        vault_key: &str,
    ) -> Result<&VaultHandle, Error> {
        let vw = self.store.create(name, vault_key)?;
        let key = vw.key.clone(); // normalized key
        self.vaults.insert(key.clone(), vw);
        Ok(&self.vaults[&key])
    }

    /// Move the file of vault `key` of a shared manager to the Trash, as
    /// [`VaultCatalog::delete`] does, and drop its copy. The manager mutex is
    /// released while the delete runs, since the delete of a synced vault
    /// first disables sync in a transaction.
    pub fn delete_vault(manager: &Mutex<Self>, key: &str) -> Result<(), Error> {
        let store = VaultsManager::lock(manager).store.clone();
        store.delete(key)?;
        let mut m = VaultsManager::lock(manager);
        m.vaults.remove(key);
        m.saves.remove(key);
        Ok(())
    }

    /// Import the selected vaults of an opened bundle on the shared context,
    /// as [`VaultCatalog::import`] does, and keep them, locked. Returns their
    /// keys.
    pub fn import_bundle(
        &mut self,
        bundle: ImportableBundle,
        selection: &BTreeMap<Uuid, ImportSelection>,
    ) -> Result<Vec<String>, Error> {
        let imported = self
            .store
            .import(bundle, selection, AuthContext::SharedThreadLocal)?;
        let mut keys = Vec::with_capacity(imported.len());
        for vw in imported {
            keys.push(vw.key.clone());
            self.vaults.insert(vw.key.clone(), vw);
        }
        Ok(keys)
    }

    /// Run `f` on a vault of a shared manager in one transaction, then keep the
    /// saved copy. Generic over the caller's own error type so each frontend
    /// can keep its own error taxonomy. It needs `From<Error>` to absorb
    /// failures from the transaction itself.
    ///
    /// The manager mutex is held only to find the vault and to keep the saved
    /// copy, and is released while the transaction waits for the vault locks
    /// and runs.
    pub fn write_vault<F, R, E>(manager: &Mutex<Self>, vault_key: &str, f: F) -> Result<R, E>
    where
        F: FnOnce(&mut VaultHandle) -> Result<R, E>,
        E: From<Error>,
    {
        let (store, target) = Self::locate(manager, vault_key)?;
        let committed = store.files().write(&target, Unlock::App, f)?;
        Ok(VaultsManager::lock(manager).install(committed))
    }

    /// Add a file credential to a vault of a shared manager, as
    /// [`files::add_file`] does, and keep the saved copy. Locks as
    /// [`Self::write_vault`] does. Returns the audit ids of the credential.
    pub fn add_file<R: Read>(
        manager: &Mutex<Self>,
        vault_key: &str,
        item_key: &str,
        cred_key: &str,
        title: &str,
        input: FileInput<R>,
    ) -> Result<SubjectIds, Error> {
        Self::add_file_with(
            manager,
            vault_key,
            Unlock::App,
            item_key,
            cred_key,
            title,
            input,
        )
    }

    /// [`Self::add_file`] with the vault key unlocked by `unlock`.
    fn add_file_with<R: Read>(
        manager: &Mutex<Self>,
        vault_key: &str,
        unlock: Unlock<'_>,
        item_key: &str,
        cred_key: &str,
        title: &str,
        input: FileInput<R>,
    ) -> Result<SubjectIds, Error> {
        let (store, target) = Self::locate(manager, vault_key)?;
        let committed = files::add_file(
            store.files(),
            &target,
            unlock,
            item_key,
            cred_key,
            title,
            input,
        )?;
        Ok(VaultsManager::lock(manager).install(committed))
    }

    /// Replace the file of a credential of a shared manager, as
    /// [`files::replace_file`] does, and keep the saved copy. Returns the
    /// audit ids of the credential.
    pub fn replace_file<R: Read>(
        manager: &Mutex<Self>,
        vault_key: &str,
        item_key: &str,
        cred_key: &str,
        input: FileInput<R>,
    ) -> Result<SubjectIds, Error> {
        Self::replace_file_with(manager, vault_key, Unlock::App, item_key, cred_key, input)
    }

    /// [`Self::replace_file`] with the vault key unlocked by `unlock`.
    fn replace_file_with<R: Read>(
        manager: &Mutex<Self>,
        vault_key: &str,
        unlock: Unlock<'_>,
        item_key: &str,
        cred_key: &str,
        input: FileInput<R>,
    ) -> Result<SubjectIds, Error> {
        let (store, target) = Self::locate(manager, vault_key)?;
        let committed =
            files::replace_file(store.files(), &target, unlock, item_key, cred_key, input)?;
        Ok(VaultsManager::lock(manager).install(committed))
    }

    /// Move a file credential of a shared manager to the trash, as
    /// [`files::delete_file`] does, and keep the saved copy.
    pub fn delete_file(
        manager: &Mutex<Self>,
        vault_key: &str,
        item_key: &str,
        cred_key: &str,
    ) -> Result<(), Error> {
        Self::delete_file_with(manager, vault_key, Unlock::App, item_key, cred_key)
    }

    /// [`Self::delete_file`] with the vault key unlocked by `unlock`.
    fn delete_file_with(
        manager: &Mutex<Self>,
        vault_key: &str,
        unlock: Unlock<'_>,
        item_key: &str,
        cred_key: &str,
    ) -> Result<(), Error> {
        let (store, target) = Self::locate(manager, vault_key)?;
        let committed = files::delete_file(store.files(), &target, unlock, item_key, cred_key)?;
        VaultsManager::lock(manager).install(committed);
        Ok(())
    }

    /// Decrypt the file of a credential of a shared manager to `output`, as
    /// [`files::read_file`] does. The read unlocks its own copy of the vault
    /// on the shared context, so the manager mutex is not held while the file
    /// downloads or decrypts.
    pub fn read_file(
        manager: &Mutex<Self>,
        vault_key: &str,
        item_key: &str,
        cred_key: &str,
        output: impl Write,
    ) -> Result<FileSummary, Error> {
        Self::read_file_on(
            manager,
            vault_key,
            AuthContext::SharedThreadLocal,
            item_key,
            cred_key,
            output,
        )
    }

    /// [`Self::read_file`] with the vault unlocked on `context`.
    fn read_file_on(
        manager: &Mutex<Self>,
        vault_key: &str,
        context: AuthContext,
        item_key: &str,
        cred_key: &str,
        output: impl Write,
    ) -> Result<FileSummary, Error> {
        let (store, target) = Self::locate(manager, vault_key)?;
        let mut vh = VaultHandle::load_from_path(&target.path, store.files().locks())?;
        store.unlock_counted(&mut vh, context)?;
        files::read_file(store.files(), &vh, item_key, cred_key, output)
    }

    /// Unlock vault `vault_key` of a shared manager on the shared context and
    /// keep the unlocked copy. The read follows the rule of a broker read
    /// ([`VaultCatalog::unlock_counted`]), so it can run a transaction with
    /// no requested change first (D6).
    ///
    /// The manager mutex is held only to find the vault and to keep the
    /// copy, and is released while the read unlocks, so no per-vault mutex
    /// is taken under it. A copy that a later save replaced is kept locked,
    /// as [`Self::install`] keeps it.
    pub fn unlock_vault(manager: &Mutex<Self>, vault_key: &str) -> Result<(), Error> {
        let (store, target) = Self::locate(manager, vault_key)?;
        let mut vh = VaultHandle::load_from_path(&target.path, store.files().locks())?;
        let save_count = store.unlock_counted(&mut vh, AuthContext::SharedThreadLocal)?;
        VaultsManager::lock(manager).install_unlocked(&target.key, vh, save_count);
        Ok(())
    }

    /// Keep `vault`, unlocked for a read at save count `save_count`, in place
    /// of the copy known by `previous_key`. The copy is kept locked if a
    /// later save replaced it.
    fn install_unlocked(&mut self, previous_key: &str, mut vault: VaultHandle, save_count: u64) {
        if vault.key != previous_key {
            self.vaults.remove(previous_key);
            self.saves.remove(previous_key);
        }
        match vault.peek_vault_id() {
            Ok(id) => self.keep_count(&mut vault, id, save_count),
            Err(_) => {
                vault.lock();
                self.saves.remove(&vault.key);
            },
        }
        self.vaults.insert(vault.key.clone(), vault);
    }

    /// Replace a vault of a shared manager with its retained version `name`,
    /// and keep the restored copy. Returns the key, name, and id of the
    /// restored vault. The key differs from `vault_key` if the vault was
    /// renamed since the manager loaded it.
    pub fn restore_version(
        manager: &Mutex<Self>,
        vault_key: &str,
        name: &str,
    ) -> Result<(String, Option<String>, Uuid), Error> {
        let (store, target) = Self::locate(manager, vault_key)?;
        let committed = store.files().restore_version(&target, Unlock::App, name)?;
        Ok(Self::install_restored(manager, committed))
    }

    /// Replace a refused vault file of a shared manager with its retained
    /// version `name`, as [`super::txn::VaultWriter::restore_refused`] does,
    /// and keep the restored copy. Returns the key, name, and id of the
    /// restored vault.
    pub fn restore_refused(
        manager: &Mutex<Self>,
        vault_key: &str,
        name: &str,
    ) -> Result<(String, Option<String>, Uuid), Error> {
        let (store, target) = Self::locate(manager, vault_key)?;
        let committed = store.files().restore_refused(&target, Unlock::App, name)?;
        Ok(Self::install_restored(manager, committed))
    }

    /// Keep the copy a restore saved. Returns its key, name, and id.
    fn install_restored(
        manager: &Mutex<Self>,
        committed: Committed<()>,
    ) -> (String, Option<String>, Uuid) {
        let key = committed.vault.key.clone();
        let vault_name = committed.vault.vault_name().map(str::to_string);
        let vault_id = committed.vault_id;
        VaultsManager::lock(manager).install(committed);
        (key, vault_name, vault_id)
    }

    /// Rebuild vault `id` of a shared manager from its local sync state, as
    /// [`VaultCatalog::rebuild`] does, and keep the rebuilt copy. The rebuild
    /// replaces the file of a listed vault with that id, or else writes its
    /// file in the vaults directory. The vault is no longer listed as
    /// missing. Returns the key of the rebuilt vault.
    pub fn rebuild_vault(manager: &Mutex<Self>, id: Uuid) -> Result<String, Error> {
        let (store, listed) = {
            let m = VaultsManager::lock(manager);
            let listed = m
                .vaults
                .iter()
                .find(|(_, vh)| vh.peek_vault_id().is_ok_and(|listed| listed == id))
                .map(|(key, vh)| (key.clone(), vh.path.clone()));
            (m.store.clone(), listed)
        };
        let path = listed.as_ref().map(|(_, path)| path.as_path());
        let committed = store.rebuild(id, path, Unlock::App)?;
        let key = committed.vault.key.clone();
        let mut m = VaultsManager::lock(manager);
        if let Some((listed_key, _)) = listed
            && listed_key != key
        {
            m.vaults.remove(&listed_key);
            m.saves.remove(&listed_key);
        }
        m.missing.retain(|missing| missing.id != id);
        m.install(committed);
        Ok(key)
    }

    /// Disable sync of vault `vault_key` of a shared manager on the shared
    /// context, as [`VaultCatalog::disable_sync`] does, and keep the saved
    /// copy, which holds no replica id. The caller then calls
    /// `SyncManager::refresh`.
    pub fn disable_sync(manager: &Mutex<Self>, vault_key: &str) -> Result<Disabled, Error> {
        let (store, target) = Self::locate(manager, vault_key)?;
        let committed = store.files().disable_sync(&target, Unlock::App)?;
        Ok(VaultsManager::lock(manager).install(committed))
    }

    /// Disable sync of vault `id` of a shared manager, whose vault file is
    /// missing, as [`VaultCatalog::disable_missing`] does. The vault is no
    /// longer listed as missing. The caller then calls
    /// `SyncManager::refresh`.
    pub fn disable_missing_vault(manager: &Mutex<Self>, id: Uuid) -> Result<Disabled, Error> {
        let store = VaultsManager::lock(manager).store.clone();
        let disabled = store.disable_missing(id, Unlock::App)?;
        VaultsManager::lock(manager)
            .missing
            .retain(|missing| missing.id != id);
        Ok(disabled)
    }

    /// Run `f` on the store and the target of vault `vault_key` of a shared
    /// manager, then keep the copy that the transaction of `f` saved. For
    /// entries that return their own [`Committed`], such as the confirm of a
    /// sync setup or a sync override. The manager mutex is released while `f`
    /// runs.
    pub fn transact<R>(
        manager: &Mutex<Self>,
        vault_key: &str,
        f: impl FnOnce(&VaultCatalog, &Target) -> Result<Committed<R>, Error>,
    ) -> Result<R, Error> {
        let (store, target) = Self::locate(manager, vault_key)?;
        let committed = f(&store, &target)?;
        Ok(VaultsManager::lock(manager).install(committed))
    }

    /// Scan the vault files again, for files added or moved outside this
    /// manager, such as a vault of a pairing import or the move to
    /// `unreadable/` on new hardware. The copy of a vault with the same key,
    /// path, and vault id stays. Other copies are dropped. The duplicates, the
    /// missing vaults, and the key state are replaced.
    pub fn rescan(&mut self) {
        let VaultScanResult {
            vaults,
            duplicates,
            duplicate_keys,
            missing,
        } = self.store.scan();
        let mut previous = std::mem::take(&mut self.vaults);
        let mut kept = BTreeSet::new();
        for (key, scanned) in vaults {
            let held = previous.remove(&key).filter(|held| {
                held.path == scanned.path
                    && held
                        .peek_vault_id()
                        .is_ok_and(|id| scanned.peek_vault_id().is_ok_and(|other| other == id))
            });
            let vault = match held {
                Some(held) => {
                    kept.insert(key.clone());
                    held
                },
                None => scanned,
            };
            self.vaults.insert(key, vault);
        }
        self.saves.retain(|key, _| kept.contains(key));
        self.duplicates = duplicates;
        self.duplicate_keys = duplicate_keys;
        self.missing = missing;
        self.key_state = self.store.key_state();
    }

    /// Store and target of a vault of a shared manager, loading the vault if
    /// the manager has not yet. The manager mutex is released on return.
    fn locate(manager: &Mutex<Self>, vault_key: &str) -> Result<(VaultCatalog, Target), Error> {
        let mut m = VaultsManager::lock(manager);
        let target = Target::of(m.get_or_create_vault_mut(vault_key)?);
        Ok((m.store.clone(), target))
    }

    /// Keep the copy of a vault a transaction saved, and return the
    /// transaction result. A copy that a later save replaced is kept locked,
    /// so the next read reloads the file.
    pub fn install<R>(&mut self, committed: Committed<R>) -> R {
        let Committed {
            value,
            mut vault,
            vault_id,
            previous_key,
            save_count,
            ..
        } = committed;
        if vault.key != previous_key {
            self.vaults.remove(&previous_key);
            self.saves.remove(&previous_key);
        }
        self.keep_count(&mut vault, vault_id, save_count);
        self.vaults.insert(vault.key.clone(), vault);
        value
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;

    use tempfile::TempDir;

    use super::*;
    use crate::secrets::vaults::FieldKind;
    use crate::secrets::vaults::files::store::BlobStore;
    use crate::secrets::vaults::storage::test_unlocker::KeyUnlocker;
    use crate::secrets::vaults::storage::txn::VaultWriter;

    /// A manager holding one vault written to a temp directory. Its store has
    /// no external vaults, so the app config is not read.
    struct Fixture {
        _dir: TempDir,
        manager: VaultsManager,
        /// The vault as created, unlocked. Its file key opens the file.
        original: VaultHandle,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let vaults_dir = dir.path().join("vaults");
            let files = VaultWriter::isolated(dir.path().join("data"));
            let original = VaultHandle::new_for_test_at(vaults_dir.join("personal.json"));
            files.create(&original).unwrap();
            let keys = HashMap::from([(
                original.vault_id().unwrap(),
                original.unlocked_key().unwrap(),
            )]);
            let manager = VaultsManager::with(VaultCatalog::with_unlocker(
                vaults_dir,
                files,
                Vec::new(),
                Arc::new(KeyUnlocker(keys)),
            ));
            Self {
                _dir: dir,
                manager,
                original,
            }
        }

        fn target(&self) -> Target {
            Target::of(self.manager.get_vault("personal").unwrap())
        }

        /// Add item `key` in a transaction, without keeping the saved copy.
        fn add_item(&self, target: &Target, key: &str) -> Committed<()> {
            self.manager
                .store
                .files()
                .write::<_, Error>(target, Unlock::Unlocked(&self.original), |vw| {
                    vw.add_item(key, key).map(|_| ())
                })
                .unwrap()
        }

        fn vaults_dir(&self) -> PathBuf {
            self._dir.path().join("vaults")
        }

        fn is_unlocked(&self, key: &str) -> bool {
            self.manager
                .get_vault(key)
                .is_some_and(|vw| vw.list_items().is_ok())
        }
    }

    #[test]
    fn saved_copy_of_newest_save_kept_unlocked() {
        let mut fx = Fixture::new();
        let target = fx.target();
        let committed = fx.add_item(&target, "alpha");

        fx.manager.install(committed);

        assert!(fx.is_unlocked("personal"));
        let vw = fx.manager.get_vault("personal").unwrap();
        assert!(vw.get_item_overview("alpha").unwrap().is_some());
    }

    #[test]
    fn copy_replaced_by_later_save_kept_locked() {
        let mut fx = Fixture::new();
        let target = fx.target();
        let earlier = fx.add_item(&target, "alpha");
        // A broker write or another app edit saves after the first, and its
        // copy is not kept here.
        fx.add_item(&target, "beta");

        fx.manager.install(earlier);

        // The stale copy lacks "beta", so it is locked and the next read
        // reloads the file.
        assert!(!fx.is_unlocked("personal"));
    }

    #[test]
    fn renamed_vault_kept_under_its_new_key_only() {
        let mut fx = Fixture::new();
        let target = fx.target();
        let committed = fx
            .manager
            .store
            .files()
            .write::<_, Error>(&target, Unlock::Unlocked(&fx.original), |vw| {
                vw.set_vault_key("renamed".to_string())
            })
            .unwrap();

        fx.manager.install(committed);

        assert!(fx.manager.get_vault("personal").is_none());
        assert!(fx.is_unlocked("renamed"));
        assert_eq!(
            fx.manager.get_vault("renamed").unwrap().path,
            fx.original.path
        );
    }

    #[test]
    fn transact_holds_copy_saved_by_its_transaction_unlocked() {
        let fx = Fixture::new();
        let original = &fx.original;
        let manager = Mutex::new(fx.manager);

        VaultsManager::transact(&manager, "personal", |store, target| {
            // The manager is free while the transaction runs.
            assert!(manager.try_lock().is_ok());
            store
                .files()
                .write::<_, Error>(target, Unlock::Unlocked(original), |vw| {
                    vw.add_item("alpha", "Alpha").map(|_| ())
                })
        })
        .unwrap();

        let m = VaultsManager::lock(&manager);
        let vw = m.get_vault("personal").unwrap();
        assert!(vw.get_item_overview("alpha").unwrap().is_some());
    }

    #[test]
    fn rescan_lists_added_vault_copy_stays_unlocked() {
        let mut fx = Fixture::new();
        let target = fx.target();
        let committed = fx.add_item(&target, "alpha");
        fx.manager.install(committed);
        let added = VaultHandle::new_for_test_at(fx.vaults_dir().join("work.json"));
        fx.manager.store.files().create(&added).unwrap();

        fx.manager.rescan();

        assert!(fx.manager.get_vault("work").is_some());
        assert!(fx.is_unlocked("personal"));
    }

    #[test]
    fn rescan_drops_vault_whose_file_moved() {
        let mut fx = Fixture::new();
        let target = fx.target();
        let committed = fx.add_item(&target, "alpha");
        fx.manager.install(committed);
        fs::rename(&fx.original.path, fx._dir.path().join("moved.json")).unwrap();

        fx.manager.rescan();

        assert!(fx.manager.get_vault("personal").is_none());
        assert!(!fx.manager.saves.contains_key("personal"));
    }

    #[test]
    fn writer_waiting_for_vault_does_not_hold_manager() {
        let fx = Fixture::new();
        let id = fx.original.vault_id().unwrap();
        let path = fx.original.path.clone();
        let original = &fx.original;
        let manager = Mutex::new(fx.manager);

        // Hold the vault locks, as a long transaction would, and start a
        // writer that waits for them as `write_vault` does.
        let (store, target) = VaultsManager::locate(&manager, "personal").unwrap();
        let held = store.files().hold_for_test(id, &path);
        std::thread::scope(|s| {
            let writer = s.spawn(|| {
                let committed = store
                    .files()
                    .write::<_, Error>(&target, Unlock::Unlocked(original), |vw| {
                        vw.add_item("alpha", "Alpha").map(|_| ())
                    })
                    .unwrap();
                VaultsManager::lock(&manager).install(committed);
            });
            store.files().locks().wait_for_waiters(id, 1);
            // The manager is free while the writer waits.
            assert!(manager.try_lock().is_ok());
            drop(held);
            writer.join().unwrap();
        });
        let m = VaultsManager::lock(&manager);
        let vw = m.get_vault("personal").unwrap();
        assert!(vw.get_item_overview("alpha").unwrap().is_some());
    }

    /// Manager of a fixture vault that holds item `item`, shared, with the
    /// unlocked vault that opens its file.
    fn manager_with_item() -> (Mutex<VaultsManager>, VaultHandle, TempDir) {
        let fx = Fixture::new();
        let original = fx.original;
        let manager = Mutex::new(fx.manager);
        VaultsManager::transact(&manager, "personal", |store, target| {
            store
                .files()
                .write::<_, Error>(target, Unlock::Unlocked(&original), |vw| {
                    vw.add_item("item", "Item").map(|_| ())
                })
        })
        .unwrap();
        (manager, original, fx._dir)
    }

    fn input(name: &str, contents: &'static [u8]) -> FileInput<&'static [u8]> {
        FileInput {
            name: name.to_string(),
            mime: Some("text/plain".to_string()),
            contents,
        }
    }

    fn read(manager: &Mutex<VaultsManager>, cred: &str) -> Result<(FileSummary, Vec<u8>), Error> {
        let mut out = Vec::new();
        let summary = VaultsManager::read_file_on(
            manager,
            "personal",
            AuthContext::OneTime,
            "item",
            cred,
            &mut out,
        )?;
        Ok((summary, out))
    }

    #[test]
    fn file_added_replaced_read_and_deleted_through_manager() {
        let (manager, original, _dir) = manager_with_item();

        let ids = VaultsManager::add_file_with(
            &manager,
            "personal",
            Unlock::Unlocked(&original),
            "item",
            "doc",
            "Doc",
            input("doc.txt", b"first"),
        )
        .unwrap();
        assert!(ids.credential_id.is_some());
        let (summary, contents) = read(&manager, "doc").unwrap();
        assert_eq!(contents, b"first");
        assert_eq!(summary.name, "doc.txt");
        assert_eq!(summary.size, 5);
        assert_eq!(summary.mime.as_deref(), Some("text/plain"));

        VaultsManager::replace_file_with(
            &manager,
            "personal",
            Unlock::Unlocked(&original),
            "item",
            "doc",
            input("doc2.txt", b"second file"),
        )
        .unwrap();
        let (summary, contents) = read(&manager, "doc").unwrap();
        assert_eq!(contents, b"second file");
        assert_eq!(summary.name, "doc2.txt");

        VaultsManager::delete_file_with(
            &manager,
            "personal",
            Unlock::Unlocked(&original),
            "item",
            "doc",
        )
        .unwrap();
        assert!(matches!(
            read(&manager, "doc"),
            Err(Error::InvalidCredentialKey(_))
        ));
    }

    #[test]
    fn replace_and_delete_refuse_non_file_credential() {
        let (manager, original, _dir) = manager_with_item();
        VaultsManager::transact(&manager, "personal", |store, target| {
            store
                .files()
                .write::<_, Error>(target, Unlock::Unlocked(&original), |vw| {
                    vw.add_new_secret(
                        "item",
                        "text",
                        "Text",
                        FieldKind::default(),
                        "value".to_string().into(),
                    )
                })
        })
        .unwrap();

        let replaced = VaultsManager::replace_file_with(
            &manager,
            "personal",
            Unlock::Unlocked(&original),
            "item",
            "text",
            input("a.txt", b"a"),
        );
        let deleted = VaultsManager::delete_file_with(
            &manager,
            "personal",
            Unlock::Unlocked(&original),
            "item",
            "text",
        );

        assert!(matches!(replaced, Err(Error::InvalidCredentialKey(_))));
        assert!(matches!(deleted, Err(Error::InvalidCredentialKey(_))));
    }

    #[test]
    fn read_reports_missing_and_damaged_blobs() {
        let (manager, original, _dir) = manager_with_item();
        for cred in ["missing", "damaged"] {
            VaultsManager::add_file_with(
                &manager,
                "personal",
                Unlock::Unlocked(&original),
                "item",
                cred,
                cred,
                input("a.txt", b"contents"),
            )
            .unwrap();
        }
        let store_of = |cred: &str| {
            let m = VaultsManager::lock(&manager);
            let vh = m.get_vault("personal").unwrap();
            let record = crate::secrets::vaults::files::read_record(vh, "item", cred).unwrap();
            let store = BlobStore::of(m.store.files().root(), vh.vault_id().unwrap());
            (store, record.blob)
        };
        let (store, blob) = store_of("missing");
        store.delete(&blob).unwrap();
        let (store, blob) = store_of("damaged");
        let mut bytes = fs::read(store.path(&blob)).unwrap();
        bytes[0] ^= 1;
        fs::write(store.path(&blob), bytes).unwrap();

        assert!(matches!(
            read(&manager, "missing"),
            Err(Error::FileMissing(_))
        ));
        assert!(matches!(
            read(&manager, "damaged"),
            Err(Error::FileBlobMismatch(_))
        ));
    }
}
