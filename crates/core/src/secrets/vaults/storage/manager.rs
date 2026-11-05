use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use uuid::Uuid;

use crate::core::auth::AuthContext;
use crate::secrets::vaults::bundle::{ImportSelection, ImportableBundle};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::storage::catalog::{
    DuplicateVaultKeys, DuplicateVaults, MissingVault, VaultCatalog, VaultScanResult,
};
use crate::secrets::vaults::storage::device_keys::KeyState;
use crate::secrets::vaults::storage::handle::VaultHandle;
use crate::secrets::vaults::storage::txn::{Committed, Target, Unlock};

/// The app's copies of its vaults, by key. A copy stays unlocked between
/// edits, so reading items does not decrypt the file again. Every change to a
/// vault file goes through [`VaultCatalog`], and the manager keeps the saved
/// copy.
#[derive(Default)]
pub struct VaultsManager {
    store: VaultCatalog,
    vaults: BTreeMap<String, VaultHandle>,
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
    /// none yet.
    pub fn get_or_create_vault_mut(&mut self, key: &str) -> Result<&mut VaultHandle, Error> {
        if !self.vaults.contains_key(key) {
            log::debug!("Vault {key} not loaded, reading it from disk");
            let vw = self.store.load(key).inspect_err(|e| {
                log::error!("Error reading vault: {:?}", e);
            })?;
            self.vaults.insert(key.to_string(), vw);
        }
        Ok(self.vaults.get_mut(key).unwrap())
    }

    /// Drop every decrypted vault from memory. Pair with `invalidate_auth` so
    /// that reading items again costs both a decryption and a fresh prompt.
    pub fn lock_all(&mut self) {
        for (key, vault) in self.vaults.iter_mut() {
            log::debug!("Locking vault {key}");
            vault.lock();
        }
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

    /// Move a vault file to the Trash and drop its copy.
    pub fn delete_vault(&mut self, key: &str) -> Result<(), Error> {
        self.store.delete(key)?;
        self.vaults.remove(key);
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
        }
        let current = vault
            .peek_vault_id()
            .is_ok_and(|id| self.store.files().locks().is_current(id, save_count));
        if !current {
            vault.lock();
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
        }
        m.missing.retain(|missing| missing.id != id);
        m.install(committed);
        Ok(key)
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
        }
        if !self.store.files().locks().is_current(vault_id, save_count) {
            vault.lock();
        }
        self.vaults.insert(vault.key.clone(), vault);
        value
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tempfile::TempDir;

    use super::*;
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
            let manager = VaultsManager::with(VaultCatalog::with_unlocker(
                vaults_dir,
                files,
                Vec::new(),
                Arc::new(KeyUnlocker::default()),
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

        fn is_unlocked(&self, key: &str) -> bool {
            self.manager
                .get_vault(key)
                .is_some_and(|vw| vw.list_items().is_ok())
        }
    }

    #[test]
    fn the_saved_copy_of_the_newest_save_is_kept_unlocked() {
        let mut fx = Fixture::new();
        let target = fx.target();
        let committed = fx.add_item(&target, "alpha");

        fx.manager.install(committed);

        assert!(fx.is_unlocked("personal"));
        let vw = fx.manager.get_vault("personal").unwrap();
        assert!(vw.get_item_overview("alpha").unwrap().is_some());
    }

    #[test]
    fn a_copy_replaced_by_a_later_save_is_kept_locked() {
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
    fn a_renamed_vault_is_kept_under_its_new_key_only() {
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
    fn a_writer_waiting_for_a_vault_does_not_hold_the_manager() {
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
            std::thread::sleep(std::time::Duration::from_millis(100));
            // The manager is free while the writer waits.
            assert!(manager.try_lock().is_ok());
            drop(held);
            writer.join().unwrap();
        });
        let m = VaultsManager::lock(&manager);
        let vw = m.get_vault("personal").unwrap();
        assert!(vw.get_item_overview("alpha").unwrap().is_some());
    }
}
