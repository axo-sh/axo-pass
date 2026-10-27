use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::{fs, io};

use uuid::Uuid;

use crate::core::auth::AuthContext;
use crate::core::config::APP_CONFIG;
use crate::core::dirs::vaults_dir;
use crate::secrets::vaults::bundle::{ExportMode, ImportableBundle};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::signing::VaultSigner;
use crate::secrets::vaults::storage::handle::{
    ExportProgress, VaultHandle, export_bundle, get_vault_encryption_key, normalized_key,
};
use crate::secrets::vaults::storage::txn::{RetainedVersion, VaultWriter};

/// This struct tracks vault files on disk: the vaults directory, the external
/// vaults, and the retained versions and lock files. Operations read the
/// necessary files and does not keep the unlocked vaults. The app's unlocked
/// copies are kept by [`super::manager::VaultsManager`].
#[derive(Clone)]
pub struct VaultCatalog {
    vaults_dir: PathBuf,
    files: VaultWriter,
    /// External vault paths by key. `None` reads the app config each time.
    external: Option<BTreeMap<String, PathBuf>>,
    unlocker: Arc<dyn Unlocker>,
}

/// Unlocks a loaded vault. Implemented as a trait so it can be swapped out in
/// tests.
pub trait Unlocker: Send + Sync {
    fn unlock(&self, vw: &mut VaultHandle, context: AuthContext) -> Result<(), Error>;
}

/// Unlock with the file key in the keychain. This can prompt.
struct KeychainUnlocker;

impl Unlocker for KeychainUnlocker {
    fn unlock(&self, vw: &mut VaultHandle, context: AuthContext) -> Result<(), Error> {
        vw.unlock_on(context)
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
        }
    }

    /// Vaults in `vaults_dir` and `external`, with lock files under `files`.
    /// [`Self::unlock`] uses `unlocker`.
    #[cfg(test)]
    pub fn with_unlocker(
        vaults_dir: PathBuf,
        files: VaultWriter,
        external: BTreeMap<String, PathBuf>,
        unlocker: Arc<dyn Unlocker>,
    ) -> Self {
        Self {
            vaults_dir,
            files,
            external: Some(external),
            unlocker,
        }
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

    /// External vault paths by key.
    fn external_vaults(&self) -> BTreeMap<String, PathBuf> {
        match &self.external {
            Some(external) => external.clone(),
            None => APP_CONFIG
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .external_vaults
                .iter()
                .map(|(key, config)| (key.clone(), config.path.clone()))
                .collect(),
        }
    }

    /// Every vault by key, locked. A vault file in the vaults directory is
    /// used before an external vault with the same key. A file that fails to
    /// load is skipped.
    pub fn list(&self) -> BTreeMap<String, VaultHandle> {
        let mut vaults = BTreeMap::new();

        let entries = fs::read_dir(&self.vaults_dir)
            .into_iter()
            .flatten()
            .flatten();
        for entry in entries {
            let path = entry.path();
            if !path.is_file() || path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let Some(key) = path.file_stem().map(|s| s.to_string_lossy().to_string()) else {
                continue;
            };
            match VaultHandle::load_from_path(Some(key.clone()), &path, self.files.locks()) {
                Ok(vw) => {
                    vaults.insert(key, vw);
                },
                Err(e) => log::error!("Skipping {key}, failed to load: {e:?}"),
            }
        }

        for (key, path) in self.external_vaults() {
            if vaults.contains_key(&key) {
                log::error!(
                    "Vault with duplicate {key} found at {}, skipping",
                    path.display()
                );
                continue;
            }
            if let Ok(vw) =
                VaultHandle::load_from_path(Some(key.clone()), &path, self.files.locks())
            {
                vaults.insert(key, vw);
            }
        }

        vaults
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

    /// Load one vault by key, locked, without reading the other vault files. A
    /// file in the vaults directory is used before an external vault, as in
    /// [`Self::list`].
    pub fn load(&self, key: &str) -> Result<VaultHandle, Error> {
        let locks = self.files.locks();
        match VaultHandle::load(&self.vaults_dir, Some(key.to_string()), locks) {
            Err(Error::VaultNotFound(_)) => {},
            other => return other,
        }
        match self.external_vaults().get(key) {
            Some(path) => VaultHandle::load_from_path(Some(key.to_string()), path, locks),
            None => Err(Error::VaultNotFound(key.to_string())),
        }
    }

    /// Load one vault by key and unlock it on `context`. This can prompt.
    pub fn open(&self, key: &str, context: AuthContext) -> Result<VaultHandle, Error> {
        let mut vw = self.load(key)?;
        self.unlock(&mut vw, context)?;
        Ok(vw)
    }

    /// Unlock `vw` on `context`. This can prompt.
    pub fn unlock(&self, vw: &mut VaultHandle, context: AuthContext) -> Result<(), Error> {
        self.unlocker.unlock(vw, context)
    }

    /// Create and write a new vault. Returns it unlocked.
    pub fn create(&self, name: Option<String>, key: &str) -> Result<VaultHandle, Error> {
        let user_encryption_key = get_vault_encryption_key()?;
        let vw = VaultHandle::new_vault(name, &self.vaults_dir, key, user_encryption_key)?;
        self.files.create(&vw)?;
        Ok(vw)
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
    /// key on `context`. `selection` maps a bundle vault id to the key it is
    /// imported as. A key that a vault already has is refused. Returns the
    /// imported vaults, locked.
    pub fn import(
        &self,
        bundle: ImportableBundle,
        selection: &BTreeMap<Uuid, String>,
        context: AuthContext,
    ) -> Result<Vec<VaultHandle>, Error> {
        // Keys are normalized before the check, since `import` normalizes
        // too, and a key that only collides after normalization would
        // otherwise pass.
        let mut targets = BTreeMap::new();
        for (id, requested_key) in selection {
            let key = normalized_key(requested_key)
                .ok_or_else(|| Error::InvalidVaultKey(requested_key.clone()))?;
            match self.load(&key) {
                Err(Error::VaultNotFound(_)) => {},
                _ => {
                    return Err(Error::InvalidVaultKey(format!(
                        "A vault with key '{key}' already exists"
                    )));
                },
            }
            targets.insert(*id, key);
        }
        bundle.import(&targets, &self.vaults_dir, &self.files, context)
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

    use serde_json::{Value, json};
    use tempfile::TempDir;

    use super::*;
    use crate::secrets::vaults::storage::test_unlocker::KeyUnlocker;

    /// Catalog of one vault named "Personal" at key `personal`, in a temp
    /// directory. The unlocker holds its file key.
    struct Fixture {
        _dir: TempDir,
        catalog: VaultCatalog,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let vaults_dir = dir.path().join("vaults");
            let files = VaultWriter::isolated(dir.path().join("data"));
            let mut vh = VaultHandle::new_for_test_at(vaults_dir.join("personal.json"));
            vh.set_vault_name("Personal".to_string()).unwrap();
            files.create(&vh).unwrap();
            let keys = HashMap::from([(vh.vault_id().unwrap(), vh.unlocked_key().unwrap())]);
            let catalog = VaultCatalog::with_unlocker(
                vaults_dir,
                files,
                BTreeMap::new(),
                Arc::new(KeyUnlocker(keys)),
            );
            Self { _dir: dir, catalog }
        }

        /// Write the `personal` vault file to `{key}.json` after `edit`.
        fn write_edited(&self, key: &str, edit: impl FnOnce(&mut Value)) {
            let dir = self.catalog.vaults_dir();
            let data = fs::read_to_string(dir.join("personal.json")).unwrap();
            let mut vault: Value = serde_json::from_str(&data).unwrap();
            edit(&mut vault);
            let data = serde_json::to_string_pretty(&vault).unwrap();
            fs::write(dir.join(format!("{key}.json")), data).unwrap();
        }

        /// Replace the `personal` vault items with an entry that fails to
        /// parse.
        fn break_items(&self) {
            self.write_edited("personal", |vault| {
                vault["items"] = json!({ "00000000-0000-0000-0000-000000000001": "not an item" });
            });
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
}
