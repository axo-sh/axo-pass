use std::collections::{BTreeMap, BTreeSet};
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
use crate::secrets::vaults::format::encrypted_vault::VaultHeader;
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

/// Vault files found by [`VaultCatalog::scan`].
#[derive(Default)]
pub struct VaultScanResult {
    /// Listed vaults by key, locked.
    pub vaults: BTreeMap<String, VaultHandle>,
    /// Vault ids held by more than one file, ordered by id.
    pub duplicates: Vec<DuplicateVaults>,
}

/// Vault files that hold one vault id. None of them is listed or tracked in
/// the vault locks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplicateVaults {
    pub id: Uuid,
    /// Paths of the files, ordered by vault key.
    pub paths: Vec<PathBuf>,
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

    /// Every vault by key, locked. Same as the vaults of [`Self::scan`].
    pub fn list(&self) -> BTreeMap<String, VaultHandle> {
        self.scan().vaults
    }

    /// Scan the vault dir for vaults. Every vault by key, locked, and the vault
    /// ids held by more than one file. A vault file in the vaults directory
    /// is used before an external vault with the same key. Files that fail
    /// to load are skipped.
    ///
    /// Every header is read before any path is tracked in the vault locks.
    /// Files that share a vault id are not listed and not tracked, so no
    /// handle from this list can write to them.
    pub fn scan(&self) -> VaultScanResult {
        // Vaults found by key, with their ids. Nothing is tracked yet.
        let mut found = BTreeMap::new();

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
            match Self::read_locked(key.clone(), &path) {
                Ok(vault) => {
                    found.insert(key, vault);
                },
                Err(e) => log::error!("Skipping {key}, failed to load: {e:?}"),
            }
        }

        for (key, path) in self.external_vaults() {
            if found.contains_key(&key) {
                log::error!(
                    "Vault with duplicate {key} found at {}, skipping",
                    path.display()
                );
                continue;
            }
            if let Ok(vault) = Self::read_locked(key.clone(), &path) {
                found.insert(key, vault);
            }
        }

        let mut paths_by_id: BTreeMap<Uuid, Vec<PathBuf>> = BTreeMap::new();
        for (id, vh) in found.values() {
            paths_by_id.entry(*id).or_default().push(vh.path.clone());
        }
        let duplicates: Vec<DuplicateVaults> = paths_by_id
            .into_iter()
            .filter(|(_, paths)| Self::distinct_files(paths) > 1)
            .map(|(id, paths)| DuplicateVaults { id, paths })
            .collect();
        for duplicate in &duplicates {
            log::error!(
                "Skipping vault {}, vault id in use by multiple files: {:?}",
                duplicate.id,
                duplicate.paths
            );
        }

        let mut vaults = BTreeMap::new();
        for (key, (id, vh)) in found {
            // skip dupes
            if duplicates.iter().any(|duplicate| duplicate.id == id) {
                continue;
            }
            self.files.locks().track(id, &vh.path);
            vaults.insert(key, vh);
        }

        VaultScanResult { vaults, duplicates }
    }

    /// Locked vault at `path` named `key`, and its vault id. Only the header
    /// is read. The path is not tracked in the vault locks.
    fn read_locked(key: String, path: &Path) -> Result<(Uuid, VaultHandle), Error> {
        let header = VaultHeader::peek(path)?;
        let id = header.id;
        Ok((id, VaultHandle::from_header(Some(key), path, header)?))
    }

    /// Number of distinct files in `paths`. Two paths to one file, such as an
    /// external vault path that points into the vaults directory, count once.
    fn distinct_files(paths: &[PathBuf]) -> usize {
        paths
            .iter()
            .map(|path| path.canonicalize().unwrap_or_else(|_| path.clone()))
            .collect::<BTreeSet<_>>()
            .len()
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
        dir: TempDir,
        catalog: VaultCatalog,
    }

    impl Fixture {
        fn new() -> Self {
            Self::with_external(&[])
        }

        /// Same as [`Self::new`], with an external vault at
        /// `external/{key}.json` for each of `keys`. The files are not
        /// written. The `personal` vault is written by another writer, so the
        /// catalog locks track no vault yet.
        fn with_external(keys: &[&str]) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let vaults_dir = dir.path().join("vaults");
            let data_dir = dir.path().join("data");
            let mut vh = VaultHandle::new_for_test_at(vaults_dir.join("personal.json"));
            vh.set_vault_name("Personal".to_string()).unwrap();
            VaultWriter::isolated(data_dir.clone()).create(&vh).unwrap();
            let external = keys
                .iter()
                .map(|key| (key.to_string(), Self::external_path_in(&dir, key)))
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

        fn external_path_in(dir: &TempDir, key: &str) -> PathBuf {
            dir.path().join("external").join(format!("{key}.json"))
        }

        /// Path of external vault `key`.
        fn external_path(&self, key: &str) -> PathBuf {
            Self::external_path_in(&self.dir, key)
        }

        /// Path of vault file `key` in the vaults directory.
        fn vault_path(&self, key: &str) -> PathBuf {
            self.catalog.vaults_dir().join(format!("{key}.json"))
        }

        /// Vault id of the `personal` vault.
        fn personal_id(&self) -> Uuid {
            VaultHeader::peek(&self.vault_path("personal")).unwrap().id
        }

        /// Whether the catalog locks track vault `id`.
        fn is_tracked(&self, id: Uuid) -> bool {
            self.catalog.files().locks().contains(id)
        }

        /// Write the `personal` vault file to `path` after `edit`. `edit`
        /// receives the `vault` object inside the file envelope.
        fn write_copy(&self, path: &Path, edit: impl FnOnce(&mut Value)) {
            let data = fs::read_to_string(self.vault_path("personal")).unwrap();
            let mut file: Value = serde_json::from_str(&data).unwrap();
            edit(&mut file["vault"]);
            let data = serde_json::to_string_pretty(&file).unwrap();
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, data).unwrap();
        }

        /// Write the `personal` vault object to `{key}.json` without its
        /// envelope, as a format 1 file is.
        fn write_without_envelope(&self, key: &str) {
            let data = fs::read_to_string(self.vault_path("personal")).unwrap();
            let file: Value = serde_json::from_str(&data).unwrap();
            let data = serde_json::to_string_pretty(&file["vault"]).unwrap();
            fs::write(self.vault_path(key), data).unwrap();
        }

        /// Write the `personal` vault file to `{key}.json` after `edit`.
        fn write_edited(&self, key: &str, edit: impl FnOnce(&mut Value)) {
            self.write_copy(&self.vault_path(key), edit);
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
    fn format1_file_is_not_listed() {
        let fx = Fixture::new();
        fx.write_without_envelope("legacy");

        let scan = fx.catalog.scan();

        assert_eq!(scan.vaults.into_keys().collect::<Vec<_>>(), ["personal"]);
        assert!(scan.duplicates.is_empty(), "{:?}", scan.duplicates);
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
        assert_eq!(
            scan.vaults.into_keys().collect::<Vec<_>>(),
            ["alias", "personal"]
        );
        assert!(fx.is_tracked(fx.personal_id()));
    }
}
