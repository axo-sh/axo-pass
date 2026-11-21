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

mod collision;
mod ids;
mod import;
mod keys;
mod legacy_v1; // MIGRATE_V1

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
