// MIGRATE_V1: delete this file with the other MIGRATE_V1 markers.
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::*;
use crate::secrets::vaults::storage::test_keys;

/// Plaintext of a metadata blob in a 0.2.0 vault.
#[derive(Serialize, Deserialize, Zeroize)]
struct LegacyMetadata {
    title: String,
    key: String,
}

impl LegacyMetadata {
    fn new(title: &str, key: &str) -> Self {
        Self {
            title: title.to_string(),
            key: key.to_string(),
        }
    }
}

/// Seconds after which a creation time is not the unset value.
const SET_CREATED_AT: i64 = 1_700_000_000;

impl Fixture {
    /// Write the `personal` vault, with item `item` and credential `token`
    /// of value "hunter2", to `path` as 0.2.0 wrote it. The file is the bare
    /// vault object. It has no key and no signature, and the metadata blobs
    /// hold a title and a key only.
    fn write_legacy(&self, path: &Path) {
        self.write_personal("hunter2");
        let cipher = self
            .read("personal")
            .unlocked_key()
            .unwrap()
            .cipher_for_test();
        let data = fs::read_to_string(self.vault_path("personal")).unwrap();
        let mut file: Value = serde_json::from_str(&data).unwrap();
        let mut vault = file["vault"].take();
        vault.as_object_mut().unwrap().remove("key");
        for (item_key, item) in vault["items"].as_object_mut().unwrap() {
            let item_id = ShortId::parse_uuid(item_key).unwrap();
            let metadata = LegacyMetadata::new("Item", "item");
            let blob = cipher.encrypt_item_metadata_as_for_test(item_id, &metadata);
            item["metadata"] = serde_json::to_value(&blob).unwrap();
            for (cred_key, cred) in item["credentials"].as_object_mut().unwrap() {
                let cred_id = ShortId::parse_uuid(cred_key).unwrap();
                let metadata = LegacyMetadata::new("Token", "token");
                let blob = cipher.encrypt_cred_metadata_as_for_test(item_id, cred_id, &metadata);
                cred["metadata"] = serde_json::to_value(&blob).unwrap();
            }
        }
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, serde_json::to_string_pretty(&vault).unwrap()).unwrap();
    }

    /// Write the legacy vault in place of the `personal` file.
    fn make_personal_legacy(&self) {
        self.write_legacy(&self.vault_path("personal"));
    }

    /// Delete the retained versions that building the legacy file left, as
    /// a Mac that only ran 0.2.0 has none.
    fn forget_versions(&self) {
        fs::remove_dir_all(self.dir.path().join("data").join("versions")).unwrap();
    }

    /// Write the legacy vault to `{name}.json` and delete the `personal`
    /// file, so the vault id is held once.
    fn move_personal_legacy(&self, name: &str) {
        self.write_legacy(&self.vault_path(name));
        fs::remove_file(self.vault_path("personal")).unwrap();
    }

    /// This fixture with the catalog over `keys`.
    fn with_keys(self, keys: Arc<dyn DeviceKeys>) -> Self {
        Self {
            dir: self.dir,
            catalog: self.catalog.with_keys(keys),
        }
    }

    /// Whether the file at `path` is a format 1 file.
    fn is_legacy_file(path: &Path) -> bool {
        let file: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        file.get("format").is_none()
    }

    /// Creation time of item `item` of vault `key`, as read.
    fn item_created_at(&self, key: &str) -> i64 {
        let vh = self.read(key);
        vh.get_item_overview("item").unwrap().unwrap().created_at
    }
}

#[test]
fn format1_file_upgraded_and_listed() {
    let fx = Fixture::new();
    fx.make_personal_legacy();
    let original = fs::read_to_string(fx.vault_path("personal")).unwrap();

    let vaults = fx.catalog.list();

    assert_eq!(vaults.into_keys().collect::<Vec<_>>(), ["personal"]);
    let signer = fx.catalog.signer().as_ref();
    let upgraded = EncryptedVault::load(&fx.vault_path("personal"), signer).unwrap();
    assert_eq!(upgraded.key, "personal");
    let backup = fx.catalog.vaults_dir().join("personal.json.v1");
    assert_eq!(fs::read_to_string(backup).unwrap(), original);
}

#[test]
fn upgraded_vault_keeps_secrets() {
    let fx = Fixture::new();
    fx.make_personal_legacy();

    let vh = fx.read("personal");

    let secret = vh.get_secret("item", "token").unwrap().unwrap();
    assert_eq!(secret.expose_secret(), "hunter2");
}

#[test]
fn upgraded_item_reads_creation_time_of_load() {
    let fx = Fixture::new();
    fx.make_personal_legacy();

    assert!(fx.item_created_at("personal") > SET_CREATED_AT);
}

#[test]
fn next_save_writes_creation_time() {
    let fx = Fixture::new();
    fx.make_personal_legacy();
    let vh = fx.read("personal");
    let cipher = vh.unlocked_key().unwrap().cipher_for_test();

    fx.catalog
        .files()
        .write_unlocked::<_, Error>(&vh, |vw| vw.add_item("other", "Other").map(|_| ()))
        .unwrap();

    let signer = fx.catalog.signer().as_ref();
    let saved = EncryptedVault::load(&fx.vault_path("personal"), signer).unwrap();
    assert_eq!(saved.items.len(), 2);
    for (item_id, item) in &saved.items {
        let metadata = cipher
            .decrypt_item_metadata(*item_id, &item.metadata)
            .unwrap();
        assert!(metadata.expose_secret().created_at > SET_CREATED_AT);
        for (cred_id, cred) in &item.credentials {
            let metadata = cipher
                .decrypt_cred_metadata(*item_id, *cred_id, &cred.metadata)
                .unwrap();
            assert!(metadata.expose_secret().created_at > SET_CREATED_AT);
        }
    }
}

#[test]
fn file_stem_normalized_as_vault_key() {
    let fx = Fixture::new();
    fx.move_personal_legacy("Work Vault");

    let vaults = fx.catalog.list();

    assert_eq!(vaults.into_keys().collect::<Vec<_>>(), ["work-vault"]);
}

#[test]
fn file_with_invalid_stem_left_as_it_was() {
    let fx = Fixture::new();
    fx.move_personal_legacy("x");
    let original = fs::read_to_string(fx.vault_path("x")).unwrap();

    let vaults = fx.catalog.list();

    assert!(vaults.is_empty(), "{:?}", vaults.keys());
    assert_eq!(fs::read_to_string(fx.vault_path("x")).unwrap(), original);
    assert!(!fx.catalog.vaults_dir().join("x.json.v1").exists());
}

#[test]
fn second_scan_leaves_upgraded_file_as_it_was() {
    let fx = Fixture::new();
    fx.make_personal_legacy();
    fx.catalog.list();
    let upgraded = fs::read_to_string(fx.vault_path("personal")).unwrap();

    fx.catalog.list();

    assert_eq!(
        fs::read_to_string(fx.vault_path("personal")).unwrap(),
        upgraded
    );
}

#[test]
fn external_format1_file_upgraded_with_stem_as_key() {
    let fx = Fixture::with_external(&["outside"]);
    fx.write_legacy(&fx.external_path("outside"));
    fs::remove_file(fx.vault_path("personal")).unwrap();

    let vaults = fx.catalog.list();

    assert_eq!(vaults.into_keys().collect::<Vec<_>>(), ["outside"]);
    assert!(!Fixture::is_legacy_file(&fx.external_path("outside")));
}

#[test]
fn signing_key_created_for_format1_files() {
    let keys = test_keys::keys(KeyProbe::Present, KeyProbe::Missing);
    let fx = Fixture::new().with_keys(keys.clone());
    fx.make_personal_legacy();
    fx.forget_versions();

    assert_eq!(fx.catalog.key_state(), KeyState::Normal);

    assert_eq!(keys.created(), 1);
    assert!(!Fixture::is_legacy_file(&fx.vault_path("personal")));
}

#[test]
fn signing_key_not_created_if_versions_exist() {
    let keys = test_keys::keys(KeyProbe::Present, KeyProbe::Missing);
    let fx = Fixture::new().with_keys(keys.clone());
    fx.write_personal("one");
    fx.write_personal("two");
    fx.make_personal_legacy();

    assert_eq!(fx.catalog.key_state(), KeyState::SigningKeyLost);

    assert_eq!(keys.created(), 0);
    assert!(Fixture::is_legacy_file(&fx.vault_path("personal")));
}

#[test]
fn signing_key_not_created_next_to_signed_vault_file() {
    let keys = test_keys::keys(KeyProbe::Present, KeyProbe::Missing);
    let fx = Fixture::new().with_keys(keys.clone());
    fx.make_personal_legacy();
    fx.write_edited("other", other_vault("other"));

    assert_eq!(fx.catalog.key_state(), KeyState::SigningKeyLost);

    assert_eq!(keys.created(), 0);
    assert!(Fixture::is_legacy_file(&fx.vault_path("personal")));
}

#[test]
fn signing_key_not_created_without_encryption_key() {
    let keys = test_keys::keys(KeyProbe::Missing, KeyProbe::Missing);
    let fx = Fixture::new().with_keys(keys.clone());
    fx.make_personal_legacy();

    assert_eq!(fx.catalog.key_state(), KeyState::NewHardware);

    assert_eq!(keys.created(), 0);
    assert!(Fixture::is_legacy_file(&fx.vault_path("personal")));
}

#[test]
fn present_signing_key_not_created_again() {
    let keys = test_keys::keys(KeyProbe::Present, KeyProbe::Present);
    let fx = Fixture::new().with_keys(keys.clone());
    fx.make_personal_legacy();

    assert_eq!(fx.catalog.key_state(), KeyState::Normal);

    assert_eq!(keys.created(), 0);
    assert!(!Fixture::is_legacy_file(&fx.vault_path("personal")));
}
