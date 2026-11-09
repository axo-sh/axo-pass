use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde_json::{Value, json};
use tempfile::TempDir;
use uuid::Uuid;

use super::{
    ExportFile, assert_live_blobs_decrypt, export_cipher, file_key_of, filled_vault, import_as,
    plain_wrap,
};
use crate::audit::test_support::test_dir;
use crate::secrets::vaults::bundle::{
    ImportAction, ImportSelection, ImportableBundle, PreparedVault,
};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::encrypted_vault::EncryptedVault;
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::format::vault_cipher::VaultCipher;
use crate::secrets::vaults::model::Vault;
use crate::secrets::vaults::model::fields::FieldKind;
use crate::secrets::vaults::storage::handle::VaultHandle;
use crate::secrets::vaults::storage::txn::VaultWriter;

/// Writer and vaults directory of an import, in a temp directory.
struct ImportTarget {
    dir: TempDir,
    files: VaultWriter,
    vaults_dir: PathBuf,
}

impl ImportTarget {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let files = VaultWriter::isolated(dir.path().join("data"));
        let vaults_dir = dir.path().join("vaults");
        Self {
            dir,
            files,
            vaults_dir,
        }
    }

    /// Import every vault of `bundle` in `ids` as `imported-{n}`, with the
    /// file key wrapper [`plain_wrap`].
    fn import(&self, bundle: ImportableBundle, ids: &[Uuid]) -> Result<Vec<VaultHandle>, Error> {
        let selection = ids
            .iter()
            .enumerate()
            .map(|(n, id)| (*id, import_as(&format!("imported-{n}"))))
            .collect();
        bundle.import_with(&selection, &self.vaults_dir, &self.files, || {
            Ok(Box::new(plain_wrap))
        })
    }

    /// Verify the vault file at `path` under the writer signer. Returns the
    /// cipher of the raw file key the file holds, which [`plain_wrap`] stored
    /// as is.
    fn load(&self, path: &Path) -> (VaultCipher, EncryptedVault) {
        let verified = EncryptedVault::load(path, self.files.signer().as_ref()).unwrap();
        let cipher = VaultCipher::new_with_bytes(verified.file_key.as_bytes(), verified.id);
        (cipher, verified.into_inner())
    }

    /// Names of the files in the vaults directory, temp files included.
    fn vault_dir_names(&self) -> Vec<String> {
        let Ok(entries) = fs::read_dir(&self.vaults_dir) else {
            return Vec::new();
        };
        entries
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }
}

/// Opened bundle vault built from `encrypted`, which `vault` encrypted.
fn prepared_from(vault: &Vault, encrypted: EncryptedVault) -> PreparedVault {
    PreparedVault {
        id: encrypted.id,
        name: encrypted.name,
        default_key: None,
        raw_file_key: SecretBox::new(Box::new(file_key_of(vault))),
        metadata: encrypted.metadata,
        items: encrypted.items,
    }
}

#[test]
fn imported_file_key_differs_from_export_file_key() {
    let _audit_dir = test_dir();
    let vault = filled_vault();
    let export = ExportFile::new(&vault, true);
    let export_key = export.open().raw_file_key.expose_secret().clone();
    let target = ImportTarget::new();

    let imported = target.import(export.open_bundle(), &[vault.id()]).unwrap();

    let (cipher, _) = target.load(&imported[0].path);
    assert_ne!(cipher.key_bytes_for_test(), export_key);
    assert_ne!(cipher.key_bytes_for_test(), file_key_of(&vault));
}

#[test]
fn two_imports_of_one_export_get_different_file_keys() {
    let _audit_dir = test_dir();
    let vault = filled_vault();
    let export = ExportFile::new(&vault, true);

    let keys: Vec<Vec<u8>> = (0..2)
        .map(|_| {
            let target = ImportTarget::new();
            let imported = target.import(export.open_bundle(), &[vault.id()]).unwrap();
            target.load(&imported[0].path).0.key_bytes_for_test()
        })
        .collect();

    assert_ne!(keys[0], keys[1]);
}

#[test]
fn imported_vault_holds_values_and_history_of_export() {
    let _audit_dir = test_dir();
    let vault = filled_vault();
    let export = ExportFile::new(&vault, true);
    let target = ImportTarget::new();

    let imported = target.import(export.open_bundle(), &[vault.id()]).unwrap();

    let (cipher, encrypted) = target.load(&imported[0].path);
    assert_eq!(encrypted.id, vault.id());
    assert_eq!(encrypted.key, "imported-0");
    assert_eq!(encrypted.generation, 0);
    assert_eq!(encrypted.replica_id, None);
    let loaded = Vault::from_encrypted_with_cipher(cipher, encrypted).unwrap();
    loaded.assert_live_filled_for_test();
    assert!(loaded.list_deleted("kept").unwrap().is_empty());
    assert!(loaded.list_deleted_items().is_empty());
}

#[test]
fn imported_blobs_fail_to_decrypt_under_export_file_key() {
    let _audit_dir = test_dir();
    let vault = filled_vault();
    let export = ExportFile::new(&vault, true);
    let export_cipher = export_cipher(&export.open());
    let target = ImportTarget::new();

    let imported = target.import(export.open_bundle(), &[vault.id()]).unwrap();

    let (cipher, encrypted) = target.load(&imported[0].path);
    assert_live_blobs_decrypt(&cipher, &encrypted, true);
    assert_live_blobs_decrypt(&export_cipher, &encrypted, false);
}

/// Credential metadata plaintext read as a JSON object.
#[derive(serde::Serialize, serde::Deserialize, zeroize::Zeroize)]
struct LooseMetadata {
    #[serde(flatten)]
    #[zeroize(skip)]
    fields: BTreeMap<String, Value>,
}

#[test]
fn stale_last_used_at_fails_import() {
    let _audit_dir = test_dir();
    let mut vault = Vault::new_for_test();
    vault.add_or_update_item("site", "Site").unwrap();
    vault
        .add_or_update_item_credential(
            "site",
            "password",
            "Password",
            FieldKind::default(),
            SecretString::from("secret".to_string()),
        )
        .unwrap();
    let item_id = vault.get_item("site").unwrap().id;
    let cred_id = vault.get_item_credential("site", "password").unwrap().id;
    let stale = LooseMetadata {
        fields: BTreeMap::from([
            ("title".to_string(), json!("Password")),
            ("key".to_string(), json!("password")),
            ("last_used_at".to_string(), json!(1_700_000_000)),
        ]),
    };
    let source_cipher = vault.unlocked_key().cipher_for_test();
    let mut encrypted = vault.to_encrypted(false).unwrap();
    let credentials = &mut encrypted.items.get_mut(&item_id).unwrap().credentials;
    credentials.get_mut(&cred_id).unwrap().metadata =
        source_cipher.encrypt_cred_metadata_as_for_test(item_id, cred_id, &stale);
    let bundle = ImportableBundle {
        vaults: vec![prepared_from(&vault, encrypted)],
    };
    let target = ImportTarget::new();

    let result = target.import(bundle, &[vault.id()]);

    assert!(matches!(result, Err(Error::VaultSecretDecryptionError)));
    assert_eq!(target.vault_dir_names(), Vec::<String>::new());
}

#[test]
fn undecryptable_vault_fails_import() {
    let _audit_dir = test_dir();
    let intact = filled_vault();
    let mut broken = Vault::new_for_test();
    broken.add_or_update_item("site", "Site").unwrap();
    for cred in ["alpha", "beta"] {
        broken
            .add_or_update_item_credential(
                "site",
                cred,
                cred,
                FieldKind::default(),
                SecretString::from(cred.to_string()),
            )
            .unwrap();
    }
    // A value blob under the AAD of another credential fails to decrypt.
    let item_id = broken.get_item("site").unwrap().id;
    let mut encrypted = broken.to_encrypted(false).unwrap();
    let credentials = &mut encrypted.items.get_mut(&item_id).unwrap().credentials;
    let mut values = credentials.values_mut();
    let (a, b) = (values.next().unwrap(), values.next().unwrap());
    std::mem::swap(&mut a.value, &mut b.value);
    let bundle = ImportableBundle {
        vaults: vec![
            prepared_from(&intact, intact.to_encrypted(false).unwrap()),
            prepared_from(&broken, encrypted),
        ],
    };
    let target = ImportTarget::new();

    let result = target.import(bundle, &[intact.id(), broken.id()]);

    assert!(result.is_err());
    assert_eq!(target.vault_dir_names(), Vec::<String>::new());
}

#[test]
fn interrupted_import_leaves_no_vault_file() {
    let _audit_dir = test_dir();
    let target = ImportTarget::new();
    let mut ids = [Uuid::new_v4(), Uuid::new_v4()];
    ids.sort();
    // A vault file outside the vaults directory holds the second id, and the
    // writer tracks it there. The second create then fails after the first
    // vault is written, since vaults are written in id order.
    let elsewhere = target.dir.path().join("elsewhere");
    let selection = BTreeMap::from([(ids[1], import_as("elsewhere"))]);
    let other = ImportableBundle::for_test(&[ids[1]])
        .import_with(&selection, &elsewhere, &target.files, || {
            Ok(Box::new(plain_wrap))
        })
        .unwrap();
    let other_contents = fs::read_to_string(&other[0].path).unwrap();

    let result = target.import(ImportableBundle::for_test(&ids), &ids);

    assert!(
        matches!(result, Err(Error::DuplicateVaultId(_))),
        "{:?}",
        result.err()
    );
    assert_eq!(target.vault_dir_names(), Vec::<String>::new());
    assert_eq!(fs::read_to_string(&other[0].path).unwrap(), other_contents);
}

#[test]
fn copy_keeps_name_and_passkeys_under_new_id_and_file_key() {
    let _audit_dir = test_dir();
    let mut vault = filled_vault();
    vault.name = Some("Work".to_string());
    let export = ExportFile::new(&vault, true);
    let export_key = export.open().raw_file_key.expose_secret().clone();
    let target = ImportTarget::new();
    let selection =
        BTreeMap::from([(vault.id(), ImportSelection::new("copy", ImportAction::Copy))]);

    let imported = export
        .open_bundle()
        .import_with(&selection, &target.vaults_dir, &target.files, || {
            Ok(Box::new(plain_wrap))
        })
        .unwrap();

    let (cipher, encrypted) = target.load(&imported[0].path);
    assert_ne!(encrypted.id, vault.id());
    assert_eq!(
        target.vault_dir_names(),
        [format!("{}.json", ShortId::encode_uuid(encrypted.id))]
    );
    assert_eq!(encrypted.key, "copy");
    assert_eq!(encrypted.name.as_deref(), Some("Work"));
    assert_eq!(encrypted.generation, 0);
    assert_eq!(encrypted.replica_id, None);
    assert_ne!(cipher.key_bytes_for_test(), export_key);
    assert_ne!(cipher.key_bytes_for_test(), file_key_of(&vault));
    let loaded = Vault::from_encrypted_with_cipher(cipher, encrypted).unwrap();
    loaded.assert_live_filled_for_test();
    let passkey = loaded
        .get_item_credential_secret("kept", "passkey")
        .unwrap()
        .unwrap();
    assert_eq!(passkey.expose_secret(), Vault::PASSKEY_VALUE_FOR_TEST);
}
