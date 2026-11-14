//! File credentials in export and import: the blobs of live files and of
//! history in the bundle, the refusal of a damaged blob, a bundle that lacks
//! a blob, and the refusal of a copy.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use secrecy::ExposeSecret;
use serde_json::Value;
use tempfile::TempDir;

use super::import::ImportTarget;
use super::plain_wrap;
use crate::audit::test_support::test_dir;
use crate::secrets::vaults::bundle::{
    ExportMode, ExportReport, ImportAction, ImportIdentity, ImportSelection, ImportableBundle,
};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::files::record::FileRecord;
use crate::secrets::vaults::files::store::BlobStore;
use crate::secrets::vaults::files::{self, FileHash, FileInput};
use crate::secrets::vaults::format::encrypted_vault::EncryptedVault;
use crate::secrets::vaults::model::Vault;
use crate::secrets::vaults::storage::handle::{VaultHandle, export_bundle};
use crate::secrets::vaults::storage::txn::{Target, Unlock, VaultWriter};

const KEEP: &[u8] = b"kept file contents";
const FIRST: &[u8] = b"first version";
const SECOND: &[u8] = b"second version";
const TRASHED: &[u8] = b"trashed file contents";

/// Vault `personal` with item `item`, in a temp directory.
struct Source {
    dir: TempDir,
    writer: VaultWriter,
    vault: VaultHandle,
}

impl Source {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let writer = VaultWriter::isolated(dir.path().join("data"));
        let vault = VaultHandle::new_for_test_at(dir.path().join("vaults").join("personal.json"));
        writer.create(&vault).unwrap();
        let source = Self { dir, writer, vault };
        source
            .writer
            .write(&Target::of(&source.vault), source.unlock(), |vh| {
                vh.add_item("item", "Item").map(|_| ())
            })
            .unwrap();
        source
    }

    /// Vault with file `keep`, file `swap` replaced once, and file `gone` in
    /// the trash.
    fn populated() -> Self {
        let source = Self::new();
        source.add("keep", KEEP);
        source.add("swap", FIRST);
        source.replace("swap", SECOND);
        source.add("gone", TRASHED);
        source.delete("gone");
        source
    }

    fn unlock(&self) -> Unlock<'_> {
        Unlock::Unlocked(&self.vault)
    }

    fn id(&self) -> uuid::Uuid {
        self.vault.vault_id().unwrap()
    }

    fn store(&self) -> BlobStore {
        BlobStore::of(&self.vault.path, self.id())
    }

    fn add(&self, cred_key: &str, contents: &[u8]) {
        files::add_file(
            &self.writer,
            &Target::of(&self.vault),
            self.unlock(),
            "item",
            cred_key,
            "Attachment",
            input(cred_key, contents),
        )
        .unwrap();
    }

    fn replace(&self, cred_key: &str, contents: &[u8]) {
        files::replace_file(
            &self.writer,
            &Target::of(&self.vault),
            self.unlock(),
            "item",
            cred_key,
            input(cred_key, contents),
        )
        .unwrap();
    }

    fn delete(&self, cred_key: &str) {
        files::delete_file(
            &self.writer,
            &Target::of(&self.vault),
            self.unlock(),
            "item",
            cred_key,
        )
        .unwrap();
    }

    /// The vault as it is on disk now.
    fn on_disk(&self) -> VaultHandle {
        let contents = fs::read_to_string(&self.vault.path).unwrap();
        let enc_vault = EncryptedVault::parse(&contents, self.writer.signer().as_ref()).unwrap();
        let vault =
            Vault::from_unlocked_key(&self.vault.unlocked_key().unwrap(), enc_vault).unwrap();
        VaultHandle::unlocked(self.vault.path.clone(), vault)
    }

    /// Blob of the live record of file `cred_key`.
    fn blob(&self, cred_key: &str) -> FileHash {
        files::read_record(&self.on_disk(), "item", cred_key)
            .unwrap()
            .blob
    }

    /// Export the vault as it is on disk to a bundle.
    fn export(&self) -> Exported {
        let identity = age::x25519::Identity::generate();
        let path = self.dir.path().join("export.axovault");
        let mode = ExportMode::Recipient(identity.to_public().to_string());
        let report =
            export_bundle(&[&self.on_disk()], &path, mode, true, &self.writer, |_| {}).unwrap();
        Exported {
            path,
            identity,
            report,
        }
    }
}

/// Bundle file of an export.
struct Exported {
    path: PathBuf,
    identity: age::x25519::Identity,
    report: ExportReport,
}

impl Exported {
    fn open(&self) -> Result<ImportableBundle, Error> {
        ImportableBundle::open(&self.path, ImportIdentity::Identity(self.identity.clone()))
    }

    /// Bundle file as JSON.
    fn json(&self) -> Value {
        serde_json::from_str(&fs::read_to_string(&self.path).unwrap()).unwrap()
    }

    /// Blob names of the first vault of the bundle file.
    fn blob_names(&self) -> BTreeSet<FileHash> {
        let json = self.json();
        let blobs = json["vaults"][0]["blobs"].as_object();
        blobs
            .into_iter()
            .flatten()
            .map(|(name, _)| FileHash::parse(name).unwrap())
            .collect()
    }
}

fn input<'a>(name: &str, contents: &'a [u8]) -> FileInput<&'a [u8]> {
    FileInput {
        name: format!("{name}.bin"),
        mime: None,
        contents,
    }
}

/// Vault imported by `target` at `path`, unlocked with the file key the
/// plain wrapper stored.
fn imported(target: &ImportTarget, path: &std::path::Path) -> VaultHandle {
    let (cipher, enc_vault) = target.load(path);
    let vault = Vault::from_encrypted_with_cipher(cipher, enc_vault).unwrap();
    VaultHandle::unlocked(path.to_path_buf(), vault)
}

/// Contents of file `cred_key` of `vh`, read through the writer of `target`.
fn read(target: &ImportTarget, vh: &VaultHandle, cred_key: &str) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    files::read_file(&target.files, vh, "item", cred_key, &mut out)?;
    Ok(out)
}

/// Contents of the older file of credential `cred_key` of `vh`, from its
/// history record.
fn read_replaced(vh: &VaultHandle, cred_key: &str) -> Vec<u8> {
    let vault = vh.get_unlocked_vault().unwrap();
    let entries = vault.list_history("item", cred_key).unwrap();
    assert_eq!(entries.len(), 1);
    let value = vault
        .get_history_value("item", cred_key, entries[0].id)
        .unwrap();
    let record = FileRecord::decode(value.expose_secret()).unwrap();
    let id = vh.vault_id().unwrap();
    let mut out = Vec::new();
    BlobStore::of(&vh.path, id)
        .read(&record, id, &mut out)
        .unwrap();
    out
}

#[test]
fn round_trip_excludes_trashed_file() {
    let _audit = test_dir();
    let source = Source::populated();
    let trashed_blob = source.blob_in_trash();
    let stray = FileHash::of(b"stray");
    source.store().put(&stray, b"stray").unwrap();
    let export = source.export();
    assert_eq!(export.report, ExportReport::default());

    // The bundle holds the blobs of the live files and of the history, and
    // neither the trashed file nor the unreferenced local blob.
    let names = export.blob_names();
    assert_eq!(names.len(), 3);
    assert!(names.contains(&source.blob("keep")));
    assert!(names.contains(&source.blob("swap")));
    assert!(!names.contains(&trashed_blob));
    assert!(!names.contains(&stray));
    // Each blob is stored as the local store holds it.
    let json = export.json();
    for (name, bytes) in json["vaults"][0]["blobs"].as_object().unwrap() {
        let bytes = B64.decode(bytes.as_str().unwrap()).unwrap();
        let name = FileHash::parse(name).unwrap();
        assert_eq!(source.store().read_bytes(&name).unwrap(), bytes);
    }

    let bundle = export.open().unwrap();
    let info = &bundle.vaults()[0];
    assert_eq!((info.files, info.missing_files), (3, 0));
    let target = ImportTarget::new();
    let handles = target.import(bundle, &[source.id()]).unwrap();

    let vh = imported(&target, &handles[0].path);
    assert_eq!(read(&target, &vh, "keep").unwrap(), KEEP);
    assert_eq!(read(&target, &vh, "swap").unwrap(), SECOND);
    assert_eq!(read_replaced(&vh, "swap"), FIRST);
    // A trashed file is not exported, as no trashed entry is.
    assert!(vh.get_secret_overview("item", "gone").unwrap().is_none());
    let store = BlobStore::of(&vh.path, vh.vault_id().unwrap());
    assert_eq!(
        store.list().unwrap().into_iter().collect::<BTreeSet<_>>(),
        names
    );
}

#[test]
fn tampered_blob_is_refused_and_nothing_is_written() {
    let _audit = test_dir();
    let source = Source::populated();
    let export = source.export();
    let blob = source.blob("keep");
    let mut json = export.json();
    let entry = &mut json["vaults"][0]["blobs"][blob.to_string()];
    let mut bytes = B64.decode(entry.as_str().unwrap()).unwrap();
    bytes[0] ^= 1;
    *entry = Value::String(B64.encode(bytes));
    fs::write(&export.path, serde_json::to_string(&json).unwrap()).unwrap();

    let result = export.open();

    let Err(Error::FileBlobMismatch(name)) = result else {
        panic!("{:?}", result.err());
    };
    assert_eq!(name, blob.to_string());
    let target = ImportTarget::new();
    assert!(!target.vaults_dir.exists());
}

#[test]
fn unreferenced_bundle_blob_checked_not_imported() {
    let _audit = test_dir();
    let source = Source::populated();
    let export = source.export();
    let extra = FileHash::of(b"extra");
    let mut json = export.json();
    json["vaults"][0]["blobs"][extra.to_string()] = Value::String(B64.encode(b"extra"));
    fs::write(&export.path, serde_json::to_string(&json).unwrap()).unwrap();

    let target = ImportTarget::new();
    let handles = target
        .import(export.open().unwrap(), &[source.id()])
        .unwrap();

    let store = BlobStore::of(&handles[0].path, source.id());
    assert!(!store.contains(&extra));
    assert_eq!(store.list().unwrap().len(), 3);

    // The same blob under a name that is not its hash is refused.
    json["vaults"][0]["blobs"][extra.to_string()] = Value::String(B64.encode(b"other"));
    fs::write(&export.path, serde_json::to_string(&json).unwrap()).unwrap();
    assert!(matches!(export.open(), Err(Error::FileBlobMismatch(_))));
}

#[test]
fn bundle_missing_blob_imports_record_and_reports() {
    let _audit = test_dir();
    let source = Source::populated();
    let lost = source.blob("keep");
    assert!(source.store().delete(&lost).unwrap());

    let export = source.export();

    let [missing] = &export.report.missing_blobs[..] else {
        panic!("{:?}", export.report);
    };
    assert_eq!((missing.vault_id, missing.blob), (source.id(), lost));
    assert!(!export.blob_names().contains(&lost));
    let bundle = export.open().unwrap();
    let info = &bundle.vaults()[0];
    assert_eq!((info.files, info.missing_files), (3, 1));
    let target = ImportTarget::new();
    let handles = target.import(bundle, &[source.id()]).unwrap();

    let vh = imported(&target, &handles[0].path);
    let result = read(&target, &vh, "keep");
    assert!(matches!(result, Err(Error::FileMissing(_))), "{result:?}");
    assert_eq!(read(&target, &vh, "swap").unwrap(), SECOND);
    assert_eq!(read_replaced(&vh, "swap"), FIRST);
    // The record is kept, so a later restore of the blob makes it readable.
    let named = vh.get_unlocked_vault().unwrap().file_blobs().unwrap();
    assert!(named.contains(&lost));
}

#[test]
fn file_vault_copy_refused() {
    let _audit = test_dir();
    let source = Source::populated();
    let export = source.export();
    let target = ImportTarget::new();
    let selection = BTreeMap::from([(
        source.id(),
        ImportSelection::new("copy", ImportAction::Copy),
    )]);

    let result =
        export
            .open()
            .unwrap()
            .import_with(&selection, &target.vaults_dir, &target.files, || {
                Ok(Box::new(plain_wrap))
            });

    let Err(Error::VaultImportError(message)) = result else {
        panic!("{:?}", result.err());
    };
    assert!(message.contains("3 files"), "{message}");
    assert!(!target.vaults_dir.exists());
    assert!(!target.dir.path().join("vaults").exists());
}

#[test]
fn vault_without_files_exports_no_blob_field() {
    let _audit = test_dir();
    let source = Source::new();

    let export = source.export();

    assert!(export.json()["vaults"][0].get("blobs").is_none());
    let bundle = export.open().unwrap();
    assert_eq!(bundle.vaults()[0].files, 0);
}

impl Source {
    /// Blob of the trashed file `gone`, from the deleted entries of the vault
    /// on disk.
    fn blob_in_trash(&self) -> FileHash {
        let on_disk = self.on_disk();
        let vault = on_disk.get_unlocked_vault().unwrap();
        let deleted = vault.list_all_deleted();
        let [entry] = &deleted[..] else {
            panic!("{} deleted credentials", deleted.len());
        };
        let value = vault
            .get_deleted_credential_secret(entry.credential.item_id, entry.credential.credential.id)
            .unwrap();
        FileRecord::decode(value.expose_secret()).unwrap().blob
    }
}
