use std::fs;
use std::path::{Path, PathBuf};

use secrecy::{ExposeSecret, SecretString};
use tempfile::TempDir;
use uuid::Uuid;

use super::store::BlobStore;
use super::*;
use crate::secrets::vaults::format::encrypted_vault::EncryptedVault;
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::model::Vault;

mod store;
mod stream;

/// Vault `personal` with item `item`, written to a temp directory, with the
/// retained versions and lock files under `data`.
struct Fixture {
    _dir: TempDir,
    writer: VaultWriter,
    /// The vault as created, still unlocked. Its file key opens the file.
    vault: VaultHandle,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let writer = VaultWriter::isolated(dir.path().join("data"));
        let vault = VaultHandle::new_for_test_at(dir.path().join("vaults").join("personal.json"));
        writer.create(&vault).unwrap();
        let fx = Self {
            _dir: dir,
            writer,
            vault,
        };
        fx.write(|vh| vh.add_item("item", "Item").map(|_| ()))
            .unwrap();
        fx
    }

    fn id(&self) -> Uuid {
        self.vault.vault_id().unwrap()
    }

    fn target(&self) -> Target {
        Target::of(&self.vault)
    }

    fn unlock(&self) -> Unlock<'_> {
        Unlock::Unlocked(&self.vault)
    }

    fn store(&self) -> BlobStore {
        self.writer.blob_store(self.id())
    }

    /// Blobs in the store.
    fn blobs(&self) -> Vec<FileHash> {
        self.store().list().unwrap()
    }

    /// Names of every entry of the store directory, temp files included.
    fn store_entries(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.store().dir())
            .into_iter()
            .flatten()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        names
    }

    /// Run `f` in a transaction on the vault.
    fn write<R>(
        &self,
        f: impl FnOnce(&mut VaultHandle) -> Result<R, Error>,
    ) -> Result<Committed<R>, Error> {
        self.writer.write(&self.target(), self.unlock(), f)
    }

    /// Save a change that touches no file credential, which runs garbage
    /// collection.
    fn touch(&self) {
        let committed = self
            .write(|vh| {
                let value = Uuid::new_v4().to_string();
                vh.add_secret(
                    "item",
                    "touch",
                    "Touch",
                    FieldKind::default(),
                    SecretString::from(value),
                )
            })
            .unwrap();
        assert!(committed.changed);
    }

    fn add(&self, cred_key: &str, contents: &[u8]) -> Result<Committed<SubjectIds>, Error> {
        add_file(
            &self.writer,
            &self.target(),
            self.unlock(),
            "item",
            cred_key,
            "Attachment",
            input(cred_key, contents),
        )
    }

    fn replace(&self, cred_key: &str, contents: &[u8]) -> Result<Committed<SubjectIds>, Error> {
        replace_file(
            &self.writer,
            &self.target(),
            self.unlock(),
            "item",
            cred_key,
            input(cred_key, contents),
        )
    }

    /// The vault as it is on disk now.
    fn on_disk(&self) -> VaultHandle {
        let contents = fs::read_to_string(&self.vault.path).unwrap();
        let enc_vault = EncryptedVault::parse(&contents, self.writer.signer().as_ref()).unwrap();
        let vault =
            Vault::from_unlocked_key(&self.vault.unlocked_key().unwrap(), enc_vault).unwrap();
        VaultHandle::unlocked(self.vault.path.clone(), vault)
    }

    /// Contents of the file credential `cred_key` of the vault on disk.
    fn read(&self, cred_key: &str) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        read_file(&self.writer, &self.on_disk(), "item", cred_key, &mut out)?;
        Ok(out)
    }

    /// Record of the file credential `cred_key` of the vault on disk.
    fn record(&self, cred_key: &str) -> FileRecord {
        read_record(&self.on_disk(), "item", cred_key).unwrap()
    }

    /// Assert that every blob named in the vault on disk is in the store.
    fn assert_no_missing_blob(&self) {
        let vh = self.on_disk();
        let named = vh.get_unlocked_vault().unwrap().file_blobs().unwrap();
        for blob in named {
            assert!(self.store().path(&blob).exists(), "{blob} is missing");
        }
    }

    /// Directory of the retained versions.
    fn versions_dir(&self) -> PathBuf {
        let id = ShortId::encode_uuid(self.id());
        self.writer.root().join("versions").join(id)
    }

    fn erase_versions(&self) {
        self.writer
            .erase_versions(self.id(), &self.vault.path)
            .unwrap();
    }
}

fn input<'a>(name: &str, contents: &'a [u8]) -> FileInput<&'a [u8]> {
    FileInput {
        name: format!("{name}.bin"),
        mime: Some("application/octet-stream".to_string()),
        contents,
    }
}

/// Bytes of `len` that differ from chunk to chunk.
fn contents(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i % 251) as u8 ^ (i / 65536) as u8)
        .collect()
}

/// Path of the temp file of a save of the vault file at `path`.
fn save_temp_path(path: &Path) -> PathBuf {
    let name = path.file_name().unwrap().to_string_lossy();
    path.with_file_name(format!(".{name}.tmp"))
}

#[test]
fn summary_reads_record_and_refuses_other_values() {
    let record = FileRecord {
        blob: FileHash([1; 32]),
        key: record::FileKey::generate(),
        sha256: FileHash([2; 32]),
        size: 3,
        name: "a.txt".to_string(),
        mime: None,
    };
    let value = record.encode().unwrap();
    let summary = summary(value.expose_secret()).unwrap();
    assert_eq!(summary.name, "a.txt");
    assert_eq!(summary.size, 3);
    assert_eq!(summary.sha256, FileHash([2; 32]));
    assert_eq!(super::summary("hunter2"), None);
}
