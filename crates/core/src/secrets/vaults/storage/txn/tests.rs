use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use secrecy::{ExposeSecret, SecretString};
use serde_json::value::RawValue;
use tempfile::TempDir;

use super::versions::{DAY_MS, HOUR_MS, kept_versions};
use super::*;
use crate::secrets::vaults::format::encrypted_vault::{VAULT_FORMAT, VaultFileKey};
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::format::vault_cipher::VaultCipher;
use crate::secrets::vaults::model::fields::FieldKind;

mod concurrency;
mod restore;
mod retention;
mod save;

/// A vault written to a temp directory, with its retained versions and lock
/// files in the same directory.
struct Fixture {
    dir: TempDir,
    files: VaultWriter,
    /// The vault as created, still unlocked. Its file key opens the file.
    vault: VaultHandle,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let files = VaultWriter::isolated(dir.path().join("data"));
        let vault = VaultHandle::new_for_test_at(dir.path().join("vaults").join("personal.json"));
        files.create(&vault).unwrap();
        Self { dir, files, vault }
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

    /// Add a credential `item/cred` with `value` in its own transaction.
    fn add(&self, target: &Target, cred: &str, value: &str) -> Committed<()> {
        self.files
            .write::<_, Error>(target, self.unlock(), |vw| add_credential(vw, cred, value))
            .unwrap()
    }

    /// The vault as it is on disk now, at `path`.
    fn read(&self, path: &Path) -> VaultHandle {
        let contents = fs::read_to_string(path).unwrap();
        let enc_vault = EncryptedVault::parse(&contents, self.files.signer().as_ref()).unwrap();
        let vault =
            Vault::from_unlocked_key(&self.vault.unlocked_key().unwrap(), enc_vault).unwrap();
        VaultHandle::unlocked(path.to_path_buf(), vault)
    }

    fn value(&self, path: &Path, cred: &str) -> Option<String> {
        self.read(path)
            .get_secret("item", cred)
            .unwrap()
            .map(|s| s.expose_secret().clone())
    }

    fn versions(&self) -> Vec<RetainedVersion> {
        self.files.list_versions(self.id()).unwrap()
    }
}

/// Add a credential `item/cred` with `value`, creating `item` if needed.
fn add_credential(vw: &mut VaultHandle, cred: &str, value: &str) -> Result<(), Error> {
    vw.add_item("item", "Item")?;
    vw.add_secret(
        "item",
        cred,
        cred,
        FieldKind::default(),
        SecretString::from(value.to_string()),
    )
}

fn version(ms: u64, seq: u64) -> RetainedVersion {
    RetainedVersion {
        name: format!("{ms}-{seq}.json"),
        saved_at_ms: ms,
        seq,
    }
}

/// Raw vault bytes of the vault file `contents`.
fn raw(contents: &str) -> String {
    EncryptedVault::raw_vault_json(contents)
        .unwrap()
        .to_string()
}

/// Replace the vault file at `path` with a copy signed by another key, which
/// is refused. Returns the refused contents.
fn refuse(path: &Path) -> String {
    let contents = fs::read_to_string(path).unwrap();
    let forged = EncryptedVault::sign_vault_json(raw(&contents), &TestSigner::random()).unwrap();
    fs::write(path, &forged).unwrap();
    forged
}
