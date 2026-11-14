//! File credentials in a synced vault: the upload of each blob before the
//! state file that references it, the fetch of a missing blob on read, the
//! blob status of the sync report, and the sync of file records between
//! Macs.

use std::sync::Arc;

use super::load::Fixture;
use super::publish::{decode, last_publish, published};
use super::transport::FakeTransport;
use super::txn::{saved, saved_vault, synced};
use crate::audit::SubjectIds;
use crate::secrets::vaults::files::record::FileRecord;
use crate::secrets::vaults::files::store::BlobStore;
use crate::secrets::vaults::files::{self, FileHash, FileInput};
use crate::secrets::vaults::format::encrypted_vault::EncryptedVault;
use crate::secrets::vaults::format::signing::TestSigner;
use crate::secrets::vaults::model::Vault;
use crate::secrets::vaults::storage::txn::{Committed, StagedCopy, Target, Unlock, VaultWriter};
use crate::secrets::vaults::sync::blobs;
use crate::secrets::vaults::sync::report::{BlobStatus, SyncReport, UnreferencedBlobs};
use crate::secrets::vaults::sync::state_file::{StateFile, StateHash};
use crate::secrets::vaults::sync::status::{PausedCause, SyncStatus};
use crate::secrets::vaults::{Error, VaultHandle};

mod model;
mod publish;
mod replicas;

/// File input named `{cred_key}.bin` with `contents`.
fn input<'a>(cred_key: &str, contents: &'a [u8]) -> FileInput<&'a [u8]> {
    FileInput {
        name: format!("{cred_key}.bin"),
        mime: None,
        contents,
    }
}

/// Add file credential `cred_key` holding `contents` to item `item` of the
/// vault `vh`, through `writer`.
fn add_file(
    writer: &VaultWriter,
    vh: &VaultHandle,
    cred_key: &str,
    contents: &[u8],
) -> Result<Committed<SubjectIds>, Error> {
    let key = || vh.unlocked_key().unwrap();
    files::add_file(
        writer,
        &Target::of(vh),
        Unlock::Test(&key),
        "item",
        cred_key,
        "Doc",
        input(cred_key, contents),
    )
}

/// Replace the file of credential `cred_key` of item `item` of the vault
/// `vh` with `contents`, through `writer`.
fn replace_file(
    writer: &VaultWriter,
    vh: &VaultHandle,
    cred_key: &str,
    contents: &[u8],
) -> Result<Committed<SubjectIds>, Error> {
    let key = || vh.unlocked_key().unwrap();
    files::replace_file(
        writer,
        &Target::of(vh),
        Unlock::Test(&key),
        "item",
        cred_key,
        input(cred_key, contents),
    )
}

/// Move file credential `cred_key` of item `item` of the vault `vh` to the
/// trash, through `writer`.
fn trash_file(writer: &VaultWriter, vh: &VaultHandle, cred_key: &str) -> Committed<()> {
    let key = || vh.unlocked_key().unwrap();
    files::delete_file(
        writer,
        &Target::of(vh),
        Unlock::Test(&key),
        "item",
        cred_key,
    )
    .unwrap()
}

/// Vault `vh` as saved, unlocked with its file key. Runs no transaction.
fn on_disk(vh: &VaultHandle) -> VaultHandle {
    let file = EncryptedVault::load(&vh.path, &TestSigner::device()).unwrap();
    let vault = Vault::from_unlocked_key(&vh.unlocked_key().unwrap(), file).unwrap();
    VaultHandle::unlocked(vh.path.clone(), vault)
}

/// Contents of file credential `cred_key` of item `item` of the vault `vh`
/// as saved, read through `writer`.
fn read_file(writer: &VaultWriter, vh: &VaultHandle, cred_key: &str) -> Result<Vec<u8>, Error> {
    let vh = on_disk(vh);
    let mut out = Vec::new();
    files::read_file(writer, &vh, "item", cred_key, &mut out)?;
    Ok(out)
}

/// Record of file credential `cred_key` of item `item` of the vault `vh`.
fn record(vh: &VaultHandle, cred_key: &str) -> FileRecord {
    files::read_record(vh, "item", cred_key).unwrap()
}

/// Local blob store of the vault `vh`.
fn store(vh: &VaultHandle) -> BlobStore {
    BlobStore::of(&vh.path, vh.vault_id().unwrap())
}

/// Sync report of the vault `vh`, read through `writer`.
fn report(writer: &VaultWriter, vh: &VaultHandle) -> SyncReport {
    let key = || vh.unlocked_key().unwrap();
    SyncReport::read(writer, &Target::of(vh), Unlock::Test(&key)).unwrap()
}

/// Blob status of a synced vault whose folder lists no unreferenced blob.
fn status(uploads_pending: usize, missing_locally: usize) -> BlobStatus {
    BlobStatus {
        uploads_pending,
        missing_locally,
        unreferenced: Some(UnreferencedBlobs::default()),
    }
}

/// Assert that the write log of `transport` holds one upload of `blob`,
/// written before the state file `hash` of vault `vault_id`.
fn assert_uploaded_before(
    transport: &FakeTransport,
    vault_id: uuid::Uuid,
    blob: FileHash,
    hash: StateHash,
) {
    let log = transport.write_log();
    let blob_name = format!("blobs/{blob}");
    let uploads: Vec<usize> = log
        .iter()
        .enumerate()
        .filter(|(_, name)| **name == blob_name)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(uploads.len(), 1, "{log:?}");
    let state_name = StateFile::name(vault_id, hash);
    let state = log.iter().position(|name| *name == state_name).unwrap();
    assert!(uploads[0] < state, "{log:?}");
}
