//! File blobs of a synced vault in the synced folder.
//!
//! A file record syncs as the `SecretText` value of its credential. The blob
//! it names is uploaded to `blobs/` of the vault directory by the replica
//! that holds it, before any state file that references it is copied
//! (`sync/publish.rs`). A blob is copied as it is, after its hash is checked.
//! Nothing is decrypted or encrypted again.
//!
//! Every credential is scanned for references, whatever its kind
//! ([`referenced`]).
//!
//! The blobs to upload are recorded in `staged_blobs` of the local sync
//! state when the staged file is written, so a copy with no key uploads them
//! (`VaultWriter::copy_staged`). They are every blob that the staged state
//! references and that the local store holds. [`upload`] lists the folder
//! and writes only the blobs it lacks. A referenced blob that the local
//! store lacks is uploaded by a replica that holds it, and does not hold back
//! a publish.
//!
//! A transaction with a transport also uploads the referenced blobs that the
//! local store holds and the folder lacks, after its publish ([`heal`]). It
//! changes no local state, and a failure does not pause sync.
//!
//! Blobs in the folder that the joined state does not reference are counted
//! for the sync report ([`unreferenced`]). No blob is deleted from the
//! folder.
//!
//! A blob that the local store lacks is fetched when the file is read
//! ([`fetch`]).

use std::collections::BTreeSet;

use uuid::Uuid;

use super::model::SyncState;
use super::transport::{ReadResult, SyncTransport};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::files::FileHash;
use crate::secrets::vaults::files::record::BlobRef;
use crate::secrets::vaults::files::store::BlobStore;

/// Blobs named by the values and history values of every credential of
/// `state`, live or trashed, whatever its `kind` register holds. A credential
/// whose `kind` register a concurrent purge emptied is scanned too, and so is
/// one of a kind that a newer build wrote.
pub(crate) fn referenced(state: &SyncState) -> BTreeSet<FileHash> {
    let mut blobs = BTreeSet::new();
    for (_, cred) in state.credentials.iter() {
        let values = cred.value.values().map(|(_, value)| &value.value);
        let history = cred
            .history
            .iter()
            .flat_map(|(_, entry)| entry.values())
            .filter_map(|(_, entry)| entry.value.value.as_ref());
        for value in values.chain(history) {
            blobs.extend(BlobRef::of(&value.0));
        }
    }
    blobs
}

/// Blobs of `referenced` that `store` holds, in order. Each may be missing
/// from the folder. [`upload`] lists the folder and skips the blobs it has.
pub(crate) fn pending(referenced: &BTreeSet<FileHash>, store: &BlobStore) -> Vec<FileHash> {
    referenced
        .iter()
        .filter(|blob| store.contains(blob))
        .copied()
        .collect()
}

/// Upload each blob of `referenced` that `store` holds and that the folder
/// of `transport` lacks, for vault `vault_id`. The folder is not listed if
/// `store` holds no referenced blob. Returns the number of blobs written.
pub(crate) fn heal(
    transport: &dyn SyncTransport,
    vault_id: Uuid,
    store: &BlobStore,
    referenced: &BTreeSet<FileHash>,
) -> Result<usize, Error> {
    upload(transport, vault_id, store, &pending(referenced, store))
}

/// Count and total size in bytes of the blobs of `listed`, as returned by
/// `SyncTransport::list_blob_sizes`, that `referenced` lacks.
pub(crate) fn unreferenced(
    listed: &[(FileHash, u64)],
    referenced: &BTreeSet<FileHash>,
) -> (usize, u64) {
    let unreferenced = listed.iter().filter(|(blob, _)| !referenced.contains(blob));
    unreferenced.fold((0, 0), |(count, total), (_, size)| {
        (count + 1, total + size)
    })
}

/// Upload each blob of `pending` that `transport` does not list, from
/// `store`, for vault `vault_id`. Each blob is checked against its name
/// before it is written. Stops at the first failure. Returns the number of
/// blobs written.
pub(crate) fn upload(
    transport: &dyn SyncTransport,
    vault_id: Uuid,
    store: &BlobStore,
    pending: &[FileHash],
) -> Result<usize, Error> {
    if pending.is_empty() {
        return Ok(0);
    }
    let listed = transport.list_blobs(vault_id)?;
    let mut written = 0;
    for blob in pending.iter().filter(|blob| !listed.contains(blob)) {
        let bytes = store.read_bytes(blob)?;
        transport.write_blob(vault_id, *blob, &bytes)?;
        written += 1;
    }
    if written > 0 {
        log::info!("Uploaded {written} file blobs of vault {vault_id}");
    }
    Ok(written)
}

/// Fetch blob `blob` of vault `vault_id` from `transport` into `store`. The
/// bytes are checked against the name before they are written.
///
/// A blob that is not local yet in the folder is requested for download,
/// and fails with `FilePending`. A blob the folder lacks fails with
/// `FileMissing`, and one whose bytes do not hash to its name with
/// `FileBlobMismatch`.
pub(crate) fn fetch(
    transport: &dyn SyncTransport,
    vault_id: Uuid,
    store: &BlobStore,
    blob: FileHash,
) -> Result<(), Error> {
    match transport.read_blob(vault_id, blob)? {
        ReadResult::Local(bytes) => {
            store.put(&blob, &bytes)?;
            log::info!("Fetched file blob {blob} of vault {vault_id}");
            Ok(())
        },
        ReadResult::Remote => {
            if let Err(e) = transport.request_blob_download(vault_id, blob) {
                log::warn!("Failed to request the download of file blob {blob}: {e}");
            }
            Err(Error::FilePending(blob.to_string()))
        },
        ReadResult::Missing => Err(Error::FileMissing(blob.to_string())),
    }
}
