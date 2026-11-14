//! File blobs of an export.
//!
//! The blobs that the exported records name are copied into the bundle as
//! stored, sealed under their per-file keys. Nothing is decrypted or
//! encrypted again.
//!
//! A blob that the local store lacks is fetched from the synced folder if the
//! vault syncs. A blob that cannot be read or fetched is listed in the
//! report, and the export still writes the rest. An unreadable local copy is
//! handled like a missing one.

use std::collections::{BTreeMap, BTreeSet};

use uuid::Uuid;

use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::files::FileHash;
use crate::secrets::vaults::files::store::BlobStore;
use crate::secrets::vaults::storage::handle::VaultHandle;
use crate::secrets::vaults::storage::txn::VaultWriter;

/// File blob that an export could not include.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissingBlob {
    pub vault_id: Uuid,
    pub blob: FileHash,
    /// Why the blob could not be read or fetched.
    pub reason: String,
}

/// Outcome of an export.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExportReport {
    /// Blobs that exported records name and that the export could not
    /// include. The files they belong to are in the bundle as records only.
    pub missing_blobs: Vec<MissingBlob>,
}

/// Bytes of each blob of `referenced` for the vault `vh` with id `vault_id`.
/// The blobs that could not be read go to `missing`. A vault that syncs
/// fetches a blob that is not local through `writer`. Fails on a read error
/// other than a missing or damaged blob.
pub(crate) fn collect(
    writer: &VaultWriter,
    vh: &VaultHandle,
    vault_id: Uuid,
    synced: bool,
    referenced: &BTreeSet<FileHash>,
    missing: &mut Vec<MissingBlob>,
) -> Result<BTreeMap<FileHash, Vec<u8>>, Error> {
    let store = BlobStore::of(&vh.path, vault_id);
    let mut blobs = BTreeMap::new();
    for blob in referenced {
        let read = match store.read_bytes(blob) {
            Ok(bytes) => Ok(bytes),
            Err(Error::FileMissing(_) | Error::FileBlobMismatch(_)) if synced => writer
                .fetch_blob(vault_id, &vh.path, *blob)
                .and_then(|()| store.read_bytes(blob)),
            Err(e @ (Error::FileMissing(_) | Error::FileBlobMismatch(_))) => Err(e),
            Err(e) => return Err(e),
        };
        match read {
            Ok(bytes) => {
                blobs.insert(*blob, bytes);
            },
            Err(e) => {
                log::warn!("File blob {blob} of vault {vault_id} is not in the export: {e}");
                missing.push(MissingBlob {
                    vault_id,
                    blob: *blob,
                    reason: e.to_string(),
                });
            },
        }
    }
    Ok(blobs)
}
