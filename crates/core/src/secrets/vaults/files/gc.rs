//! Local garbage collection of file blobs.
//!
//! A blob is deleted once no record references it in the vault file,
//! including trash and history, or in any retained vault version, and a
//! synced vault does not list it to upload. It runs
//! under the vault locks after a transaction saves (`storage/txn.rs`), so no
//! save adds a reference meanwhile. A blob staged for a transaction is a temp
//! file until the transaction renames it under the locks, so it is never a
//! candidate.

use std::collections::BTreeSet;
use std::time::SystemTime;

use super::record::FileHash;
use super::store::BlobStore;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::model::Vault;

/// Delete the blobs of `store` that neither `keep`, `vault`, nor any vault
/// of `retained` references. Stale temp files are deleted first.
///
/// `keep` holds the blobs that a synced vault has not uploaded yet
/// (`sync/blobs.rs`). `retained` is called only if a blob is unreferenced in
/// `vault`, and its vaults are read only until every candidate is
/// referenced. A retained vault that fails to read fails the call before
/// anything is deleted, so a blob it might reference is kept. Returns the
/// number of blobs deleted.
pub(crate) fn collect<I>(
    store: &BlobStore,
    keep: &[FileHash],
    vault: &Vault,
    retained: impl FnOnce() -> Result<I, Error>,
) -> Result<usize, Error>
where
    I: Iterator<Item = Result<Vault, Error>>,
{
    store.delete_stale_temps(SystemTime::now());
    let mut candidates: BTreeSet<FileHash> = store.list()?.into_iter().collect();
    for blob in keep {
        candidates.remove(blob);
    }
    if candidates.is_empty() {
        return Ok(0);
    }
    for blob in vault.file_blobs()? {
        candidates.remove(&blob);
    }
    if candidates.is_empty() {
        return Ok(0);
    }
    for version in retained()? {
        for blob in version?.file_blobs()? {
            candidates.remove(&blob);
        }
        if candidates.is_empty() {
            return Ok(0);
        }
    }
    let mut deleted = 0;
    for blob in &candidates {
        if store.delete(blob)? {
            deleted += 1;
        }
    }
    Ok(deleted)
}
