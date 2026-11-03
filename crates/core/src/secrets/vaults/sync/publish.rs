//! Staged file and publish of a synced vault.
//!
//! A transaction publishes if the local context is ahead of
//! `published_context`, or if this replica's directory lacks the file of its
//! last publish. It writes the staged file first, then the sync state that
//! names it in `staged_context` and `staged_hash`, then the vault. It then
//! copies the staged file to the synced folder and records its hash in the
//! sidecar. No signed save follows the vault save. The next transaction moves
//! `staged_context` to `published_context` if the sidecar hash and the staged
//! file both match `staged_hash`.

use std::path::Path;
use std::{fs, io};

use uuid::Uuid;

use super::crdt::{OwnFile, ReplicaId};
use super::local_state::LocalSyncState;
use super::state_file::StateHash;
use super::transport::{FileName, SyncTransport};
use crate::core::files::write_atomic;
use crate::secrets::vaults::errors::Error;

/// Staged file to copy to the synced folder.
#[derive(Debug)]
pub(crate) struct Staged {
    /// SHA-256 of the file bytes, the hash in its published name.
    pub(crate) hash: StateHash,
    bytes: Vec<u8>,
    /// Whether this transaction wrote the file.
    pub(crate) written: bool,
}

impl Staged {
    /// Bytes of the staged file of vault `vault_id` under the app data
    /// directory `root`. `None` if the file is missing or cannot be read.
    pub(crate) fn read(root: &Path, vault_id: Uuid) -> Option<Vec<u8>> {
        let path = LocalSyncState::staged_path(root, vault_id);
        match fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => {
                log::warn!("Failed to read {}: {e}", path.display());
                None
            },
        }
    }

    /// Staged file of vault `vault_id` under `root` as it is on disk, if it
    /// hashes to `hash`.
    pub(crate) fn existing(root: &Path, vault_id: Uuid, hash: StateHash) -> Option<Self> {
        let bytes = Self::read(root, vault_id)?;
        (StateHash::of(&bytes) == hash).then_some(Self {
            hash,
            bytes,
            written: false,
        })
    }

    /// Write `bytes` as the staged file of vault `vault_id` under `root`,
    /// replacing the file in one rename.
    pub(crate) fn write(root: &Path, vault_id: Uuid, bytes: Vec<u8>) -> Result<Self, Error> {
        let path = LocalSyncState::staged_path(root, vault_id);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(Error::SyncStateWriteError)?;
        }
        write_atomic(&path, &bytes).map_err(Error::SyncStateWriteError)?;
        Ok(Self {
            hash: StateHash::of(&bytes),
            bytes,
            written: true,
        })
    }

    /// Delete the staged file of vault `vault_id` under `root` if this
    /// transaction wrote it. A failure is logged.
    pub(crate) fn discard(&self, root: &Path, vault_id: Uuid) {
        if !self.written {
            return;
        }
        let path = LocalSyncState::staged_path(root, vault_id);
        if let Err(e) = fs::remove_file(&path)
            && e.kind() != io::ErrorKind::NotFound
        {
            log::error!("Failed to delete {}: {e}", path.display());
        }
    }

    /// Copy the file to the directory of `replica` through `transport`. A
    /// file already listed in `own_files` under the same hash holds the same
    /// bytes, so it is not written again. A publish never overwrites a file.
    pub(crate) fn copy(
        &self,
        transport: &dyn SyncTransport,
        vault_id: Uuid,
        replica: ReplicaId,
        own_files: &[OwnFile<StateHash>],
    ) -> Result<(), Error> {
        if own_files.iter().any(|file| file.hash == self.hash) {
            return Ok(());
        }
        transport.write_own(vault_id, replica, FileName::State(self.hash), &self.bytes)
    }
}
