//! Move of the vault files that this Mac cannot read to `unreadable/`.
//!
//! On new hardware `vault-encryption-key` is missing, so no file under
//! `vaults/`, `versions/`, or `sync/` can be decrypted. Before a key is
//! created, every such file is renamed to `unreadable/{yyyy-mm-dd}/`, with the
//! same relative path. Files in `unreadable/` are never listed, loaded,
//! verified, or pruned. External vault files are never moved.

use std::path::{Path, PathBuf};
use std::{fs, io};

use jiff::civil::Date;
use uuid::Uuid;

use crate::audit::{self, Action, AuditEvent, Outcome};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::storage::device_keys::VaultFiles;
use crate::secrets::vaults::sync::crdt::ReplicaId;
use crate::secrets::vaults::sync::local_state::LocalSyncState;

#[cfg(test)]
mod tests;

/// Directory of the moved files under the app data directory.
pub(super) const UNREADABLE_DIR: &str = "unreadable";

/// Synced vault named by its local sync state, read without verifying it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncedVault {
    pub vault_id: Uuid,
    pub replica_id: ReplicaId,
}

/// Result of [`Unreadable::move_all`].
#[derive(Debug)]
pub struct MovedFiles {
    /// Directory the files moved to. `None` if no file was found.
    pub dir: Option<PathBuf>,
    /// Number of files moved.
    pub count: usize,
    /// Synced vaults of the sync states, listed before the move.
    pub synced: Vec<SyncedVault>,
}

/// Move of the vault files of this Mac to `unreadable/`.
pub(super) struct Unreadable;

impl Unreadable {
    /// Rename every file under `vaults/`, `versions/`, and `sync/` of `files`
    /// to `unreadable/{date}/` under the app data directory, with the same
    /// relative paths. A second move on the same date uses
    /// `unreadable/{date}-{n}/` with the first free `n` from 1. Sync states,
    /// staged files, and sidecars move too. `locks/`, `config.toml`, and
    /// external vault files do not move.
    ///
    /// Every file is listed before the first rename. A failed listing moves
    /// nothing. A failed rename stops the move, and the files moved before it
    /// stay in `unreadable/`. No file is deleted or replaced. The move records
    /// one `vault.unreadable_moved` event with the number of files moved.
    pub(super) fn move_all(files: &VaultFiles, date: Date) -> Result<MovedFiles, Error> {
        let synced = Self::synced_vaults(files.root());
        let mut count = 0;
        let result = Self::move_files(files, date, &mut count);
        Self::record(count, result.as_ref().err());
        let dir = result.map_err(Error::UnreadableMoveFailed)?;
        log::info!("Moved {count} unreadable vault files to {dir:?}");
        Ok(MovedFiles { dir, count, synced })
    }

    /// Synced vaults of the local sync states under the app data directory
    /// `root`, by the unverified vault id and replica id of each. A file that
    /// does not parse is skipped.
    pub fn synced_vaults(root: &Path) -> Vec<SyncedVault> {
        LocalSyncState::list(root)
            .into_iter()
            .filter_map(|(_, path)| {
                let contents = fs::read_to_string(path).ok()?;
                let (vault_id, replica_id) = LocalSyncState::peek(&contents)?;
                Some(SyncedVault {
                    vault_id,
                    replica_id,
                })
            })
            .collect()
    }

    /// Move the files and count each one in `count`. Returns the directory
    /// they moved to.
    fn move_files(
        files: &VaultFiles,
        date: Date,
        count: &mut usize,
    ) -> io::Result<Option<PathBuf>> {
        let mut sources = Vec::new();
        for (name, dir) in files.dirs() {
            Self::list(dir, Path::new(name), &mut sources)?;
        }
        if sources.is_empty() {
            return Ok(None);
        }
        let dir = Self::new_dir(&files.root().join(UNREADABLE_DIR), date)?;
        for (relative, path) in sources {
            let target = dir.join(relative);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            if fs::symlink_metadata(&target).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} exists", target.display()),
                ));
            }
            fs::rename(&path, &target)?;
            *count += 1;
        }
        Ok(Some(dir))
    }

    /// Add every file under `dir`, at any depth, to `found` with its path
    /// relative to the app data directory, under `relative`. A directory that
    /// does not exist holds no file. Links are moved as files.
    fn list(dir: &Path, relative: &Path, found: &mut Vec<(PathBuf, PathBuf)>) -> io::Result<()> {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let mut paths = Vec::new();
        for entry in entries {
            let entry = entry?;
            paths.push((entry.file_name(), entry.path(), entry.file_type()?.is_dir()));
        }
        paths.sort();
        for (name, path, is_dir) in paths {
            if is_dir {
                Self::list(&path, &relative.join(&name), found)?;
            } else {
                found.push((relative.join(&name), path));
            }
        }
        Ok(())
    }

    /// Create a new directory `{date}` under `unreadable`, or `{date}-{n}`
    /// with the first free `n` from 1 if it exists.
    fn new_dir(unreadable: &Path, date: Date) -> io::Result<PathBuf> {
        fs::create_dir_all(unreadable)?;
        let date = date.strftime("%Y-%m-%d").to_string();
        for n in 0u64.. {
            let name = if n == 0 {
                date.clone()
            } else {
                format!("{date}-{n}")
            };
            let path = unreadable.join(name);
            match fs::create_dir(&path) {
                Ok(()) => return Ok(path),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {},
                Err(e) => return Err(e),
            }
        }
        unreachable!("some index is free")
    }

    /// Record the move of `count` files, failed with `error` if set.
    fn record(count: usize, error: Option<&io::Error>) {
        let outcome = if error.is_some() {
            Outcome::Failed
        } else {
            Outcome::Succeeded
        };
        let mut event = AuditEvent::new(
            audit::process_source(),
            Action::VaultUnreadableMoved,
            outcome,
        )
        .detail("file_count", count.to_string());
        if let Some(error) = error {
            event = event.message(error.to_string());
        }
        audit::record(event);
    }
}
