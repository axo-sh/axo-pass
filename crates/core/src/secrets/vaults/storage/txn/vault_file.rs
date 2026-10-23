//! Vault file paths and writes under the vault locks.

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use uuid::Uuid;

use crate::core::files::{write_atomic, write_atomic_new};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::encrypted_vault::VaultHeader;
use crate::secrets::vaults::storage::handle::VaultHandle;

fn same_path(a: &Path, b: &Path) -> bool {
    if let (Ok(a), Ok(b)) = (a.canonicalize(), b.canonicalize()) {
        a == b
    } else {
        false
    }
}

fn path_contains_vault(path: &Path, id: Uuid) -> bool {
    VaultHeader::peek(path).is_ok_and(|header| header.id == id)
}

fn duplicate_vault_id(a: &Path, b: &Path) -> Error {
    Error::DuplicateVaultId(format!("{} and {}", a.display(), b.display()))
}

/// Path of the vault file. `tracked` is the path in the vault locks.
/// `caller_path` is where the caller found the vault. `tracked` is used if
/// the vault was renamed since.
pub(super) fn resolve(tracked: &Path, id: Uuid, caller_path: &Path) -> Result<PathBuf, Error> {
    if same_path(tracked, caller_path) {
        return Ok(tracked.to_path_buf());
    }
    match (
        path_contains_vault(tracked, id),
        path_contains_vault(caller_path, id),
    ) {
        (true, true) => Err(duplicate_vault_id(tracked, caller_path)),
        (true, false) => Ok(tracked.to_path_buf()),
        (false, true) => Ok(caller_path.to_path_buf()),
        (false, false) => Err(Error::VaultNotFound(caller_path.display().to_string())),
    }
}

/// Fail if `tracked` holds vault `id` and differs from `path`.
pub(super) fn check_create_path(tracked: &Path, id: Uuid, path: &Path) -> Result<(), Error> {
    if !same_path(tracked, path) && path_contains_vault(tracked, id) {
        return Err(duplicate_vault_id(tracked, path));
    }
    Ok(())
}

/// Write `contents` at the path of `vh`. A file that exists there is never
/// replaced.
pub(super) fn write_new(vh: &VaultHandle, contents: &str) -> Result<(), Error> {
    write_atomic_new(&vh.path, contents.as_bytes()).map_err(|e| {
        if e.kind() == io::ErrorKind::AlreadyExists {
            Error::InvalidVaultKey(format!("A vault file already exists for key '{}'", vh.key))
        } else {
            Error::VaultWriteError(e)
        }
    })
}

/// Save `vh` over `old_path`, whose contents were `old_contents`. A vault
/// whose path changed is written at the new path and removed at the old one.
/// Returns whether anything was written.
pub(super) fn commit(old_path: &Path, old_contents: &str, vh: &VaultHandle) -> Result<bool, Error> {
    let contents = vh.file_contents()?;
    let moved = vh.path != old_path;
    if !moved && contents == old_contents {
        return Ok(false);
    }
    if moved {
        move_vault_file(old_path, vh, &contents)?;
    } else {
        write_atomic(&vh.path, contents.as_bytes()).map_err(Error::VaultWriteError)?;
    }
    Ok(true)
}

/// Write `contents` at the path of `vh`, then remove the vault file at
/// `old_path`. A file that exists at the new path is never replaced. The vault
/// locks are per vault id, so another vault file can appear at the new path at
/// any time. If any step fails, the file at `old_path` is unchanged.
fn move_vault_file(old_path: &Path, vh: &VaultHandle, contents: &str) -> Result<(), Error> {
    write_new(vh, contents).map_err(|e| match e {
        Error::VaultWriteError(e) => Error::VaultKeyUpdateFailed(e),
        e => e,
    })?;
    if let Err(e) = fs::remove_file(old_path) {
        // Two files with one vault id would make every later write fail.
        if let Err(undo) = fs::remove_file(&vh.path) {
            log::error!(
                "Failed to remove {} after a failed move: {undo}",
                vh.path.display()
            );
        }
        return Err(Error::VaultKeyUpdateFailed(e));
    }
    // Sync the directory so the removal is durable. A crash before the sync can
    // leave both files.
    if let Some(dir) = old_path.parent()
        && let Err(e) = File::open(dir).and_then(|dir| dir.sync_all())
    {
        log::error!("Failed to sync {} after a move: {e}", dir.display());
    }
    Ok(())
}
