//! Vault file paths and writes under the vault locks.

use std::io;
use std::path::{Path, PathBuf};

use uuid::Uuid;

use crate::core::files::{write_atomic, write_atomic_new};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::encrypted_vault::{EncryptedVault, VaultHeader};
use crate::secrets::vaults::format::signing::VaultSigner;
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
/// `caller_path` no longer holds the vault. If both hold it, the vault id is
/// held by two files and the write is refused.
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
            Error::DuplicateVaultId(format!(
                "A vault file already exists at {}",
                vh.path.display()
            ))
        } else {
            Error::VaultWriteError(e)
        }
    })
}

/// Commit of a save of vault `vh` to `path`, signed by `signer`. The raw vault
/// bytes are compared to `old_contents`, not the file envelope since
/// signatures may differ. If the raw vault bytes are equal, this is a no-op.
/// Otherwise `retain` is called with `old_contents` before the file is
/// replaced. The path of `vh` is expected to be `path`, because save does not
/// move vault files. Returns a bool indicating whether anything was written.
pub(super) fn commit(
    path: &Path,
    old_contents: &str,
    vh: &VaultHandle,
    signer: &dyn VaultSigner,
    retain: impl FnOnce(&str),
) -> Result<bool, Error> {
    debug_assert_eq!(vh.path, path);
    let vault_json = vh.vault_json()?;
    if vault_json == EncryptedVault::raw_vault_json(old_contents)? {
        return Ok(false);
    }
    let contents = EncryptedVault::sign_vault_json(vault_json, signer)?;
    retain(old_contents);
    write_atomic(path, contents.as_bytes()).map_err(Error::VaultWriteError)?;
    Ok(true)
}
