//! Public key files of vault SSH keys.
//!
//! Each vault key has a file `id_vault_<id>.pub` in the SSH directory, for
//! `IdentityFile` and `user.signingkey`. `<id>` is the credential id in short
//! form, which does not change if the item or credential is renamed. The file
//! is not used for listing or signing, and there is no private key next to it.

use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::{fs, io};

use uuid::Uuid;

use crate::secrets::vaults::ShortId;

const PREFIX: &str = "id_vault_";
const SUFFIX: &str = ".pub";

/// Key name of credential `id`, such as `id_vault_<id>`. It is the public key
/// file name without `.pub`.
pub fn key_name(id: Uuid) -> String {
    format!("{PREFIX}{}", ShortId::encode_uuid(id))
}

/// Path of the public key file of credential `id` in `dir`.
pub fn path_for(dir: &Path, id: Uuid) -> PathBuf {
    dir.join(format!("{}{SUFFIX}", key_name(id)))
}

/// Write the public key file of credential `id`, replacing an existing file.
/// Creates `dir` with mode `0700` if it is missing. Returns the path.
pub fn write(dir: &Path, id: Uuid, public_key: &str) -> io::Result<PathBuf> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    let path = path_for(dir, id);
    fs::write(&path, format!("{}\n", public_key.trim()))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    Ok(path)
}

/// Delete the public key file of credential `id`. A missing file is not an
/// error.
pub fn remove(dir: &Path, id: Uuid) -> io::Result<()> {
    match fs::remove_file(path_for(dir, id)) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// Delete the public key files in `dir` of credentials that are not in `keep`.
/// Other files are left alone. Returns the deleted paths.
pub fn sweep(dir: &Path, keep: &HashSet<Uuid>) -> io::Result<Vec<PathBuf>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut removed = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(text) = name
            .to_str()
            .and_then(|name| name.strip_prefix(PREFIX))
            .and_then(|name| name.strip_suffix(SUFFIX))
        else {
            continue;
        };
        let Ok(id) = ShortId::parse_uuid(text) else {
            continue;
        };
        if keep.contains(&id) {
            continue;
        }
        let path = entry.path();
        fs::remove_file(&path)?;
        removed.push(path);
    }
    Ok(removed)
}

#[cfg(test)]
mod tests;
