//! Deletes of the key and vault state of this Mac. Each call deletes state
//! immediately. The caller quits the app afterward, so no open handle or
//! cached key outlives the delete. `core::reset` and the debug Developer menu
//! call these.

use std::{fs, io};

use anyhow::Context;

use crate::core::dirs::app_data_dir;
use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::vaults::format::signing::KeychainSigner;
use crate::secrets::vaults::storage::device_keys::{VAULT_ENCRYPTION_KEY_LABEL, VAULTS_DIR};
use crate::secrets::vaults::storage::txn::VERSIONS_DIR;
use crate::secrets::vaults::storage::unreadable::UNREADABLE_DIR;
use crate::secrets::vaults::sync::local_state::SYNC_DIR;

/// Delete `device-signing-key`. The next launch reports `SigningKeyLost` if
/// vault files exist.
pub fn delete_signing_key() -> anyhow::Result<()> {
    KeychainSigner::delete_key().context("failed to delete device-signing-key")
}

/// Delete `vault-encryption-key` and `device-signing-key`. The next launch
/// reports `NewHardware` if vault files exist.
pub fn delete_device_keys() -> anyhow::Result<()> {
    ManagedKey::delete_by_label(VAULT_ENCRYPTION_KEY_LABEL)
        .context("failed to delete vault-encryption-key")?;
    delete_signing_key()
}

/// Delete every file under `vaults/`, `versions/`, `sync/`, and
/// `unreadable/` in the app data directory. External vaults, `config.toml`,
/// and keys are not touched.
pub fn erase_vault_files() -> anyhow::Result<()> {
    let root = app_data_dir();
    for name in [VAULTS_DIR, VERSIONS_DIR, SYNC_DIR, UNREADABLE_DIR] {
        let dir = root.join(name);
        match fs::remove_dir_all(&dir) {
            Ok(()) => {},
            Err(e) if e.kind() == io::ErrorKind::NotFound => {},
            Err(e) => return Err(e).with_context(|| format!("failed to delete {}", dir.display())),
        }
    }
    Ok(())
}
