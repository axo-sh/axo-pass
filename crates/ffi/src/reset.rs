//! Resets of the state of this Mac.
//!
//! The app asks for user presence before it calls either reset, clears its
//! preferences, and quits afterward. It stops the SSH agent and the sync
//! manager before an erase.

use axo_pass_core::core::reset;

use crate::*;

/// Delete protected settings, browser listing grants, and SSH app grants.
/// Keys, vaults, and sync are not touched.
#[uniffi::export]
pub fn reset_settings() -> Result<(), FfiError> {
    log::warn!("Resetting settings");
    Ok(reset::reset_settings()?)
}

/// Delete vault files, the app config, vault public key files, grants,
/// settings, the saved S3 location, Secure Enclave SSH keys, keychain
/// passphrases, and the device keys.
#[uniffi::export]
pub fn erase_this_mac() -> Result<(), FfiError> {
    log::warn!("Erasing this Mac");
    Ok(reset::erase_this_mac()?)
}

/// State that [`reset_device_state`] deletes. Debug builds only, to put this
/// Mac into a given key state for testing.
#[cfg(debug_assertions)]
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceResetScope {
    /// `device-signing-key`. Vault files stay, so the next launch reports a
    /// lost signing key.
    SigningKey,
    /// `vault-encryption-key` and `device-signing-key`. Vault files stay, so
    /// the next launch reports new hardware.
    DeviceKeys,
    /// Vault, version, sync, and unreadable files. Keys stay.
    VaultFiles,
}

/// Delete the state of `scope`. The caller quits the app afterward.
#[cfg(debug_assertions)]
#[uniffi::export]
pub fn reset_device_state(scope: DeviceResetScope) -> Result<(), FfiError> {
    use axo_pass_core::secrets::vaults;

    log::warn!("Resetting device state: {scope:?}");
    match scope {
        DeviceResetScope::SigningKey => vaults::delete_signing_key()?,
        DeviceResetScope::DeviceKeys => vaults::delete_device_keys()?,
        DeviceResetScope::VaultFiles => vaults::erase_vault_files()?,
    }
    Ok(())
}
