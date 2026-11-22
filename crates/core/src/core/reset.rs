//! Resets of the state of this Mac that a user can ask for.
//!
//! [`reset_settings`] deletes grants and protected settings, and keeps sync.
//! [`erase_this_mac`] also deletes vault files, the saved S3 location, Secure
//! Enclave SSH keys, keychain passphrases, device keys, and the app config.
//! Each records an audit event with its outcome. The audit log, logs, and
//! external vault files are not touched.
//! The caller clears the preferences, stops the SSH agent and the sync
//! manager before an erase, and quits the app afterward.

use std::collections::HashSet;
use std::{fs, io};

use anyhow::Context;

use crate::audit::{self, Action, AuditEvent, Outcome};
use crate::core::app_broker::browser_grants;
use crate::core::app_broker::ssh::vault_keys_path;
use crate::core::config::AppConfig;
use crate::core::protected_settings;
use crate::secrets::keychain::generic_password::PasswordEntry;
use crate::secrets::keychain::managed_key::ManagedSshKey;
use crate::secrets::vaults;
use crate::secrets::vaults::sync::transport::s3::credentials::default_credential_store;
use crate::ssh::utils::ssh_dir_path;
use crate::ssh::{app_grants, vault_pubkeys};

/// Name of the saved S3 location of the app. Matches `SyncModel.s3Name` in
/// the app.
const APP_S3_NAME: &str = "default";

/// Delete protected settings, browser listing grants, and SSH app grants.
pub fn reset_settings() -> anyhow::Result<()> {
    let result = delete_settings();
    record(Action::VaultSettingsReset, &result);
    result
}

/// Delete vault files, the app config, vault public key files, the vault key
/// listing, grants, settings, the saved S3 location, Secure Enclave SSH keys,
/// keychain passphrases, and finally the device keys. Files go before keys, so
/// a failure leaves a Mac without vault files, which is a normal state, and
/// not vault files without a key to read them.
pub fn erase_this_mac() -> anyhow::Result<()> {
    let result = erase();
    record(Action::VaultMacErased, &result);
    result
}

fn erase() -> anyhow::Result<()> {
    vaults::erase_vault_files()?;
    AppConfig::reset().context("failed to reset the app config")?;
    delete_vault_key_files()?;
    delete_settings()?;
    if let Some(store) = default_credential_store() {
        store
            .delete(APP_S3_NAME)
            .context("failed to delete the S3 location")?;
    }
    ManagedSshKey::delete_all().context("failed to delete the SSH keys")?;
    PasswordEntry::delete_all().context("failed to delete the keychain passphrases")?;
    vaults::delete_device_keys()
}

fn delete_settings() -> anyhow::Result<()> {
    protected_settings::delete_stored().context("failed to delete protected settings")?;
    browser_grants::delete_all().context("failed to delete browser grants")?;
    app_grants::delete_all().context("failed to delete SSH app grants")
}

/// Delete the `id_vault_*.pub` files in `~/.ssh` and the vault key listing.
fn delete_vault_key_files() -> anyhow::Result<()> {
    let ssh_dir = ssh_dir_path()?;
    vault_pubkeys::sweep(&ssh_dir, &HashSet::new())
        .context("failed to delete the vault public key files")?;
    let listing = vault_keys_path();
    match fs::remove_file(&listing) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => {
            Err(e).with_context(|| format!("failed to delete {}", listing.display()))
        },
        _ => Ok(()),
    }
}

fn record(action: Action, result: &anyhow::Result<()>) {
    let event = match result {
        Ok(()) => AuditEvent::new(audit::process_source(), action, Outcome::Succeeded),
        Err(e) => AuditEvent::new(audit::process_source(), action, Outcome::Failed)
            .message(format!("{e:#}")),
    };
    audit::record(event);
}
