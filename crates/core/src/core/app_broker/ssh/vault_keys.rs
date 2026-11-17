//! Listing cache of the SSH keys stored in vaults.
//!
//! Vault contents need the vault encryption key, which requires user presence
//! on every use, so the broker cannot list vault keys from the vaults. The app
//! writes the public half of each key, and where it is stored, to a file. The
//! broker reads it to answer `ssh-add -l` with no prompt, also before the app
//! is unlocked.
//!
//! The file holds no secret. It is written only by the app and read only by the
//! broker. The broker does not trust an entry. It checks the key against the
//! vault before it signs.

use std::path::Path;
use std::{fs, io};

use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use ssh_key::{HashAlg, PublicKey};

use crate::core::files::write_atomic_private;
use crate::secrets::keychain::managed_key::KeyPolicy;
use crate::secrets::vaults::ssh_keys::SshKeyRecord;
use crate::secrets::vaults::{FieldKind, VaultHandle};

const FORMAT_VERSION: u32 = 1;

/// One vault SSH key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultKeyEntry {
    /// Canonical `SHA256:...` fingerprint.
    pub fingerprint: String,

    /// OpenSSH public key line, with the comment.
    pub public_key: String,

    pub comment: String,

    /// Location of the credential.
    pub vault_key: String,
    pub item_key: String,
    pub credential_key: String,

    pub policy: KeyPolicy,
}

impl VaultKeyEntry {
    /// Entry for the key in `record`, stored at the given location. Fails if
    /// the record does not hold a valid public key.
    pub fn from_record(
        record: &SshKeyRecord,
        vault_key: &str,
        item_key: &str,
        credential_key: &str,
    ) -> Result<Self, String> {
        let public = PublicKey::from_openssh(&record.public_key)
            .map_err(|e| format!("Invalid public key: {e}"))?;
        let public_key = PublicKey::new(public.key_data().clone(), &record.comment)
            .to_openssh()
            .map_err(|e| format!("Failed to encode public key: {e}"))?;
        Ok(Self {
            fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
            public_key,
            comment: record.comment.clone(),
            vault_key: vault_key.to_string(),
            item_key: item_key.to_string(),
            credential_key: credential_key.to_string(),
            policy: record.policy,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct CacheFile {
    version: u32,
    keys: Vec<VaultKeyEntry>,
}

/// Entries for the SSH key credentials of an unlocked vault. A credential
/// whose value cannot be read as a key is skipped and logged.
pub fn collect(vault_key: &str, vault: &VaultHandle) -> Vec<VaultKeyEntry> {
    let Ok(items) = vault.list_items() else {
        return Vec::new();
    };
    let mut entries = Vec::new();
    for item in items {
        for credential in item.credentials.values() {
            if credential.kind != FieldKind::SshKey {
                continue;
            }
            let entry = vault
                .get_secret(&item.key, &credential.key)
                .map_err(|e| e.to_string())
                .and_then(|secret| secret.ok_or_else(|| "No value".to_string()))
                .and_then(|secret| {
                    SshKeyRecord::from_value(secret.expose_secret()).map_err(|e| e.to_string())
                })
                .and_then(|record| {
                    record.private_key().map_err(|e| e.to_string())?;
                    VaultKeyEntry::from_record(&record, vault_key, &item.key, &credential.key)
                });
            match entry {
                Ok(entry) => entries.push(entry),
                Err(e) => log::warn!(
                    "Skipping SSH key {vault_key}/{}/{}: {e}",
                    item.key,
                    credential.key
                ),
            }
        }
    }
    entries
}

/// Entries in `path`. A missing, unreadable, or corrupt file lists no keys.
pub fn load(path: &Path) -> Vec<VaultKeyEntry> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            log::debug!("No vault SSH key listing at {}", path.display());
            return Vec::new();
        },
        Err(e) => {
            log::warn!(
                "Could not read the vault SSH key listing {}: {e}",
                path.display()
            );
            return Vec::new();
        },
    };
    match serde_json::from_str::<CacheFile>(&text) {
        Ok(file) if file.version == FORMAT_VERSION => file.keys,
        Ok(file) => {
            log::warn!(
                "Ignoring the vault SSH key listing {}: unknown version {}",
                path.display(),
                file.version
            );
            Vec::new()
        },
        Err(e) => {
            log::warn!(
                "Ignoring the corrupt vault SSH key listing {}: {e}",
                path.display()
            );
            Vec::new()
        },
    }
}

/// Write `entries` to `path`, atomically and with mode `0600`. The file is
/// left alone if it already holds the same entries.
pub fn store(path: &Path, entries: &[VaultKeyEntry]) -> io::Result<()> {
    let mut keys = entries.to_vec();
    keys.sort_by(|a, b| {
        (&a.vault_key, &a.item_key, &a.credential_key).cmp(&(
            &b.vault_key,
            &b.item_key,
            &b.credential_key,
        ))
    });
    let file = CacheFile {
        version: FORMAT_VERSION,
        keys,
    };
    let data = serde_json::to_vec_pretty(&file).map_err(io::Error::other)?;
    if fs::read(path).is_ok_and(|existing| existing == data) {
        return Ok(());
    }
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    write_atomic_private(path, &data)
}

/// Rewrite the listing in `path` after the app read its vaults. `collected`
/// holds the entries of each vault that was unlocked. `known` are the keys of
/// all vaults. Entries of a vault that was not unlocked are kept, and entries
/// of a vault that no longer exists are dropped.
pub fn refresh(
    path: &Path,
    known: &[String],
    collected: Vec<(String, Vec<VaultKeyEntry>)>,
) -> io::Result<()> {
    let mut keys: Vec<VaultKeyEntry> = load(path)
        .into_iter()
        .filter(|entry| known.contains(&entry.vault_key))
        .filter(|entry| collected.iter().all(|(key, _)| *key != entry.vault_key))
        .collect();
    keys.extend(collected.into_iter().flat_map(|(_, entries)| entries));
    store(path, &keys)
}

/// Replace the entries of vault `vault_key` in `path` with `entries`. The
/// entries of other vaults are kept.
pub fn replace_vault(path: &Path, vault_key: &str, entries: Vec<VaultKeyEntry>) -> io::Result<()> {
    let mut keys: Vec<VaultKeyEntry> = load(path)
        .into_iter()
        .filter(|entry| entry.vault_key != vault_key)
        .collect();
    keys.extend(entries);
    store(path, &keys)
}

#[cfg(test)]
mod tests;
