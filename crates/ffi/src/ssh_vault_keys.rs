//! Vault SSH keys for Swift.
//!
//! A key is a credential of kind `ssh-key` whose value is a record with the
//! private key. The generic credential calls in `vault.rs` cannot write that
//! kind (`FieldKindInfo` has no `ssh-key` discriminator), so these calls are
//! the only way to create or change a key. None returns the private key.
//! `export_vault_ssh_key` writes it to a file the user picked.
//!
//! Each call that adds or changes a key rewrites the listing cache the broker
//! reads (`vault_keys_path()`) before it returns. The app also writes the
//! public key file `~/.ssh/id_vault_<id>.pub` when a key is created or
//! imported. A restore call writes it again. The file is deleted when a refresh
//! of the listing finds that no vault holds the key.

use std::fs;
use std::io::Read;
use std::sync::{Arc, Mutex};

use axo_pass_core::audit;
use axo_pass_core::core::app_broker::ssh::{vault_keys, vault_keys_path};
use axo_pass_core::secrets::vaults::ssh_keys::SshKeyError;
use axo_pass_core::secrets::vaults::ssh_keys::ops::{self, AddedKey, KeyTarget};
use axo_pass_core::secrets::vaults::{VaultHandle, VaultsManager};
use axo_pass_core::ssh::utils::ssh_dir_path;
use axo_pass_core::ssh::vault_pubkeys;
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use crate::vault::{change_event, credential_subject, ensure_unlocked, item_subject};
use crate::*;

/// Largest private key file that is read. A key file is a few kilobytes.
const MAX_KEY_FILE_BYTES: u64 = 256 * 1024;

/// A vault SSH key that was added.
#[derive(uniffi::Record, Clone, Debug)]
pub struct VaultSshKeyInfo {
    pub vault_key: String,
    pub item_key: String,
    pub credential_key: String,
    /// Canonical `SHA256:...` fingerprint.
    pub fingerprint_sha256: String,
    /// OpenSSH public key line, with the comment.
    pub public_key: String,
    /// Path of the public key file. `None` if it could not be written.
    pub pubkey_path: Option<String>,
}

/// Write the public key file of `credential_id`. A failure is logged, since
/// the key itself is stored.
fn write_pubkey_file(credential_id: Uuid, public_key: &str) -> Option<String> {
    let written = ssh_dir_path()
        .map_err(std::io::Error::other)
        .and_then(|dir| vault_pubkeys::write(&dir, credential_id, public_key));
    match written {
        Ok(path) => Some(path.to_string_lossy().to_string()),
        Err(e) => {
            log::warn!("Failed to write the public key file of {credential_id}: {e}");
            None
        },
    }
}

/// Delete the public key files of keys that `entries` do not list. `entries`
/// are the listing entries of all vaults as just written.
pub(crate) fn sweep_ssh_pubkey_files(entries: &[vault_keys::VaultKeyEntry]) {
    let swept = ssh_dir_path()
        .map_err(std::io::Error::other)
        .and_then(|dir| vault_keys::sweep_pubkey_files(&dir, entries));
    if let Err(e) = swept {
        log::warn!("Failed to delete public key files of removed SSH keys: {e}");
    }
}

/// Rewrite the listing entries of `vault_key` from the vault, and delete the
/// public key files of keys no vault holds. Skipped with a log line if the
/// vault cannot be read.
pub(crate) async fn sync_ssh_key_listing(manager: Arc<Mutex<VaultsManager>>, vault_key: String) {
    let synced = tokio::task::spawn_blocking(move || sync_listing(&manager, &vault_key)).await;
    if let Err(e) = synced {
        log::error!("Vault SSH key listing task failed: {e}");
    }
}

fn sync_listing(manager: &Mutex<VaultsManager>, vault_key: &str) {
    if let Err(e) = ensure_unlocked(manager, vault_key) {
        log::warn!("Vault SSH key listing not updated for {vault_key}: {e}");
        return;
    }
    let ssh_dir = match ssh_dir_path() {
        Ok(dir) => dir,
        Err(e) => {
            log::warn!("Vault SSH key listing not updated for {vault_key}: {e}");
            return;
        },
    };
    let Ok(mut m) = manager.lock() else {
        log::error!("Vault SSH key listing not updated for {vault_key}: mutex poisoned");
        return;
    };
    let Some(vault) = m.get_vault_mut(vault_key) else {
        return;
    };
    if let Err(e) = vault_keys::sync_vault(&vault_keys_path(), &ssh_dir, vault_key, vault) {
        log::error!("Failed to update the vault SSH key listing for {vault_key}: {e}");
    }
}

/// Where a key goes: the existing item `item_key`, or a new item titled
/// `item_title`.
struct Placement {
    item_key: Option<String>,
    item_title: String,
}

impl Placement {
    fn target(&self) -> KeyTarget<'_> {
        match &self.item_key {
            Some(item_key) => KeyTarget::ExistingItem { item_key },
            None => KeyTarget::NewItem {
                title: &self.item_title,
            },
        }
    }
}

/// Add a key to a vault with `add`, then write its public key file and update
/// the listing. `source` is `generated` or `imported`, for the audit event.
async fn add_key(
    manager: Arc<Mutex<VaultsManager>>,
    vault_key: String,
    placement: Placement,
    source: &'static str,
    add: impl FnOnce(&mut VaultHandle, KeyTarget<'_>) -> Result<AddedKey, SshKeyError> + Send + 'static,
) -> Result<VaultSshKeyInfo, FfiError> {
    let key = vault_key.clone();
    let new_item_title = placement
        .item_key
        .is_none()
        .then(|| placement.item_title.clone());
    let (added, item_ids, ids, pubkey_path) = tokio::task::spawn_blocking(move || {
        let (added, item_ids, ids) = VaultsManager::write_vault(&manager, &vault_key, |vw| {
            let added = add(vw, placement.target())?;
            let item_ids = vw.item_ids(&added.item_key)?;
            let ids = vw.credential_ids(&added.item_key, &added.credential_key)?;
            Ok::<_, FfiError>((added, item_ids, ids))
        })?;
        let pubkey_path = write_pubkey_file(added.credential_id, &added.public_key);
        sync_listing(&manager, &vault_key);
        Ok::<_, FfiError>((added, item_ids, ids, pubkey_path))
    })
    .await
    .map_err(|e| FfiError::Internal(e.to_string()))??;

    if let Some(title) = new_item_title {
        change_event(
            audit::Action::ItemCreated,
            &key,
            item_subject(&key, &added.item_key).label(title),
            item_ids,
        )
        .detail("ssh_key", "true")
        .record_async()
        .await;
    }
    change_event(
        audit::Action::CredentialCreated,
        &key,
        credential_subject(&key, &added.item_key, &added.credential_key),
        ids,
    )
    .detail("kind", "ssh-key")
    .detail("source", source)
    .detail("fingerprint", added.fingerprint.clone())
    .record_async()
    .await;

    Ok(VaultSshKeyInfo {
        vault_key: key,
        item_key: added.item_key,
        credential_key: added.credential_key,
        fingerprint_sha256: added.fingerprint,
        public_key: added.public_key,
        pubkey_path,
    })
}

/// Read the private key file at `path`. Fails with `InvalidInput` if it cannot
/// be read, is not a regular file, is too large, or is not text.
fn read_key_file(path: &str) -> Result<String, FfiError> {
    let invalid = |e: std::io::Error| FfiError::InvalidInput(format!("Cannot read {path}: {e}"));
    let file = fs::File::open(path).map_err(invalid)?;
    let metadata = file.metadata().map_err(invalid)?;
    if !metadata.is_file() {
        return Err(FfiError::InvalidInput(format!("{path} is not a file")));
    }
    if metadata.len() > MAX_KEY_FILE_BYTES {
        return Err(FfiError::InvalidInput(format!(
            "{path} is too large to be an SSH key"
        )));
    }
    let mut text = String::new();
    file.take(MAX_KEY_FILE_BYTES)
        .read_to_string(&mut text)
        .map_err(|_| FfiError::InvalidInput(format!("{path} is not an SSH private key")))?;
    Ok(text)
}

fn non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_key_file_returns_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id_ed25519");
        fs::write(&path, "-----BEGIN OPENSSH PRIVATE KEY-----\n").unwrap();

        let text = read_key_file(path.to_str().unwrap()).unwrap();

        assert_eq!(text, "-----BEGIN OPENSSH PRIVATE KEY-----\n");
    }

    #[test]
    fn read_key_file_refuses_unusable_paths() {
        let dir = tempfile::tempdir().unwrap();
        let large = dir.path().join("large");
        fs::write(&large, vec![b'a'; MAX_KEY_FILE_BYTES as usize + 1]).unwrap();
        let binary = dir.path().join("binary");
        fs::write(&binary, [0xff, 0xfe, 0x00]).unwrap();

        for path in [
            dir.path().to_path_buf(),
            dir.path().join("missing"),
            large,
            binary,
        ] {
            let result = read_key_file(path.to_str().unwrap());

            assert!(
                matches!(result, Err(FfiError::InvalidInput(_))),
                "{}",
                path.display()
            );
        }
    }

    #[test]
    fn key_errors_map_to_ffi_variants() {
        assert!(matches!(
            FfiError::from(SshKeyError::PassphraseRequired),
            FfiError::SshKeyPassphraseRequired
        ));
        assert!(matches!(
            FfiError::from(SshKeyError::WrongPassphrase),
            FfiError::SshKeyWrongPassphrase
        ));
        assert!(matches!(
            FfiError::from(SshKeyError::Duplicate {
                fingerprint: "SHA256:x".to_string()
            }),
            FfiError::SshKeyDuplicate(f) if f == "SHA256:x"
        ));
        assert!(matches!(
            FfiError::from(SshKeyError::InvalidPrivateKey("bad".to_string())),
            FfiError::InvalidInput(_)
        ));
    }

    #[test]
    fn empty_comment_is_none() {
        assert_eq!(non_empty(Some("  ".to_string())), None);
        assert_eq!(non_empty(None), None);
        assert_eq!(non_empty(Some(" a ".to_string())), Some("a".to_string()));
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl AxoPass {
    /// Generate an Ed25519 key with policy `default` in vault `vault_key`.
    /// With `item_key`, the key is added to that item. Otherwise a new item
    /// titled `item_title` with category `ssh-key` holds it. `comment` is the
    /// key comment. Writes `~/.ssh/id_vault_<id>.pub` and updates the listing.
    pub async fn generate_vault_ssh_key(
        &self,
        vault_key: String,
        item_key: Option<String>,
        item_title: String,
        comment: String,
    ) -> Result<VaultSshKeyInfo, FfiError> {
        let comment = comment.trim().to_string();
        add_key(
            Arc::clone(&self.manager),
            vault_key,
            Placement {
                item_key,
                item_title,
            },
            "generated",
            move |vw, target| ops::generate(vw, target, &comment),
        )
        .await
    }

    /// Import the OpenSSH private key file at `path` into vault `vault_key`,
    /// placed as `generate_vault_ssh_key` places a key. An encrypted key is
    /// decrypted with `passphrase` and stored unencrypted. The comment is
    /// `comment`, or the comment in the key. Fails with
    /// `SshKeyPassphraseRequired` or `SshKeyWrongPassphrase` for an encrypted
    /// key, `SshKeyDuplicate` if the vault already holds the key, and
    /// `InvalidInput` for a file that is not a usable private key.
    pub async fn import_vault_ssh_key(
        &self,
        vault_key: String,
        item_key: Option<String>,
        item_title: String,
        path: String,
        passphrase: Option<String>,
        comment: Option<String>,
    ) -> Result<VaultSshKeyInfo, FfiError> {
        let text = SecretString::from(read_key_file(&path)?);
        let passphrase = passphrase.map(SecretString::from);
        let comment = non_empty(comment);
        add_key(
            Arc::clone(&self.manager),
            vault_key,
            Placement {
                item_key,
                item_title,
            },
            "imported",
            move |vw, target| {
                ops::import(
                    vw,
                    target,
                    text.expose_secret(),
                    passphrase.as_ref(),
                    comment.as_deref(),
                )
            },
        )
        .await
    }

    /// OpenSSH public key line of a vault SSH key, for copying.
    pub async fn vault_ssh_key_public_key(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
    ) -> Result<String, FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            ensure_unlocked(&manager, &vault_key)?;
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vault = m
                .get_or_create_vault_mut(&vault_key)
                .map_err(FfiError::from)?;
            Ok(ops::public_key_line(vault, &item_key, &cred_key)?)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Change the comment of a vault SSH key. Updates the listing, and the
    /// public key file if it exists. Returns the new public key line.
    pub async fn set_vault_ssh_key_comment(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
        comment: String,
    ) -> Result<String, FfiError> {
        let comment = comment.trim().to_string();
        let subject = credential_subject(&vault_key, &item_key, &cred_key);
        let manager = Arc::clone(&self.manager);
        let key = vault_key.clone();
        let (line, ids) = tokio::task::spawn_blocking(move || {
            let (line, ids) = VaultsManager::write_vault(&manager, &vault_key, |vw| {
                let line = ops::set_comment(vw, &item_key, &cred_key, &comment)?;
                let ids = vw.credential_ids(&item_key, &cred_key)?;
                Ok::<_, FfiError>((line, ids))
            })?;
            if let (Some(id), Ok(dir)) = (ids.credential_id, ssh_dir_path())
                && vault_pubkeys::path_for(&dir, id).exists()
            {
                write_pubkey_file(id, &line);
            }
            sync_listing(&manager, &vault_key);
            Ok::<_, FfiError>((line, ids))
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))??;
        change_event(audit::Action::CredentialUpdated, &key, subject, ids)
            .detail("changed", "comment")
            .detail("kind", "ssh-key")
            .record_async()
            .await;
        Ok(line)
    }

    /// Set whether the agent advertises (`auto_load`) and signs with
    /// (`ssh_use`) a vault SSH key. Turning off `ssh_use` also turns off
    /// `auto_load`. Updates the listing.
    pub async fn set_vault_ssh_key_access(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
        auto_load: bool,
        ssh_use: bool,
    ) -> Result<(), FfiError> {
        let subject = credential_subject(&vault_key, &item_key, &cred_key);
        let manager = Arc::clone(&self.manager);
        let key = vault_key.clone();
        let ids = tokio::task::spawn_blocking(move || {
            let ids = VaultsManager::write_vault(&manager, &vault_key, |vw| {
                ops::set_ssh_access(vw, &item_key, &cred_key, auto_load, ssh_use)?;
                Ok::<_, FfiError>(vw.credential_ids(&item_key, &cred_key)?)
            })?;
            sync_listing(&manager, &vault_key);
            Ok::<_, FfiError>(ids)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))??;
        change_event(audit::Action::CredentialUpdated, &key, subject, ids)
            .detail("changed", "ssh_access")
            .detail("kind", "ssh-key")
            .detail("auto_load", (auto_load && ssh_use).to_string())
            .detail("ssh_use", ssh_use.to_string())
            .record_async()
            .await;
        Ok(())
    }

    /// Write the private key of a vault SSH key to `dest_path` as an OpenSSH
    /// key file with mode `0600`. `dest_path` is replaced if it exists. A
    /// non-empty `passphrase` encrypts the file. Records a `credential.read`
    /// event, as the key leaves the vault.
    pub async fn export_vault_ssh_key(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
        dest_path: String,
        passphrase: Option<String>,
    ) -> Result<(), FfiError> {
        let passphrase = passphrase.map(SecretString::from);
        let encrypted = passphrase
            .as_ref()
            .is_some_and(|p| !p.expose_secret().is_empty());
        let subject = credential_subject(&vault_key, &item_key, &cred_key);
        let manager = Arc::clone(&self.manager);
        let key = vault_key.clone();
        let ids = tokio::task::spawn_blocking(move || {
            ensure_unlocked(&manager, &vault_key)?;
            let (text, ids) = {
                let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
                let vault = m
                    .get_or_create_vault_mut(&vault_key)
                    .map_err(FfiError::from)?;
                let text =
                    ops::export_private_key(vault, &item_key, &cred_key, passphrase.as_ref())?;
                (text, vault.credential_ids(&item_key, &cred_key)?)
            };
            crate::files::write_atomically(std::path::Path::new(&dest_path), |out| {
                std::io::Write::write_all(out, text.as_bytes())
                    .map_err(|e| FfiError::Internal(format!("Cannot write {dest_path}: {e}")))
            })?;
            Ok::<_, FfiError>(ids)
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))??;
        change_event(audit::Action::CredentialRead, &key, subject, ids)
            .detail("kind", "ssh-key")
            .detail("export", "private-key-file")
            .detail("encrypted", if encrypted { "true" } else { "false" })
            .record_async()
            .await;
        Ok(())
    }

    /// Write the public key file `~/.ssh/id_vault_<id>.pub` of a vault SSH
    /// key again, for a file that was deleted. Returns its path.
    pub async fn write_vault_ssh_key_pubkey(
        &self,
        vault_key: String,
        item_key: String,
        cred_key: String,
    ) -> Result<String, FfiError> {
        let manager = Arc::clone(&self.manager);
        tokio::task::spawn_blocking(move || {
            ensure_unlocked(&manager, &vault_key)?;
            let mut m = manager.lock().map_err(|_| FfiError::Poisoned)?;
            let vault = m
                .get_or_create_vault_mut(&vault_key)
                .map_err(FfiError::from)?;
            let line = ops::public_key_line(vault, &item_key, &cred_key)?;
            let id = vault
                .credential_ids(&item_key, &cred_key)?
                .credential_id
                .ok_or_else(|| FfiError::NotFound(format!("{vault_key}/{item_key}/{cred_key}")))?;
            let dir = ssh_dir_path().map_err(FfiError::from)?;
            let path = vault_pubkeys::write(&dir, id, &line).map_err(|e| {
                FfiError::Internal(format!("Cannot write the public key file: {e}"))
            })?;
            Ok(path.to_string_lossy().to_string())
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }
}
