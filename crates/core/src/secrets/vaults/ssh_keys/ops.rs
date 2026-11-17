//! Generate, import, and edit SSH keys in an unlocked vault.
//!
//! Each function changes the vault in memory. The caller saves it, as for the
//! other vault edits.

use std::collections::HashSet;

use secrecy::{ExposeSecret, SecretString};
use ssh_key::public::KeyData;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, Error as KeyError, LineEnding, PrivateKey};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{SshKeyError, SshKeyRecord};
use crate::secrets::vaults::storage::handle::normalized_key;
use crate::secrets::vaults::{CATEGORY_SSH_KEY, Error as VaultError, FieldKind, VaultHandle};

/// Credential key of a new key, with a numeric suffix if the item has it.
const CREDENTIAL_KEY: &str = "ssh-key";

/// Title of the credential of a new key.
const CREDENTIAL_TITLE: &str = "SSH key";

/// Item key of a new item whose title gives no valid key.
const FALLBACK_ITEM_KEY: &str = "ssh-key";

/// Where a new key is stored.
#[derive(Debug, Clone, Copy)]
pub enum KeyTarget<'a> {
    /// A new item with this title. Its category is `ssh-key`.
    NewItem { title: &'a str },
    /// An existing item.
    ExistingItem { item_key: &'a str },
}

/// A key that was added to a vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddedKey {
    pub item_key: String,
    pub credential_key: String,
    /// Identifier of the credential, stable across renames.
    pub credential_id: Uuid,
    /// Canonical `SHA256:...` fingerprint.
    pub fingerprint: String,
    /// OpenSSH public key line, with the comment.
    pub public_key: String,
}

/// Generate an Ed25519 key and add it to the vault with policy `default`.
pub fn generate(
    vw: &mut VaultHandle,
    target: KeyTarget<'_>,
    comment: &str,
) -> Result<AddedKey, SshKeyError> {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .map_err(|e| SshKeyError::InvalidPrivateKey(e.to_string()))?;
    add_key(vw, target, &key, comment)
}

/// Add the OpenSSH private key `text` to the vault with policy `default`. An
/// encrypted key is decrypted with `passphrase` and stored unencrypted. The
/// comment is `comment`, or the comment of the key if there is none.
pub fn import(
    vw: &mut VaultHandle,
    target: KeyTarget<'_>,
    text: &str,
    passphrase: Option<&SecretString>,
    comment: Option<&str>,
) -> Result<AddedKey, SshKeyError> {
    let key = parse_private_key(text, passphrase)?;
    let comment = comment.unwrap_or_else(|| key.comment());
    add_key(vw, target, &key, comment)
}

/// Parse an OpenSSH private key and decrypt it with `passphrase` if needed.
/// Fails if the public half cannot be derived from the private half.
pub fn parse_private_key(
    text: &str,
    passphrase: Option<&SecretString>,
) -> Result<PrivateKey, SshKeyError> {
    let key = PrivateKey::from_openssh(text.trim())
        .map_err(|e| SshKeyError::InvalidPrivateKey(e.to_string()))?;
    let key = if key.is_encrypted() {
        let passphrase = passphrase
            .map(ExposeSecret::expose_secret)
            .filter(|passphrase| !passphrase.is_empty())
            .ok_or(SshKeyError::PassphraseRequired)?;
        key.decrypt(passphrase).map_err(|e| match e {
            KeyError::Crypto => SshKeyError::WrongPassphrase,
            other => SshKeyError::InvalidPrivateKey(other.to_string()),
        })?
    } else {
        key
    };
    let derived =
        KeyData::try_from(key.key_data()).map_err(|e| SshKeyError::NoPublicKey(e.to_string()))?;
    if derived != *key.public_key().key_data() {
        return Err(SshKeyError::PublicKeyMismatch);
    }
    Ok(key)
}

/// Set the comment of the key in credential `cred_key`. Returns the new public
/// key line.
pub fn set_comment(
    vw: &mut VaultHandle,
    item_key: &str,
    cred_key: &str,
    comment: &str,
) -> Result<String, SshKeyError> {
    let (title, mut record) = read_record(vw, item_key, cred_key)?;
    record.set_comment(comment)?;
    vw.add_secret(
        item_key,
        cred_key,
        &title,
        FieldKind::SshKey,
        record.to_value()?,
    )?;
    Ok(record.public_key.clone())
}

/// OpenSSH public key line of the key in credential `cred_key`.
pub fn public_key_line(
    vw: &VaultHandle,
    item_key: &str,
    cred_key: &str,
) -> Result<String, SshKeyError> {
    let (_, record) = read_record(vw, item_key, cred_key)?;
    Ok(record.public_key.clone())
}

/// OpenSSH private key text of the key in credential `cred_key`, with the
/// record comment. A non-empty `passphrase` encrypts it.
pub fn export_private_key(
    vw: &VaultHandle,
    item_key: &str,
    cred_key: &str,
    passphrase: Option<&SecretString>,
) -> Result<Zeroizing<String>, SshKeyError> {
    let (_, record) = read_record(vw, item_key, cred_key)?;
    let mut key = record.private_key()?;
    key.set_comment(record.comment.as_str());
    let passphrase = passphrase
        .map(ExposeSecret::expose_secret)
        .filter(|passphrase| !passphrase.is_empty());
    let key = match passphrase {
        Some(passphrase) => key
            .encrypt(&mut OsRng, passphrase)
            .map_err(|e| SshKeyError::InvalidPrivateKey(e.to_string()))?,
        None => key,
    };
    key.to_openssh(LineEnding::LF)
        .map_err(|e| SshKeyError::InvalidPrivateKey(e.to_string()))
}

fn read_record(
    vw: &VaultHandle,
    item_key: &str,
    cred_key: &str,
) -> Result<(String, SshKeyRecord), SshKeyError> {
    let overview = vw
        .get_secret_overview(item_key, cred_key)?
        .ok_or_else(|| VaultError::InvalidCredentialKey(cred_key.to_string()))?;
    if overview.kind != FieldKind::SshKey {
        return Err(SshKeyError::NotSshKey(cred_key.to_string()));
    }
    let title = overview.title.clone();
    let value = vw
        .get_secret(item_key, cred_key)?
        .ok_or_else(|| SshKeyError::Malformed("No value".to_string()))?;
    Ok((title, SshKeyRecord::from_value(value.expose_secret())?))
}

fn add_key(
    vw: &mut VaultHandle,
    target: KeyTarget<'_>,
    key: &PrivateKey,
    comment: &str,
) -> Result<AddedKey, SshKeyError> {
    let record = SshKeyRecord::new(key, comment)?;
    let fingerprint = record.fingerprint()?;
    if fingerprints(vw)?.contains(&fingerprint) {
        return Err(SshKeyError::Duplicate { fingerprint });
    }

    let item_key = match target {
        KeyTarget::NewItem { title } => {
            let item_key = unused_item_key(vw, title)?;
            let title = Some(title.trim()).filter(|title| !title.is_empty());
            vw.add_item(&item_key, title.unwrap_or(CREDENTIAL_TITLE))?;
            vw.set_item_category(&item_key, Some(CATEGORY_SSH_KEY.to_string()))?;
            item_key
        },
        KeyTarget::ExistingItem { item_key } => {
            if vw.get_item_overview(item_key)?.is_none() {
                return Err(VaultError::InvalidItemKey(item_key.to_string()).into());
            }
            item_key.to_string()
        },
    };
    let credential_key = unused_credential_key(vw, &item_key)?;
    vw.add_new_secret(
        &item_key,
        &credential_key,
        CREDENTIAL_TITLE,
        FieldKind::SshKey,
        record.to_value()?,
    )?;
    let credential_id = vw
        .get_secret_overview(&item_key, &credential_key)?
        .map(|credential| credential.id)
        .ok_or_else(|| VaultError::InvalidCredentialKey(credential_key.clone()))?;
    Ok(AddedKey {
        item_key,
        credential_key,
        credential_id,
        fingerprint,
        public_key: record.public_key.clone(),
    })
}

/// Fingerprints of the SSH keys in the vault. A credential that does not hold a
/// readable key is skipped.
fn fingerprints(vw: &VaultHandle) -> Result<HashSet<String>, SshKeyError> {
    let mut found = HashSet::new();
    for item in vw.list_items()? {
        for credential in item.credentials.values() {
            if credential.kind != FieldKind::SshKey {
                continue;
            }
            let Some(value) = vw.get_secret(&item.key, &credential.key)? else {
                continue;
            };
            if let Ok(fingerprint) =
                SshKeyRecord::from_value(value.expose_secret()).and_then(|r| r.fingerprint())
            {
                found.insert(fingerprint);
            }
        }
    }
    Ok(found)
}

/// Item key from `title`, with a numeric suffix if the key is taken.
fn unused_item_key(vw: &VaultHandle, title: &str) -> Result<String, SshKeyError> {
    let base = normalized_key(title).unwrap_or_else(|| FALLBACK_ITEM_KEY.to_string());
    let mut key = base.clone();
    let mut n = 2;
    while vw.get_item_overview(&key)?.is_some() {
        key = format!("{base}-{n}");
        n += 1;
    }
    Ok(key)
}

fn unused_credential_key(vw: &VaultHandle, item_key: &str) -> Result<String, SshKeyError> {
    let mut key = CREDENTIAL_KEY.to_string();
    let mut n = 2;
    while vw.get_secret_overview(item_key, &key)?.is_some() {
        key = format!("{CREDENTIAL_KEY}-{n}");
        n += 1;
    }
    Ok(key)
}

#[cfg(test)]
mod tests;
