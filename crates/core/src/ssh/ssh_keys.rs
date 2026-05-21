use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail};
use serde::{Deserialize, Serialize};
use ssh_key::{Algorithm, PrivateKey, PublicKey};
use typeshare::typeshare;

use crate::secrets::keychain::generic_password::PasswordEntry;
use crate::ssh::utils::{compute_md5_fingerprint, compute_sha256_fingerprint, ssh_dir_path};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub enum SshKeyType {
    Rsa,
    Ed25519,
    Ecdsa, // Managed keys are always this type
    Dsa,
    Unknown,
}

impl From<Algorithm> for SshKeyType {
    fn from(algorithm: Algorithm) -> Self {
        match algorithm {
            Algorithm::Rsa { .. } => SshKeyType::Rsa,
            Algorithm::Ed25519 => SshKeyType::Ed25519,
            Algorithm::Ecdsa { .. } => SshKeyType::Ecdsa,
            Algorithm::Dsa => SshKeyType::Dsa,
            _ => SshKeyType::Unknown,
        }
    }
}

pub struct SystemSshKey {
    pub name: String,
    pub path: PathBuf,
    pub public_key: PublicKey,
    pub public_key_path: Option<PathBuf>,
    pub comment: String,
    pub key_type: SshKeyType,
    pub fingerprint_sha256: String,
    pub fingerprint_md5: String,
}

impl SystemSshKey {
    pub fn load_from_user_ssh_dir() -> anyhow::Result<Vec<SystemSshKey>> {
        let ssh_dir = ssh_dir_path()
            .inspect_err(|e| log::error!("Failed to get SSH directory: {e}"))
            .unwrap_or_default();
        Self::load_from_dir(&ssh_dir)
    }

    pub fn load_from_dir(dir: &Path) -> anyhow::Result<Vec<SystemSshKey>> {
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut keys = Vec::new();
        let entries =
            fs::read_dir(dir).map_err(|e| anyhow!("Failed to read .ssh directory: {e}"))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let file_name = match path.file_name().and_then(|n| n.to_str()) {
                Some(name) => name.to_string(),
                None => continue,
            };

            // Skip common file types
            if file_name.ends_with(".pub")
                || file_name == "config"
                || file_name == "known_hosts"
                || file_name == "known_hosts.old"
                || file_name == "authorized_keys"
            {
                continue;
            }
            match Self::load_from_path(&path) {
                Ok(ssh_key) => keys.push(ssh_key),
                Err(err) => log::warn!("Failed to parse {}: {err:#?}", path.display()),
            }
        }

        Ok(keys)
    }

    // Given a private key path, try to get information about the SSH key. We
    // attempt to read the public key file first, then fall back to parsing the
    // private key. The latter only works for unencrypted keys.
    // Note: Only OpenSSH private key formats are supported for now (since we rely
    // on ssh-keys for parsing)
    fn load_from_path(path: &Path) -> anyhow::Result<SystemSshKey> {
        // Try to read the corresponding public key file first (most reliable)
        let public_key_path = path.with_extension("pub");
        let public_key = if public_key_path.exists()
            && let Ok(pubkey) = PublicKey::read_openssh_file(&public_key_path)
                .inspect_err(|e| log::warn!("Error reading public key file: {e}"))
        {
            pubkey
        } else {
            // Fall back to parsing the private key (only works for unencrypted keys)
            let privkey = PrivateKey::read_openssh_file(path)
                .map_err(|e| anyhow!("Failed to read private key file: {e}"))?;
            if privkey.is_encrypted() {
                bail!("Private key {} is encrypted; skipping", path.display());
            }
            privkey.public_key().clone()
        };

        Ok(SystemSshKey {
            name: path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string(),
            path: path.to_path_buf(),
            public_key_path: if public_key_path.exists() {
                Some(public_key_path)
            } else {
                None
            },
            comment: public_key.comment().to_string(),
            key_type: public_key.algorithm().into(),
            fingerprint_sha256: compute_sha256_fingerprint(public_key.key_data()),
            fingerprint_md5: compute_md5_fingerprint(public_key.key_data()),
            public_key,
        })
    }

    pub fn has_saved_password(&self) -> bool {
        PasswordEntry::ssh(&self.fingerprint_sha256)
            .exists()
            .unwrap_or(false)
    }
}
