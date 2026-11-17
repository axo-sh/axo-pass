//! SSH private keys stored as vault credentials.
//!
//! One key is one credential of kind [`FieldKind::SshKey`](super::FieldKind),
//! whose value is a JSON [`SshKeyRecord`]: the unencrypted OpenSSH private key,
//! the public key line, the comment, and the key policy. The vault encrypts the
//! value with the rest of the vault, and it travels in export bundles.
//!
//! The broker signs with the key inside the app (`app_broker/ssh.rs`). The
//! private key never leaves the app.
//!
//! [`ops`] generates, imports, and edits keys in an unlocked vault.

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use ssh_key::{HashAlg, LineEnding, PrivateKey, PublicKey};
use thiserror::Error;
use zeroize::Zeroize;

use crate::secrets::keychain::managed_key::KeyPolicy;
use crate::secrets::vaults::Error as VaultError;

pub mod ops;

#[derive(Debug, Error)]
pub enum SshKeyError {
    #[error("Malformed SSH key record: {0}")]
    Malformed(String),

    #[error("Invalid SSH private key: {0}")]
    InvalidPrivateKey(String),

    #[error("Invalid SSH public key: {0}")]
    InvalidPublicKey(String),

    #[error("The SSH private key is encrypted")]
    Encrypted,

    #[error("The stored public key does not belong to the private key")]
    PublicKeyMismatch,

    #[error("The stored key has fingerprint {actual}, not {requested}")]
    FingerprintMismatch { requested: String, actual: String },

    #[error("The SSH private key is encrypted and needs a passphrase")]
    PassphraseRequired,

    #[error("The passphrase does not decrypt the SSH private key")]
    WrongPassphrase,

    #[error("Cannot derive a public key from the SSH private key: {0}")]
    NoPublicKey(String),

    #[error("This vault already holds the SSH key {fingerprint}")]
    Duplicate { fingerprint: String },

    #[error("The credential {0} is not an SSH key")]
    NotSshKey(String),

    #[error(transparent)]
    Vault(#[from] VaultError),
}

/// The value of an SSH key credential.
///
/// The private key is unencrypted OpenSSH text. It is zeroized on drop and
/// left out of the `Debug` output.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SshKeyRecord {
    /// OpenSSH private key, unencrypted.
    pub private_key: String,

    /// OpenSSH public key line.
    pub public_key: String,

    /// Key comment.
    #[serde(default)]
    pub comment: String,

    /// How use of the key is authorized. New and imported keys use `default`.
    #[serde(default = "default_policy")]
    pub policy: KeyPolicy,
}

fn default_policy() -> KeyPolicy {
    KeyPolicy::Default
}

impl std::fmt::Debug for SshKeyRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshKeyRecord")
            .field("public_key", &self.public_key)
            .field("comment", &self.comment)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl Drop for SshKeyRecord {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl SshKeyRecord {
    /// Record for an unencrypted `key`, with the policy `default`.
    pub fn new(key: &PrivateKey, comment: &str) -> Result<Self, SshKeyError> {
        if key.is_encrypted() {
            return Err(SshKeyError::Encrypted);
        }
        let private_key = key
            .to_openssh(LineEnding::LF)
            .map_err(|e| SshKeyError::InvalidPrivateKey(e.to_string()))?;
        let public_key = PublicKey::new(key.public_key().key_data().clone(), comment)
            .to_openssh()
            .map_err(|e| SshKeyError::InvalidPublicKey(e.to_string()))?;
        Ok(Self {
            private_key: private_key.to_string(),
            public_key,
            comment: comment.to_string(),
            policy: KeyPolicy::Default,
        })
    }

    /// Set the comment, in the record and in the public key line.
    pub fn set_comment(&mut self, comment: &str) -> Result<(), SshKeyError> {
        let public = self.parsed_public_key()?;
        self.public_key = PublicKey::new(public.key_data().clone(), comment)
            .to_openssh()
            .map_err(|e| SshKeyError::InvalidPublicKey(e.to_string()))?;
        self.comment = comment.to_string();
        Ok(())
    }

    /// Parse a credential value.
    pub fn from_value(value: &str) -> Result<Self, SshKeyError> {
        serde_json::from_str(value).map_err(|e| SshKeyError::Malformed(e.to_string()))
    }

    /// The credential value.
    pub fn to_value(&self) -> Result<SecretString, SshKeyError> {
        serde_json::to_string(self)
            .map(SecretString::from)
            .map_err(|e| SshKeyError::Malformed(e.to_string()))
    }

    /// Canonical `SHA256:...` fingerprint of the stored public key.
    pub fn fingerprint(&self) -> Result<String, SshKeyError> {
        Ok(self
            .parsed_public_key()?
            .fingerprint(HashAlg::Sha256)
            .to_string())
    }

    /// The private key, after checking that the stored public key belongs to
    /// it.
    pub fn private_key(&self) -> Result<PrivateKey, SshKeyError> {
        let key = PrivateKey::from_openssh(&self.private_key)
            .map_err(|e| SshKeyError::InvalidPrivateKey(e.to_string()))?;
        if key.is_encrypted() {
            return Err(SshKeyError::Encrypted);
        }
        if key.public_key().key_data() != self.parsed_public_key()?.key_data() {
            return Err(SshKeyError::PublicKeyMismatch);
        }
        Ok(key)
    }

    /// The private key, after checking that its fingerprint is `fingerprint`.
    pub fn private_key_for(&self, fingerprint: &str) -> Result<PrivateKey, SshKeyError> {
        let actual = self.fingerprint()?;
        if actual != fingerprint {
            return Err(SshKeyError::FingerprintMismatch {
                requested: fingerprint.to_string(),
                actual,
            });
        }
        self.private_key()
    }

    fn parsed_public_key(&self) -> Result<PublicKey, SshKeyError> {
        PublicKey::from_openssh(&self.public_key)
            .map_err(|e| SshKeyError::InvalidPublicKey(e.to_string()))
    }
}

#[cfg(test)]
mod tests;
