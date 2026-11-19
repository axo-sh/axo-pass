//! P-256 device keys in files of the data directory, for simulator builds.
//!
//! The simulator has no Secure Enclave. A key is the 32 byte scalar in
//! `simulator-keys/{label}.key`, with mode 0600. The public key and the
//! signatures have the same SEC1 and DER forms as Secure Enclave keys.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;

use p256::SecretKey;

use crate::core::dirs::try_app_data_dir;
use crate::secrets::keychain::errors::KeychainError;

/// Directory of the key files under the data directory.
const KEYS_DIR: &str = "simulator-keys";

/// Key files of the simulator.
pub struct SoftwareKeys;

impl SoftwareKeys {
    /// Whether the key `label` exists.
    pub fn exists(label: &str) -> Result<bool, KeychainError> {
        Ok(Self::load(label)?.is_some())
    }

    /// The key `label`, or `None` if it does not exist.
    pub fn load(label: &str) -> Result<Option<SecretKey>, KeychainError> {
        let bytes = match fs::read(Self::path(label)?) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(anyhow::Error::from(e).into()),
        };
        SecretKey::from_slice(&bytes)
            .map(Some)
            .map_err(|e| anyhow::anyhow!("key file of {label} is invalid: {e}").into())
    }

    /// Create the key `label`. Fails if it exists.
    pub fn create(label: &str) -> Result<SecretKey, KeychainError> {
        let path = Self::path(label)?;
        let key = SecretKey::random(&mut aes_gcm::aead::OsRng);
        let write = || -> io::Result<()> {
            if let Some(dir) = path.parent() {
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(dir)?;
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            file.write_all(&key.to_bytes())?;
            file.sync_all()
        };
        write().map_err(|e| KeychainError::AddFailed(e.to_string()))?;
        Ok(key)
    }

    fn path(label: &str) -> Result<PathBuf, KeychainError> {
        let dir = try_app_data_dir().map_err(anyhow::Error::from)?;
        Ok(dir.join(KEYS_DIR).join(format!("{label}.key")))
    }
}
