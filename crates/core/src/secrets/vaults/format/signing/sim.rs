//! `device-signing-key` in software, for simulator builds.
//!
//! The key is a P-256 key in a file of the data directory. Signatures are
//! randomized DER ECDSA SHA-256, the form of a Secure Enclave signature.

use p256::ecdsa::signature::RandomizedSigner;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

use super::{DEVICE_SIGNING_KEY_LABEL, DEVICE_VERIFYING_KEY, KeychainSigner, VaultSigner};
use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::keychain::software_keys::SoftwareKeys;
use crate::secrets::vaults::errors::Error;

impl KeychainSigner {
    /// Look for `device-signing-key`.
    pub(crate) fn probe_key() -> Result<Option<ManagedKey>, KeychainError> {
        SoftwareKeys::load(DEVICE_SIGNING_KEY_LABEL)?
            .map(|secret| {
                ManagedKey::from_secret(Some(DEVICE_SIGNING_KEY_LABEL.to_string()), &secret)
            })
            .transpose()
    }

    /// Create `device-signing-key` and clear the cached public key, so the
    /// next verification in this process reads the new key. The caller checks
    /// that the key is missing.
    pub(crate) fn create_key() -> Result<(), Error> {
        log::debug!("Creating the software device signing key");
        let created = SoftwareKeys::create(DEVICE_SIGNING_KEY_LABEL)
            .map(|_| ())
            .map_err(Error::KeyCreationFailed);
        DEVICE_VERIFYING_KEY.clear();
        created
    }

    /// Read `device-signing-key`.
    fn find_key() -> Result<SigningKey, Error> {
        SoftwareKeys::load(DEVICE_SIGNING_KEY_LABEL)
            .map_err(Error::KeyRetrievalFailed)?
            .map(SigningKey::from)
            .ok_or(Error::SigningKeyNotFound)
    }
}

impl VaultSigner for KeychainSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let key = Self::find_key()?;
        let signature: Signature = key
            .try_sign_with_rng(&mut aes_gcm::aead::OsRng, message)
            .map_err(|e| Error::VaultSigningFailed(e.to_string()))?;
        Ok(signature.to_der().as_bytes().to_vec())
    }

    fn verifying_key(&self) -> Result<VerifyingKey, Error> {
        DEVICE_VERIFYING_KEY.get_or_load(|| Ok(*Self::find_key()?.verifying_key()))
    }
}
