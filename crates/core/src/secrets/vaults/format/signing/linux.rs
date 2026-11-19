//! Linux stub of the device signing key. Every operation fails with
//! `Unsupported`. The TPM and software signers replace it.

use p256::ecdsa::VerifyingKey;

use super::{DEVICE_VERIFYING_KEY, KeychainSigner, VaultSigner};
use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::vaults::errors::Error;

impl KeychainSigner {
    pub(crate) fn probe_key() -> Result<Option<ManagedKey>, KeychainError> {
        Err(KeychainError::Unsupported)
    }

    pub(crate) fn create_key() -> Result<(), Error> {
        DEVICE_VERIFYING_KEY.clear();
        Err(Error::KeyCreationFailed(KeychainError::Unsupported))
    }
}

impl VaultSigner for KeychainSigner {
    fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, Error> {
        Err(Error::VaultSigningFailed(
            KeychainError::Unsupported.to_string(),
        ))
    }

    fn verifying_key(&self) -> Result<VerifyingKey, Error> {
        DEVICE_VERIFYING_KEY
            .get_or_load(|| Err(Error::KeyRetrievalFailed(KeychainError::Unsupported)))
    }
}
