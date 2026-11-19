//! `device-signing-key` in the macOS keychain.

use p256::ecdsa::VerifyingKey;

use super::{DEVICE_SIGNING_KEY_LABEL, DEVICE_VERIFYING_KEY, KeychainSigner, VaultSigner};
use crate::core::auth::run_local_onetime;
use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::keychain_query::KeychainQuery;
use crate::secrets::keychain::managed_key::{KeyClass, ManagedKey, ManagedKeyQuery};
use crate::secrets::vaults::errors::Error;

impl KeychainSigner {
    /// Look for `device-signing-key` with interaction not allowed. A key gated
    /// by authentication fails with `ItemNotAccessible`.
    pub(crate) fn probe_key() -> Result<Option<ManagedKey>, KeychainError> {
        run_local_onetime(|la_context| {
            ManagedKeyQuery::build()
                .with_label(DEVICE_SIGNING_KEY_LABEL)
                .with_key_class(KeyClass::Private)
                .one_with_retry(la_context, false)
        })
    }

    /// Create `device-signing-key` and clear the cached public key, so the
    /// next verification in this process reads the new key. The caller checks
    /// that the key is missing, as `ensure_device_keys` and the re-sign do.
    pub(crate) fn create_key() -> Result<(), Error> {
        log::debug!("Creating the device signing key");
        let created = ManagedKey::create_device_key(DEVICE_SIGNING_KEY_LABEL)
            .map(|_| ())
            .map_err(Error::KeyCreationFailed);
        DEVICE_VERIFYING_KEY.clear();
        created
    }

    /// Read `device-signing-key`. The key never prompts.
    fn find_key() -> Result<Option<ManagedKey>, Error> {
        run_local_onetime(|la_context| {
            ManagedKeyQuery::build()
                .with_label(DEVICE_SIGNING_KEY_LABEL)
                .with_key_class(KeyClass::Private)
                .one(la_context)
        })
        .map_err(Error::KeyRetrievalFailed)
    }

    /// Public key of a managed P-256 key.
    fn verifying_key_of(key: &ManagedKey) -> Result<VerifyingKey, Error> {
        let sec1 = key.public_key_sec1().map_err(Error::KeyRetrievalFailed)?;
        VerifyingKey::from_sec1_bytes(&sec1).map_err(|e| {
            Error::KeyRetrievalFailed(KeychainError::PublicKeyUnavailable(e.to_string()))
        })
    }
}

impl VaultSigner for KeychainSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let key = Self::find_key()?.ok_or(Error::SigningKeyNotFound)?;
        key.sign(message)
            .map_err(|e| Error::VaultSigningFailed(e.to_string()))
    }

    fn verifying_key(&self) -> Result<VerifyingKey, Error> {
        DEVICE_VERIFYING_KEY.get_or_load(|| {
            let key = Self::find_key()?.ok_or(Error::SigningKeyNotFound)?;
            Self::verifying_key_of(&key)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::vaults::format::signing::verify;

    const MESSAGE: &[u8] = b"ap-vault-v2:{\"id\":\"vault\"}";

    /// Needs a binary signed with the app's keychain access group.
    #[test]
    #[ignore = "creates a Secure Enclave key in the keychain"]
    fn secure_enclave_signature_verifies() {
        let label = format!("test-device-signing-key-{}", uuid::Uuid::new_v4().simple());
        let key = ManagedKey::create_device_key(&label).unwrap();
        let result = key
            .sign(MESSAGE)
            .map_err(|e| Error::VaultSigningFailed(e.to_string()))
            .and_then(|signature| {
                verify(
                    &KeychainSigner::verifying_key_of(&key)?,
                    MESSAGE,
                    &signature,
                )
            });
        key.delete().unwrap();
        result.unwrap();
    }
}
