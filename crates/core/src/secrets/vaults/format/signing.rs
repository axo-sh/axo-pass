//! Vault file signatures by the per-Mac `device-signing-key`.
//!
//! Signatures are ECDSA P-256 over the SHA-256 digest of the message, DER
//! encoded. This is the form [`ManagedKey::sign`] returns. [`verify`] checks a
//! signature with the `p256` crate and makes no keychain call.

use std::fmt;
use std::sync::OnceLock;

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};

use crate::core::auth::run_local_onetime;
use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::keychain_query::KeychainQuery;
use crate::secrets::keychain::managed_key::{KeyClass, ManagedKey, ManagedKeyQuery};
use crate::secrets::vaults::errors::Error;

/// Keychain label of the per-Mac signing key.
pub const DEVICE_SIGNING_KEY_LABEL: &str = "device-signing-key";

/// Public key of `device-signing-key`, read once per process.
static DEVICE_VERIFYING_KEY: OnceLock<VerifyingKey> = OnceLock::new();

/// Signs vault files.
pub trait VaultSigner: Send + Sync {
    /// Sign `message`. Returns a DER encoded ECDSA P-256 SHA-256 signature.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error>;

    /// Public key that verifies the signatures of [`Self::sign`].
    fn verifying_key(&self) -> Result<VerifyingKey, Error>;
}

impl fmt::Debug for dyn VaultSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultSigner")
    }
}

/// Check a DER encoded signature of `message` under `key`.
pub fn verify(key: &VerifyingKey, message: &[u8], signature: &[u8]) -> Result<(), Error> {
    let signature = Signature::from_der(signature).map_err(|_| Error::VaultSignatureInvalid)?;
    key.verify(message, &signature)
        .map_err(|_| Error::VaultSignatureInvalid)
}

/// Signer with `device-signing-key` in the keychain. Construction makes no
/// keychain call. The key is read on each signature, and the public key is
/// cached for the process.
#[derive(Debug, Default)]
pub struct KeychainSigner;

impl KeychainSigner {
    /// Create `device-signing-key` if it is missing.
    pub fn ensure_key() -> Result<(), Error> {
        if Self::find_key()?.is_none() {
            log::debug!("Device signing key not found, creating it");
            ManagedKey::create_device_key(DEVICE_SIGNING_KEY_LABEL)
                .map_err(Error::KeyCreationFailed)?;
        }
        Ok(())
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
        if let Some(key) = DEVICE_VERIFYING_KEY.get() {
            return Ok(*key);
        }
        let key = Self::find_key()?.ok_or(Error::SigningKeyNotFound)?;
        let key = Self::verifying_key_of(&key)?;
        Ok(*DEVICE_VERIFYING_KEY.get_or_init(|| key))
    }
}

/// In-memory signer for tests. Its signatures have the form of
/// [`KeychainSigner`] signatures.
#[cfg(test)]
pub struct TestSigner(p256::ecdsa::SigningKey);

#[cfg(test)]
impl TestSigner {
    /// Signer with a new random key.
    pub fn random() -> Self {
        Self(p256::ecdsa::SigningKey::random(&mut aes_gcm::aead::OsRng))
    }

    /// Signer with one fixed key, used as the device key of every test writer.
    pub fn device() -> Self {
        let key = p256::ecdsa::SigningKey::from_bytes(&[7u8; 32].into())
            .expect("fixed test key is a valid scalar");
        Self(key)
    }
}

#[cfg(test)]
impl VaultSigner for TestSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        use p256::ecdsa::signature::Signer;
        let signature: Signature = self.0.sign(message);
        Ok(signature.to_der().as_bytes().to_vec())
    }

    fn verifying_key(&self) -> Result<VerifyingKey, Error> {
        Ok(*self.0.verifying_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE: &[u8] = b"ap-vault-v2:{\"id\":\"vault\"}";

    #[test]
    fn signature_verifies_under_its_key() {
        let signer = TestSigner::random();
        let signature = signer.sign(MESSAGE).unwrap();
        verify(&signer.verifying_key().unwrap(), MESSAGE, &signature).unwrap();
    }

    #[test]
    fn signature_fails_under_another_key() {
        let signature = TestSigner::random().sign(MESSAGE).unwrap();
        let other = TestSigner::random().verifying_key().unwrap();
        assert!(matches!(
            verify(&other, MESSAGE, &signature),
            Err(Error::VaultSignatureInvalid)
        ));
    }

    #[test]
    fn signature_fails_over_changed_bytes() {
        let signer = TestSigner::random();
        let signature = signer.sign(MESSAGE).unwrap();
        let mut changed = MESSAGE.to_vec();
        changed[0] ^= 1;
        assert!(matches!(
            verify(&signer.verifying_key().unwrap(), &changed, &signature),
            Err(Error::VaultSignatureInvalid)
        ));
    }

    #[test]
    fn der_signature_in_secure_enclave_form_verifies() {
        let signer = TestSigner::device();
        let signature = signer.sign(MESSAGE).unwrap();
        // X9.62 DER is a SEQUENCE of two INTEGERs, r and s.
        assert_eq!(signature[0], 0x30);
        assert_eq!(usize::from(signature[1]), signature.len() - 2);
        verify(&signer.verifying_key().unwrap(), MESSAGE, &signature).unwrap();
    }

    #[test]
    fn signature_that_is_not_der_fails() {
        let signer = TestSigner::random();
        let key = signer.verifying_key().unwrap();
        assert!(matches!(
            verify(&key, MESSAGE, &[0u8; 64]),
            Err(Error::VaultSignatureInvalid)
        ));
    }

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
