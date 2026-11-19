//! Vault file signatures by the per-Mac `device-signing-key`.
//!
//! Signatures are ECDSA P-256 over the SHA-256 digest of the message, DER
//! encoded. This is the form [`ManagedKey::sign`] returns. [`verify`] checks a
//! signature with the `p256` crate and makes no keychain call.

#[cfg(secure_enclave)]
mod apple;
#[cfg(linux)]
mod linux;
#[cfg(sim_keys)]
mod sim;

use std::fmt;
use std::sync::RwLock;

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};

use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::vaults::errors::Error;

/// Keychain label of the per-Mac signing key.
pub const DEVICE_SIGNING_KEY_LABEL: &str = "device-signing-key";

/// Public key of `device-signing-key`, read once per process and cleared when
/// the key is created.
static DEVICE_VERIFYING_KEY: VerifyingKeyCache = VerifyingKeyCache::new();

/// Cached public key. A cleared cache reads the key again.
pub(crate) struct VerifyingKeyCache(RwLock<Option<VerifyingKey>>);

impl VerifyingKeyCache {
    pub(crate) const fn new() -> Self {
        Self(RwLock::new(None))
    }

    /// Cached key, or the key from `load`, which is then cached. An error from
    /// `load` caches nothing.
    pub(crate) fn get_or_load(
        &self,
        load: impl FnOnce() -> Result<VerifyingKey, Error>,
    ) -> Result<VerifyingKey, Error> {
        if let Some(key) = *self.0.read().unwrap_or_else(|e| e.into_inner()) {
            return Ok(key);
        }
        let mut cached = self.0.write().unwrap_or_else(|e| e.into_inner());
        if let Some(key) = *cached {
            return Ok(key);
        }
        let key = load()?;
        *cached = Some(key);
        Ok(key)
    }

    /// Drop the cached key.
    pub(crate) fn clear(&self) {
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

impl KeychainSigner {
    /// Delete `device-signing-key` and the cached public key. A missing key is
    /// not an error.
    pub(crate) fn delete_key() -> Result<(), KeychainError> {
        let deleted = ManagedKey::delete_by_label(DEVICE_SIGNING_KEY_LABEL);
        DEVICE_VERIFYING_KEY.clear();
        deleted
    }
}

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

/// In-memory signer for tests. Its signatures have the form of
/// [`KeychainSigner`] signatures, and are randomized as Secure Enclave
/// signatures are, so two signatures of one message differ.
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
        Self::seeded(7)
    }

    /// Signer with the fixed key of every byte `seed`. Two signers of one
    /// seed hold the same key.
    pub fn seeded(seed: u8) -> Self {
        let key = p256::ecdsa::SigningKey::from_bytes(&[seed; 32].into())
            .expect("fixed test key is a valid scalar");
        Self(key)
    }
}

#[cfg(test)]
impl VaultSigner for TestSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        use p256::ecdsa::signature::RandomizedSigner;
        let signature: Signature = self.0.sign_with_rng(&mut aes_gcm::aead::OsRng, message);
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
    fn signatures_of_one_message_differ() {
        let signer = TestSigner::device();
        assert_ne!(signer.sign(MESSAGE).unwrap(), signer.sign(MESSAGE).unwrap());
    }

    #[test]
    fn signature_not_der_fails() {
        let signer = TestSigner::random();
        let key = signer.verifying_key().unwrap();
        assert!(matches!(
            verify(&key, MESSAGE, &[0u8; 64]),
            Err(Error::VaultSignatureInvalid)
        ));
    }

    #[test]
    fn cleared_cache_verifies_with_new_key() {
        let cache = VerifyingKeyCache::new();
        let old = TestSigner::seeded(1);
        let new = TestSigner::seeded(2);
        let load = |signer: &TestSigner| signer.verifying_key();

        assert_eq!(
            cache.get_or_load(|| load(&old)).unwrap(),
            load(&old).unwrap()
        );
        assert_eq!(
            cache.get_or_load(|| load(&new)).unwrap(),
            load(&old).unwrap(),
            "the cached key is kept until cleared"
        );
        cache.clear();
        let key = cache.get_or_load(|| load(&new)).unwrap();

        assert_eq!(key, load(&new).unwrap());
        let signature = new.sign(MESSAGE).unwrap();
        verify(&key, MESSAGE, &signature).unwrap();
    }

    #[test]
    fn failed_load_caches_nothing() {
        let cache = VerifyingKeyCache::new();
        let signer = TestSigner::seeded(3);

        assert!(matches!(
            cache.get_or_load(|| Err(Error::SigningKeyNotFound)),
            Err(Error::SigningKeyNotFound)
        ));
        let key = cache.get_or_load(|| signer.verifying_key()).unwrap();

        assert_eq!(key, signer.verifying_key().unwrap());
    }
}
