//! Sync keys of one vault and the keys derived from them.
//!
//! A sync key is 32 random bytes shared by every Mac that syncs the vault.
//! Each key has a [`KeyId`]. A rotation adds a key under the next id. The
//! state key that encrypts sync state bodies is derived from the sync key and
//! the vault id. The fingerprint names a key in file headers and recovery
//! kits.
//!
//! Each Mac stores its keys as a list of [`WrappedSyncKey`], each wrapped to
//! `vault-encryption-key` with [`ManagedKey::encrypt`], the scheme of the
//! vault file key.

use std::fmt;

use aes_gcm::aead::{Aead, AeadCore, OsRng, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
#[cfg(test)]
use base64::Engine;
#[cfg(test)]
use base64::engine::general_purpose::STANDARD as B64;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::{ZeroizeOnDrop, Zeroizing};

#[cfg(test)]
use super::model::PublicKey;
use super::model::{ByteString, KeyId};
use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::vaults::errors::Error;

/// HKDF info of the key fingerprint.
const FINGERPRINT_INFO: &[u8] = b"ap-key-fingerprint-v1";

/// HKDF info of the state key.
const STATE_KEY_INFO: &[u8] = b"ap-state-key-v1";

/// Sync key: 32 random bytes. Zeroized on drop. `Debug` shows no bytes.
#[derive(Clone)]
pub struct SyncKey(Zeroizing<[u8; 32]>);

impl SyncKey {
    /// New random key.
    pub fn generate() -> Self {
        let random = Zeroizing::new(Aes256Gcm::generate_key(OsRng));
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(&random);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Key of the unwrapped bytes `bytes`. Fails if `bytes` is not 32 bytes.
    pub(crate) fn from_slice(bytes: &[u8]) -> Option<Self> {
        let mut key = Zeroizing::new([0u8; 32]);
        if bytes.len() != key.len() {
            return None;
        }
        key.copy_from_slice(bytes);
        Some(Self(key))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// `HKDF-SHA-256(sync_key, info = "ap-key-fingerprint-v1")`,
    /// truncated to 16 bytes. No salt.
    pub fn fingerprint(&self) -> KeyFingerprint {
        let mut fingerprint = [0u8; 16];
        Hkdf::<Sha256>::new(None, self.as_bytes())
            .expand(FINGERPRINT_INFO, &mut fingerprint)
            .expect("16 bytes is a valid HKDF-SHA-256 output length");
        KeyFingerprint(fingerprint)
    }

    /// State key of vault `vault_id`:
    /// `HKDF-SHA-256(sync_key, salt = vault_id, info = "ap-state-key-v1")`.
    /// The salt is the 16 bytes of the vault id.
    pub fn state_key(&self, vault_id: Uuid) -> StateKey {
        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(vault_id.as_bytes()), self.as_bytes())
            .expand(STATE_KEY_INFO, key.as_mut())
            .expect("32 bytes is a valid HKDF-SHA-256 output length");
        StateKey(key)
    }
}

impl fmt::Debug for SyncKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SyncKey(..)")
    }
}

/// The only field is `Zeroizing`, which zeroizes the bytes on drop.
impl ZeroizeOnDrop for SyncKey {}

/// Fingerprint of a sync key. Fingerprints are equal only if all 16 bytes
/// are equal. The serde form is a byte string, or base64 in JSON.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyFingerprint(#[serde(with = "ByteString")] pub [u8; 16]);

impl KeyFingerprint {
    /// Fingerprint in lowercase hex, as state file AADs hold it.
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

/// AES-256-GCM key for vault sync state.
pub struct StateKey(Zeroizing<[u8; 32]>);

impl StateKey {
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new(self.as_bytes().into())
    }

    /// Fresh random nonce and the ciphertext of `plaintext` under `aad`.
    /// Fails only for a plaintext above the AES-GCM limit.
    pub(crate) fn encrypt(&self, aad: &[u8], plaintext: &[u8]) -> Option<([u8; 12], Vec<u8>)> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher()
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .ok()?;
        Some((nonce.into(), ciphertext))
    }

    /// Plaintext of `ciphertext` under `nonce` and `aad`. Fails if the tag
    /// does not verify.
    pub(crate) fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Option<Zeroizing<Vec<u8>>> {
        self.cipher()
            .decrypt(
                nonce.into(),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .ok()
            .map(Zeroizing::new)
    }
}

impl fmt::Debug for StateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StateKey(..)")
    }
}

/// Zeroizes the bytes on drop.
impl ZeroizeOnDrop for StateKey {}

/// Unwrapped sync keys for a vault. Key ids are unique.
#[derive(Clone, Debug, Default)]
pub struct SyncKeyring {
    keys: Vec<(KeyId, SyncKey)>,
}

impl SyncKeyring {
    /// Keyring of `keys`. Fails if two keys share a key id.
    pub fn new(keys: Vec<(KeyId, SyncKey)>) -> Result<Self, Error> {
        for (index, (key_id, _)) in keys.iter().enumerate() {
            if keys[..index].iter().any(|(other, _)| other == key_id) {
                return Err(Error::DuplicateSyncKeyId(key_id.0));
            }
        }
        Ok(Self { keys })
    }

    pub fn keys(&self) -> &[(KeyId, SyncKey)] {
        &self.keys
    }

    /// Key with id `key_id`.
    pub fn get(&self, key_id: KeyId) -> Option<&SyncKey> {
        self.keys
            .iter()
            .find(|(id, _)| *id == key_id)
            .map(|(_, key)| key)
    }

    /// Key with id `key_id`, if its fingerprint equals `fingerprint` in all 16
    /// bytes. A key with another fingerprint under the same id is a different
    /// key.
    pub fn find(&self, key_id: KeyId, fingerprint: &KeyFingerprint) -> Option<&SyncKey> {
        self.get(key_id)
            .filter(|key| key.fingerprint() == *fingerprint)
    }

    /// Stored form of the keys, in keyring order, each wrapped by `wrapper`.
    pub fn wrap(&self, wrapper: &impl SyncKeyWrapper) -> Result<Vec<WrappedSyncKey>, Error> {
        self.keys
            .iter()
            .map(|(key_id, key)| {
                let wrapped = wrapper
                    .wrap(key.as_bytes())
                    .ok_or(Error::SyncKeyEncryptionError(key_id.0))?;
                Ok(WrappedSyncKey {
                    key_id: *key_id,
                    wrapped,
                })
            })
            .collect()
    }

    /// Keyring of the stored keys `wrapped`, each unwrapped by `wrapper`. Fails
    /// if a key does not unwrap to 32 bytes, or if two keys share a key id.
    pub fn unwrap(
        wrapped: &[WrappedSyncKey],
        wrapper: &impl SyncKeyWrapper,
    ) -> Result<Self, Error> {
        let keys = wrapped
            .iter()
            .map(|entry| {
                let error = || Error::SyncKeyDecryptionError(entry.key_id.0);
                let raw = wrapper.unwrap(entry.wrapped.as_bytes()).ok_or_else(error)?;
                let bytes: [u8; 32] = raw.as_slice().try_into().map_err(|_| error())?;
                Ok((entry.key_id, SyncKey::from_bytes(bytes)))
            })
            .collect::<Result<_, Error>>()?;
        Self::new(keys)
    }
}

/// One stored sync key: its key id and the key wrapped to
/// `vault-encryption-key`. The wrapped key is the base64 string that
/// [`ManagedKey::encrypt`] returns.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedSyncKey {
    pub key_id: KeyId,
    pub wrapped: String,
}

/// Wrapping of raw sync keys for storage on this Mac.
pub trait SyncKeyWrapper {
    /// Wrapped form of `raw`, as a base64 string.
    fn wrap(&self, raw: &[u8]) -> Option<String>;

    /// Raw key of the base64 string `wrapped`.
    fn unwrap(&self, wrapped: &[u8]) -> Option<Zeroizing<Vec<u8>>>;
}

/// ECIES to `vault-encryption-key`, as for the vault file key. Unwrapping can
/// prompt.
impl SyncKeyWrapper for ManagedKey {
    fn wrap(&self, raw: &[u8]) -> Option<String> {
        self.encrypt(raw)
    }

    fn unwrap(&self, wrapped: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        self.decrypt(wrapped)
    }
}

/// Wrapper with no keychain, for tests. The wrapped form is the base64 of
/// [`Self::PREFIX`] and the raw key. A string without the prefix fails to
/// unwrap.
#[cfg(test)]
pub(crate) struct TestKeyWrapper;

#[cfg(test)]
impl TestKeyWrapper {
    const PREFIX: &[u8] = b"test-wrapped-sync-key:";

    /// Public key of `vault-encryption-key` in the tests.
    pub(crate) fn public_key() -> PublicKey {
        PublicKey(vec![4; 65])
    }
}

#[cfg(test)]
impl SyncKeyWrapper for TestKeyWrapper {
    fn wrap(&self, raw: &[u8]) -> Option<String> {
        Some(B64.encode(Zeroizing::new([Self::PREFIX, raw].concat())))
    }

    fn unwrap(&self, wrapped: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let decoded = Zeroizing::new(B64.decode(wrapped).ok()?);
        let raw = decoded.strip_prefix(Self::PREFIX)?;
        Some(Zeroizing::new(raw.to_vec()))
    }
}
