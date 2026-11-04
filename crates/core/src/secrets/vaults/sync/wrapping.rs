//! `key.json`, the sync key wrappings in the directory of one replica.
//!
//! A `key.json` holds `version` and a list of `wrappings`. Each wrapping is
//! parsed by its `kind`. A `Device` wrapping is the sync key ECIES-wrapped to
//! the `vault-encryption-key` of another replica. An `Age` wrapping is the
//! sync key wrapped to the age recipient of a recovery kit. A wrapping of a
//! kind this build does not know is skipped on read and written back as read.
//!
//! `key.json` is not authenticated as a file. The pairing code, the rotation
//! signature, or the kit fingerprint authenticates each key that is unwrapped.

pub mod base32;
pub mod encoding;

use serde::{Deserialize, Serialize, Serializer};
use serde_json::value::RawValue;
use serde_json::{Map, Value};
use thiserror::Error;
use zeroize::Zeroizing;

use super::crdt::ReplicaId;
use super::keys::{KeyFingerprint, SyncKey};
use super::model::{ByteString, KeyId, PublicKey, ReplicaKeys};
use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::vaults::bundle::{ExportMode, ImportIdentity};
use crate::secrets::vaults::errors::Error;

/// Version of the `key.json` format.
pub const KEY_FILE_VERSION: u32 = 1;

/// Failure to read a `key.json`.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum KeyFileError {
    /// Version other than [`KEY_FILE_VERSION`].
    #[error("key file is from another format: {0}")]
    VersionSkew(String),
    #[error("key file is malformed: {0}")]
    Malformed(String),
}

/// Parsed `key.json`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct KeyFile {
    /// Wrappings in file order.
    pub wrappings: Vec<Wrapping>,
    /// Reasons of the wrappings that failed to parse. They are not written.
    pub invalid: Vec<String>,
}

impl KeyFile {
    /// Key file of the JSON `bytes`. The version is checked before the other
    /// fields. A wrapping that fails to parse is listed in `invalid`, and the
    /// other wrappings are still read.
    pub fn parse(bytes: &[u8]) -> Result<Self, KeyFileError> {
        let malformed = |e: serde_json::Error| KeyFileError::Malformed(e.to_string());
        let version = serde_json::from_slice::<Version>(bytes).map_err(malformed)?;
        if version.version != KEY_FILE_VERSION {
            return Err(KeyFileError::VersionSkew(format!(
                "version {}",
                version.version
            )));
        }
        let file = serde_json::from_slice::<RawKeyFile>(bytes).map_err(malformed)?;
        let mut key_file = Self::default();
        for raw in file.wrappings {
            match Wrapping::parse(raw) {
                Ok(wrapping) => key_file.wrappings.push(wrapping),
                Err(reason) => key_file.invalid.push(reason),
            }
        }
        Ok(key_file)
    }

    /// JSON of the key file. Unknown wrappings are written as read. Invalid
    /// wrappings are not written.
    pub fn to_bytes(&self) -> Vec<u8> {
        let file = KeyFileOut {
            version: KEY_FILE_VERSION,
            wrappings: &self.wrappings,
        };
        serde_json::to_vec(&file).expect("key file has only string map keys")
    }

    pub fn devices(&self) -> impl Iterator<Item = &DeviceWrapping> {
        self.wrappings.iter().filter_map(|wrapping| match wrapping {
            Wrapping::Device(device) => Some(device),
            _ => None,
        })
    }

    pub fn ages(&self) -> impl Iterator<Item = &AgeWrapping> {
        self.wrappings.iter().filter_map(|wrapping| match wrapping {
            Wrapping::Age(age) => Some(age),
            _ => None,
        })
    }
}

/// `version` of a `key.json`, read before the other fields.
#[derive(Deserialize)]
struct Version {
    version: u32,
}

/// Fields of a `key.json` as read. Each wrapping is parsed on its own.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKeyFile {
    #[allow(dead_code)]
    version: u32,
    wrappings: Vec<Box<RawValue>>,
}

/// Fields of a `key.json` as written.
#[derive(Serialize)]
struct KeyFileOut<'a> {
    version: u32,
    wrappings: &'a [Wrapping],
}

/// One entry of `wrappings`, by its `kind`.
#[derive(Clone, Debug, PartialEq)]
pub enum Wrapping {
    Device(DeviceWrapping),
    Age(AgeWrapping),
    /// Kind this build does not know. Skipped on read.
    Unknown(UnknownWrapping),
}

impl Wrapping {
    /// Wrapping of the JSON `raw`. Fails with the reason if `raw` is not an
    /// object with a string `kind`, or if a `Device` or `Age` wrapping has a
    /// missing, malformed, or unknown field.
    fn parse(raw: Box<RawValue>) -> Result<Self, String> {
        let mut fields =
            serde_json::from_str::<Map<String, Value>>(raw.get()).map_err(|e| e.to_string())?;
        let kind = match fields.remove("kind") {
            Some(Value::String(kind)) => kind,
            Some(_) => return Err("kind is not a string".to_string()),
            None => return Err("wrapping has no kind".to_string()),
        };
        let fields = Value::Object(fields);
        let invalid = |e: serde_json::Error| format!("{kind} wrapping: {e}");
        match kind.as_str() {
            DeviceWrapping::KIND => serde_json::from_value(fields)
                .map(Self::Device)
                .map_err(invalid),
            AgeWrapping::KIND => serde_json::from_value(fields)
                .map(Self::Age)
                .map_err(invalid),
            _ => Ok(Self::Unknown(UnknownWrapping {
                kind: kind.clone(),
                raw,
            })),
        }
    }
}

impl Serialize for Wrapping {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Device(device) => KnownWrapping::Device(device).serialize(serializer),
            Self::Age(age) => KnownWrapping::Age(age).serialize(serializer),
            Self::Unknown(unknown) => unknown.raw.serialize(serializer),
        }
    }
}

/// Written form of a known wrapping, with `kind` first.
#[derive(Serialize)]
#[serde(tag = "kind")]
enum KnownWrapping<'a> {
    Device(&'a DeviceWrapping),
    Age(&'a AgeWrapping),
}

/// Wrapping of a kind this build does not know, as read.
#[derive(Clone, Debug)]
pub struct UnknownWrapping {
    pub kind: String,
    raw: Box<RawValue>,
}

impl UnknownWrapping {
    /// JSON text of the wrapping as read.
    pub fn json(&self) -> &str {
        self.raw.get()
    }
}

impl PartialEq for UnknownWrapping {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind && self.json() == other.json()
    }
}

/// Sync key ECIES-wrapped to the `vault-encryption-key` of `to_replica`, with
/// the public keys of the Mac that wrote it.
///
/// A wrapping made during pairing carries `pairing_mac`. A wrapping made
/// during a rotation carries `signature`, `removed`, and `remaining`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceWrapping {
    pub key_id: KeyId,
    pub key_fingerprint: KeyFingerprint,
    pub to_replica: ReplicaId,
    /// Encryption public key of the Mac that wrote the wrapping.
    pub from_encryption: PublicKey,
    /// Signing public key of the Mac that wrote the wrapping.
    pub from_signing: PublicKey,
    /// Raw ECIES ciphertext of the key.
    #[serde(with = "ByteString")]
    pub wrapped: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_mac: Option<PairingMac>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<WrappingSignature>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<Vec<ReplicaId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining: Option<Vec<ReplicaId>>,
}

impl DeviceWrapping {
    const KIND: &str = "Device";

    /// Wrapping of `key` under `key_id` to `to_replica`, whose encryption key
    /// is `to_encryption`, written by the Mac with the keys `from`. Makes no
    /// keychain call. Carries no pairing MAC and no rotation fields.
    pub fn wrap(
        key_id: KeyId,
        key: &SyncKey,
        to_replica: ReplicaId,
        to_encryption: &PublicKey,
        from: &ReplicaKeys,
    ) -> Result<Self, Error> {
        let wrapped = ManagedKey::encrypt_to(&to_encryption.0, key.as_bytes()).map_err(|e| {
            log::debug!("Failed to wrap sync key {} to a device: {e}", key_id.0);
            Error::SyncKeyEncryptionError(key_id.0)
        })?;
        Ok(Self {
            key_id,
            key_fingerprint: key.fingerprint(),
            to_replica,
            from_encryption: from.encryption.clone(),
            from_signing: from.signing.clone(),
            wrapped,
            pairing_mac: None,
            signature: None,
            removed: None,
            remaining: None,
        })
    }

    /// Key of the wrapping, unwrapped by `unwrap`. Fails if it does not unwrap
    /// to 32 bytes, or if its fingerprint differs from `key_fingerprint`.
    pub fn unwrap(&self, unwrap: &impl DeviceUnwrap) -> Result<SyncKey, Error> {
        let raw = unwrap
            .unwrap_sync_key(&self.wrapped)
            .ok_or(Error::SyncKeyDecryptionError(self.key_id.0))?;
        let key = SyncKey::from_slice(&raw).ok_or(Error::SyncKeyDecryptionError(self.key_id.0))?;
        if key.fingerprint() != self.key_fingerprint {
            return Err(Error::SyncKeyFingerprintMismatch(self.key_id.0));
        }
        Ok(key)
    }
}

/// HMAC-SHA-256 of a pairing wrapping under the pairing key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PairingMac(#[serde(with = "ByteString")] pub [u8; 32]);

/// Rotation signature of a `Device` wrapping. Written by milestone 13.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WrappingSignature(#[serde(with = "ByteString")] pub Vec<u8>);

/// Unwrap of a `Device` wrapping with the `vault-encryption-key` of this Mac.
pub trait DeviceUnwrap {
    /// Plaintext of the raw ECIES ciphertext `wrapped`.
    fn unwrap_sync_key(&self, wrapped: &[u8]) -> Option<Zeroizing<Vec<u8>>>;
}

/// ECIES with the private key. For `vault-encryption-key`, unwrapping
/// prompts.
impl DeviceUnwrap for ManagedKey {
    fn unwrap_sync_key(&self, wrapped: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        self.decrypt_bytes(wrapped)
    }
}

/// Sync key wrapped to the age recipient of a recovery kit.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgeWrapping {
    pub key_id: KeyId,
    /// Fingerprint as written. The age import does not use it.
    pub key_fingerprint: KeyFingerprint,
    /// Age x25519 recipient, `age1...`.
    pub recipient: String,
    /// ASCII-armored age ciphertext of the key.
    pub wrapped: String,
}

impl AgeWrapping {
    const KIND: &str = "Age";

    /// Wrapping of `key` under `key_id` to the age recipient `recipient`.
    pub fn wrap(key_id: KeyId, key: &SyncKey, recipient: &str) -> Result<Self, Error> {
        let wrapped = ExportMode::Recipient(recipient.to_string())
            .encrypt(key.as_bytes())
            .map_err(|e| {
                log::debug!(
                    "Failed to wrap sync key {} to an age recipient: {e}",
                    key_id.0
                );
                Error::SyncKeyEncryptionError(key_id.0)
            })?;
        Ok(Self {
            key_id,
            key_fingerprint: key.fingerprint(),
            recipient: recipient.to_string(),
            wrapped,
        })
    }

    /// Key of the wrapping, decrypted with `identity`. Fails if it does not
    /// decrypt to 32 bytes. `key_fingerprint` is not checked. The age import
    /// checks the key against the fingerprint of the kit.
    pub fn unwrap(&self, identity: &age::x25519::Identity) -> Result<SyncKey, Error> {
        let raw = ImportIdentity::Identity(identity.clone())
            .decrypt(&self.wrapped)
            .map(Zeroizing::new)
            .map_err(|e| {
                log::debug!(
                    "Failed to unwrap age wrapping of sync key {}: {e}",
                    self.key_id.0
                );
                Error::SyncKeyDecryptionError(self.key_id.0)
            })?;
        SyncKey::from_slice(&raw).ok_or(Error::SyncKeyDecryptionError(self.key_id.0))
    }
}
