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

use p256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::value::RawValue;
use serde_json::{Map, Value};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use self::encoding::Canonical;
use super::crdt::ReplicaId;
use super::keys::{KeyFingerprint, SyncKey, SyncKeyWrapper};
use super::model::{ByteString, KeyId, PublicKey, ReplicaKeys};
use super::transport::{FileName, ReadResult, SyncTransport};
use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::vaults::bundle::{ExportMode, ImportIdentity};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::format::signing::{self, VaultSigner};
use crate::secrets::vaults::storage::txn::Unlock;

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

    /// Own `key.json` of `replica` in vault `vault_id`, read through
    /// `transport` before this Mac rewrites it. A missing file, or one that
    /// fails to parse, is read as empty. A file that is `Remote` or of
    /// another version fails, so no wrapping of it is lost. A `Remote` file
    /// is requested for download, so a later transaction reads it. A sync
    /// service can evict the file, since this Mac reads it only to rewrite
    /// it.
    pub(crate) fn read_own(
        transport: &dyn SyncTransport,
        vault_id: Uuid,
        replica: ReplicaId,
    ) -> Result<Self, Error> {
        match transport.read(vault_id, replica, FileName::Key)? {
            ReadResult::Missing => Ok(Self::default()),
            ReadResult::Remote => {
                if let Err(e) = transport.request_download(vault_id) {
                    log::warn!("Failed to request the download of vault {vault_id}: {e}");
                }
                Err(Error::SyncTransportError(
                    "own key.json is not local".to_string(),
                ))
            },
            ReadResult::Local(bytes) => match Self::parse(&bytes) {
                Ok(file) => Ok(file),
                Err(KeyFileError::VersionSkew(message)) => {
                    Err(Error::SyncStateVersionSkew(message))
                },
                Err(e) => {
                    log::warn!("Own key.json of vault {vault_id} is read as empty: {e}");
                    Ok(Self::default())
                },
            },
        }
    }

    /// Add `wrapping` in place of any `Device` wrapping to the same replica
    /// id and key id.
    pub(crate) fn put_device(&mut self, wrapping: DeviceWrapping) {
        self.wrappings.retain(|existing| {
            !matches!(existing, Wrapping::Device(device)
                if device.to_replica == wrapping.to_replica && device.key_id == wrapping.key_id)
        });
        self.wrappings.push(Wrapping::Device(wrapping));
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
    pub fn unwrap(&self, unwrap: &(impl DeviceUnwrap + ?Sized)) -> Result<SyncKey, Error> {
        let raw = unwrap
            .unwrap_sync_key(&self.wrapped)
            .ok_or(Error::SyncKeyDecryptionError(self.key_id.0))?;
        let key = SyncKey::from_slice(&raw).ok_or(Error::SyncKeyDecryptionError(self.key_id.0))?;
        if key.fingerprint() != self.key_fingerprint {
            return Err(Error::SyncKeyFingerprintMismatch(self.key_id.0));
        }
        Ok(key)
    }

    /// Canonical bytes that the pairing MAC of the wrapping covers (D4):
    /// `vault_id`, `from_replica`, `to_replica`, `key_id`, `key_fingerprint`,
    /// the keys `to` of the new Mac, `from_encryption`, `from_signing`, and
    /// `wrapped`. `from_replica` is the directory of the `key.json` that
    /// holds the wrapping.
    pub fn pairing_input(
        &self,
        vault_id: Uuid,
        from_replica: ReplicaId,
        to: &ReplicaKeys,
    ) -> Vec<u8> {
        Canonical::new()
            .id(vault_id)
            .id(from_replica.0)
            .id(self.to_replica.0)
            .number(self.key_id.0)
            .field(self.key_fingerprint.0)
            .field(&to.encryption.0)
            .field(&to.signing.0)
            .field(&self.from_encryption.0)
            .field(&self.from_signing.0)
            .field(&self.wrapped)
            .into_bytes()
    }

    /// Message that the rotation signature of the wrapping covers:
    /// `ap-key-wrap-v1:` and the canonical encoding of `vault_id`, `key_id`,
    /// `key_fingerprint`, `from_replica`, `to_replica`, `from_encryption`,
    /// `from_signing`, `removed`, `remaining`, and `wrapped`, in that order.
    /// `removed` and `remaining` are counted lists of replica ids, empty if
    /// absent. `from_replica` is the directory of the `key.json` that holds
    /// the wrapping.
    pub fn rotation_message(&self, vault_id: Uuid, from_replica: ReplicaId) -> Vec<u8> {
        let ids = |list: &Option<Vec<ReplicaId>>| list.clone().unwrap_or_default();
        let removed = ids(&self.removed);
        let remaining = ids(&self.remaining);
        let canonical = Canonical::new()
            .id(vault_id)
            .number(self.key_id.0)
            .field(self.key_fingerprint.0)
            .id(from_replica.0)
            .id(self.to_replica.0)
            .field(&self.from_encryption.0)
            .field(&self.from_signing.0)
            .list(removed.iter(), |c, replica| c.id(replica.0))
            .list(remaining.iter(), |c, replica| c.id(replica.0))
            .field(&self.wrapped)
            .into_bytes();
        [ROTATION_LABEL, &canonical].concat()
    }

    /// Set `removed` and `remaining`, and sign the wrapping with `signer`,
    /// the `device-signing-key` of `from_replica`. Signing never prompts.
    pub fn sign_rotation(
        &mut self,
        vault_id: Uuid,
        from_replica: ReplicaId,
        removed: Vec<ReplicaId>,
        remaining: Vec<ReplicaId>,
        signer: &dyn VaultSigner,
    ) -> Result<(), Error> {
        self.pairing_mac = None;
        self.removed = Some(removed);
        self.remaining = Some(remaining);
        let message = self.rotation_message(vault_id, from_replica);
        self.signature = Some(WrappingSignature(signer.sign(&message)?));
        Ok(())
    }

    /// Check the rotation signature of the wrapping, read from the
    /// `key.json` of `from_replica`, against `signing`, the pinned signing
    /// key of `from_replica`. A wrapping with no signature, no `removed` or
    /// `remaining` list, or a pairing MAC fails. So does a wrapping whose
    /// `from_signing` is not `signing`.
    pub fn verify_rotation(
        &self,
        vault_id: Uuid,
        from_replica: ReplicaId,
        signing: &PublicKey,
    ) -> Result<(), Error> {
        let refused = |reason: &str| Err(Error::RotationRefused(reason.to_string()));
        let (Some(signature), Some(_), Some(_)) = (&self.signature, &self.removed, &self.remaining)
        else {
            return refused("wrapping is not a signed rotation");
        };
        if self.pairing_mac.is_some() {
            return refused("wrapping holds a pairing MAC");
        }
        if self.from_signing != *signing {
            return refused("sender signing key is not the pinned key");
        }
        let Ok(key) = VerifyingKey::from_sec1_bytes(&signing.0) else {
            return refused("pinned signing key does not parse");
        };
        let message = self.rotation_message(vault_id, from_replica);
        signing::verify(&key, &message, &signature.0)
            .or_else(|_| refused("rotation signature does not verify"))
    }
}

/// Prefix of the message of a rotation signature.
const ROTATION_LABEL: &[u8] = b"ap-key-wrap-v1:";

/// HMAC-SHA-256 of a pairing request or a pairing wrapping under the pairing
/// key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PairingMac(#[serde(with = "ByteString")] pub [u8; 32]);

/// Rotation signature of a `Device` wrapping: a DER ECDSA P-256 signature by
/// the `device-signing-key` of the rotating replica.
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

/// Keys of a pairing of the new Mac, held by the `SyncManager` (D6 of doc
/// 18). They unwrap a `Device` wrapping, unwrap the keyring of a local sync
/// state, and wrap the keyring and the file key of each import.
pub trait PairingKeys: DeviceUnwrap + SyncKeyWrapper {
    /// Unlock of the join of a paired vault with these keys. Reads no key.
    fn unlock(&self) -> Unlock<'_>;
}

/// `vault-encryption-key`, read once on the context of the pairing start.
impl PairingKeys for ManagedKey {
    fn unlock(&self) -> Unlock<'_> {
        Unlock::Key(self)
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
