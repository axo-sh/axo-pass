//! State files, the published form of a replica's sync state.
//!
//! A state file is the 4 bytes `APST`, the header length as a big-endian
//! `u32`, the JSON header, and the AES-256-GCM ciphertext of the padded body.
//! The padded body is built by [`padded::PaddedBody`]. The decrypted body is
//! the CBOR encoding of the sync state, built by [`body::StateBody`]. A state
//! file is named `{hash}.apstate`, with the SHA-256 of the file bytes.

pub mod body;
pub mod padded;

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use self::body::{BodyError, StateBody};
use self::padded::{PaddedBody, PaddingError};
use super::crdt::{CausalState, ReplicaId};
use super::keys::{KeyFingerprint, SyncKey, SyncKeyring};
use super::model::{ByteString, KeyId, SYNC_FORMAT_VERSION, SyncState};
use crate::secrets::vaults::errors::Error;

/// First bytes of every state file.
const MAGIC: &[u8; 4] = b"APST";

/// Prefix of the body AAD of a state file.
const AAD_PREFIX: &str = "ap-state-body-v1";

/// Plaintext header of a state file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateHeader {
    pub format_version: u32,
    pub vault_id: Uuid,
    /// Writer of the file.
    pub replica_id: ReplicaId,
    pub key_id: KeyId,
    pub key_fingerprint: KeyFingerprint,
    #[serde(with = "ByteString")]
    pub nonce: [u8; 12],
}

impl StateHeader {
    /// Body AAD:
    /// `ap-state-body-v1:{format_version}:{vault_id}:{replica_id}:{key_id}:
    /// {key_fingerprint}`. Ids are lowercase hyphenated UUIDs, the key id
    /// is decimal, and the fingerprint is lowercase hex.
    pub fn aad(&self) -> String {
        let Self {
            format_version,
            vault_id,
            replica_id,
            key_id,
            key_fingerprint,
            nonce: _,
        } = self;
        let replica_id = replica_id.0;
        let key_id = key_id.0;
        let key_fingerprint = key_fingerprint.to_hex();
        format!("{AAD_PREFIX}:{format_version}:{vault_id}:{replica_id}:{key_id}:{key_fingerprint}")
    }
}

/// SHA-256 of the bytes of a state file. The serde form and the text form are
/// 64 lowercase hex characters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StateHash(pub [u8; 32]);

impl StateHash {
    /// Hash of the file bytes `bytes`.
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// Hash of the 64 lowercase hex characters `text`.
    pub fn parse(text: &str) -> Option<Self> {
        let digit = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        };
        let text = text.as_bytes();
        if text.len() != 64 {
            return None;
        }
        let mut hash = [0u8; 32];
        for (byte, [high, low]) in hash.iter_mut().zip(text.as_chunks::<2>().0) {
            *byte = digit(*high)? << 4 | digit(*low)?;
        }
        Some(Self(hash))
    }
}

impl fmt::Display for StateHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl Serialize for StateHash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for StateHash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text)
            .ok_or_else(|| de::Error::invalid_value(de::Unexpected::Str(&text), &"a SHA-256 hash"))
    }
}

/// Names a state file is read under: the vault and replica directories, and
/// the hash in the file name.
#[derive(Clone, Copy, Debug)]
pub struct StateSource {
    pub vault_id: Uuid,
    pub replica_id: ReplicaId,
    pub hash: StateHash,
}

/// Failure to read a state file.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum StateFileError {
    /// Key id the keyring lacks. The file can be read once the key arrives.
    #[error("state file is under key {}, which this Mac does not hold", .0.0)]
    WaitingForKey(KeyId),
    /// Key id the keyring holds under another fingerprint. The file is
    /// ignored.
    #[error("state file is under another key with id {}", .0.0)]
    OtherKey(KeyId),
    /// Key id below the newest key this Mac has accepted. The file is
    /// ignored, whatever replica it names.
    #[error("state file is under key {}, older than the accepted key", .0.0)]
    OldKey(KeyId),
    /// Newer format version, or a body field this build does not know.
    #[error("state file is from a newer format: {0}")]
    VersionSkew(String),
    /// Damaged or forged file.
    #[error("state file is quarantined: {0}")]
    Quarantine(Damage),
}

impl StateFileError {
    pub fn is_quarantine(&self) -> bool {
        matches!(self, Self::Quarantine(_))
    }
}

/// Reason a state file is quarantined.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum Damage {
    #[error("file bytes do not hash to the file name")]
    HashMismatch,
    #[error("file does not start with the state file magic bytes")]
    NoMagic,
    #[error("header length is past the end of the file")]
    HeaderLength,
    #[error("header is malformed: {0}")]
    Header(String),
    #[error("header names vault {0}, not the vault it is read under")]
    WrongVault(Uuid),
    #[error("header names replica {}, not the replica it is read under", .0.0)]
    WrongReplica(ReplicaId),
    #[error("body fails to decrypt")]
    Decryption,
    #[error(transparent)]
    Padding(PaddingError),
    #[error(transparent)]
    Body(BodyError),
}

/// Encoding and decoding of state files.
pub struct StateFile;

impl StateFile {
    /// State file of the padded body `padded`, written by `replica_id`,
    /// encrypted under the state key of `key` with a fresh nonce.
    pub fn encode(
        padded: &[u8],
        vault_id: Uuid,
        replica_id: ReplicaId,
        key_id: KeyId,
        key: &SyncKey,
    ) -> Result<Vec<u8>, Error> {
        let mut header = StateHeader {
            format_version: SYNC_FORMAT_VERSION,
            vault_id,
            replica_id,
            key_id,
            key_fingerprint: key.fingerprint(),
            nonce: [0; 12],
        };
        let (nonce, ciphertext) = key
            .state_key(vault_id)
            .encrypt(header.aad().as_bytes(), padded)
            .ok_or_else(|| Error::SyncStateEncodeError("body fails to encrypt".to_string()))?;
        header.nonce = nonce;
        let header_json =
            serde_json::to_vec(&header).map_err(|e| Error::SyncStateEncodeError(e.to_string()))?;
        let header_len = u32::try_from(header_json.len())
            .expect("header is shorter than 4 GiB")
            .to_be_bytes();
        Ok([MAGIC, &header_len[..], &header_json, &ciphertext].concat())
    }

    /// File name of the state file with hash `hash`.
    pub fn name(hash: StateHash) -> String {
        format!("{hash}.apstate")
    }

    /// Header and sync state of the state file `bytes`, read under `source`
    /// with the keys of `keyring`.
    pub fn decode(
        bytes: &[u8],
        source: &StateSource,
        keyring: &SyncKeyring,
    ) -> Result<(StateHeader, CausalState<SyncState>), StateFileError> {
        Self::decode_accepted(bytes, source, keyring, KeyId(0))
    }

    /// [`Self::decode`] on a Mac that has accepted the key `accepted`. A file
    /// under a lower key id is `OldKey`, checked before the keyring, so it is
    /// never decrypted.
    pub fn decode_accepted(
        bytes: &[u8],
        source: &StateSource,
        keyring: &SyncKeyring,
        accepted: KeyId,
    ) -> Result<(StateHeader, CausalState<SyncState>), StateFileError> {
        let (header, padded) = Self::open_accepted(bytes, source, keyring, accepted)?;
        let body = PaddedBody::unpad(&padded)
            .map_err(|e| StateFileError::Quarantine(Damage::Padding(e)))?;
        let state = StateBody::decode(&body).map_err(|e| match e {
            BodyError::VersionSkew(message) => StateFileError::VersionSkew(message),
            e => StateFileError::Quarantine(Damage::Body(e)),
        })?;
        Ok((header, state))
    }

    /// Header and padded body of the state file `bytes`. Checks, in order:
    /// the hash, the magic bytes, the header length, the header format
    /// version, the header fields, the vault and replica ids against
    /// `source`, the key id and fingerprint against `keyring`, and the AAD.
    #[cfg(test)]
    pub(crate) fn open(
        bytes: &[u8],
        source: &StateSource,
        keyring: &SyncKeyring,
    ) -> Result<(StateHeader, Zeroizing<Vec<u8>>), StateFileError> {
        Self::open_accepted(bytes, source, keyring, KeyId(0))
    }

    /// [`Self::open`], with a key id below `accepted` refused as `OldKey`
    /// after the vault and replica id checks.
    fn open_accepted(
        bytes: &[u8],
        source: &StateSource,
        keyring: &SyncKeyring,
        accepted: KeyId,
    ) -> Result<(StateHeader, Zeroizing<Vec<u8>>), StateFileError> {
        let quarantine = StateFileError::Quarantine;
        if StateHash::of(bytes) != source.hash {
            return Err(quarantine(Damage::HashMismatch));
        }
        let (header_json, ciphertext) = Self::split(bytes)?;
        let header = Self::header(header_json)?;
        if header.vault_id != source.vault_id {
            return Err(quarantine(Damage::WrongVault(header.vault_id)));
        }
        if header.replica_id != source.replica_id {
            return Err(quarantine(Damage::WrongReplica(header.replica_id)));
        }
        if header.key_id.0 < accepted.0 {
            return Err(StateFileError::OldKey(header.key_id));
        }
        if keyring.get(header.key_id).is_none() {
            return Err(StateFileError::WaitingForKey(header.key_id));
        }
        let key = keyring
            .find(header.key_id, &header.key_fingerprint)
            .ok_or(StateFileError::OtherKey(header.key_id))?;
        let padded = key
            .state_key(header.vault_id)
            .decrypt(&header.nonce, header.aad().as_bytes(), ciphertext)
            .ok_or(quarantine(Damage::Decryption))?;
        Ok((header, padded))
    }

    /// Key id of the plaintext header of the state file `bytes`, for the age
    /// import. Reads the magic bytes, the header length, and the `key_id`
    /// field of the header only. The hash, the format version, the other
    /// header fields, and the body are not checked, and nothing is
    /// decrypted. No state is read from the file.
    pub fn peek_key_id(bytes: &[u8]) -> Result<KeyId, StateFileError> {
        let (header_json, _) = Self::split(bytes)?;
        serde_json::from_slice::<HeaderKeyId>(header_json)
            .map(|header| header.key_id)
            .map_err(|e| StateFileError::Quarantine(Damage::Header(e.to_string())))
    }

    /// JSON header and ciphertext of the state file `bytes`. Checks the magic
    /// bytes and that the header length lies inside the file.
    fn split(bytes: &[u8]) -> Result<(&[u8], &[u8]), StateFileError> {
        let quarantine = StateFileError::Quarantine;
        let rest = bytes
            .strip_prefix(MAGIC)
            .ok_or(quarantine(Damage::NoMagic))?;
        let (header_len, rest) = rest
            .split_first_chunk::<4>()
            .ok_or(quarantine(Damage::HeaderLength))?;
        let header_len = u32::from_be_bytes(*header_len) as usize;
        if header_len > rest.len() {
            return Err(quarantine(Damage::HeaderLength));
        }
        Ok(rest.split_at(header_len))
    }

    /// Header of the JSON `header_json`. A newer format version is version
    /// skew, checked before the other fields.
    fn header(header_json: &[u8]) -> Result<StateHeader, StateFileError> {
        let damage = |message: String| StateFileError::Quarantine(Damage::Header(message));
        match FormatVersion::of(header_json).map_err(damage)? {
            SYNC_FORMAT_VERSION => {},
            newer if newer > SYNC_FORMAT_VERSION => {
                return Err(StateFileError::VersionSkew(format!(
                    "header format version {newer}"
                )));
            },
            older => return Err(damage(format!("format version {older}"))),
        }
        serde_json::from_slice(header_json).map_err(|e| damage(e.to_string()))
    }
}

/// `key_id` of a JSON header. Other fields are ignored.
#[derive(Deserialize)]
struct HeaderKeyId {
    key_id: KeyId,
}

/// `format_version` of a JSON header, read before the other fields.
#[derive(Deserialize)]
pub(crate) struct FormatVersion {
    format_version: u32,
}

impl FormatVersion {
    /// Format version of the JSON object `json`. Other fields are ignored.
    pub(crate) fn of(json: &[u8]) -> Result<u32, String> {
        serde_json::from_slice::<Self>(json)
            .map(|header| header.format_version)
            .map_err(|e| e.to_string())
    }
}
