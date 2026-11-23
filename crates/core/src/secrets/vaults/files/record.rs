//! File record stored as the value of a file credential.

use std::fmt;

use aes_gcm::aead::OsRng;
use aes_gcm::{Aes256Gcm, KeyInit};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use secrecy::SecretString;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest, Sha256};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::secrets::vaults::errors::Error;

/// SHA-256 hash of file bytes. The serde form and the text form are 64
/// lowercase hex characters.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileHash(pub [u8; 32]);

impl FileHash {
    /// Hash of `bytes`.
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

impl fmt::Display for FileHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl fmt::Debug for FileHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileHash({self})")
    }
}

impl Serialize for FileHash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for FileHash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text)
            .ok_or_else(|| de::Error::invalid_value(de::Unexpected::Str(&text), &"a SHA-256 hash"))
    }
}

/// Per-file AES-256 key: 32 random bytes. Zeroized on drop. `Debug` shows no
/// bytes. The serde form is standard base64 with padding.
#[derive(Clone, PartialEq, Eq)]
pub struct FileKey(Zeroizing<[u8; 32]>);

impl FileKey {
    /// New random key.
    pub(crate) fn generate() -> Self {
        let random = Zeroizing::new(Aes256Gcm::generate_key(OsRng));
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(&random);
        Self(bytes)
    }

    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for FileKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FileKey(..)")
    }
}

/// The only field is `Zeroizing`, which zeroizes the bytes on drop.
impl ZeroizeOnDrop for FileKey {}

impl Serialize for FileKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let text = Zeroizing::new(B64.encode(self.as_bytes()));
        serializer.serialize_str(&text)
    }
}

impl<'de> Deserialize<'de> for FileKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = Zeroizing::new(String::deserialize(deserializer)?);
        let decoded = Zeroizing::new(
            B64.decode(text.as_bytes())
                .map_err(|_| de::Error::custom("file key is not base64"))?,
        );
        let mut key = Zeroizing::new([0u8; 32]);
        if decoded.len() != key.len() {
            return Err(de::Error::custom("file key is not 32 bytes"));
        }
        key.copy_from_slice(&decoded);
        Ok(Self(key))
    }
}

/// Value of a file credential. The file bytes are in a blob outside the
/// vault file, encrypted under `key` (`files/stream.rs`).
///
/// The record is secret, since it holds the key. `Debug` shows no key bytes.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRecord {
    /// Blob name, the SHA-256 of the ciphertext.
    pub blob: FileHash,
    /// Per-file key.
    pub(crate) key: FileKey,
    /// SHA-256 of the plaintext.
    pub sha256: FileHash,
    /// Plaintext size in bytes.
    pub size: u64,
    /// File name.
    pub name: String,
    /// MIME type, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
}

impl FileRecord {
    /// Record of the credential value `value`.
    pub fn decode(value: &str) -> Result<Self, Error> {
        serde_json::from_str(value).map_err(|e| Error::FileRecordInvalid(e.to_string()))
    }

    /// Credential value of this record.
    pub fn encode(&self) -> Result<SecretString, Error> {
        let json = serde_json::to_string(self)
            .map_err(|e| Error::FileRecordInvalid(format!("failed to encode: {e}")))?;
        Ok(SecretString::from(json))
    }
}

/// Blob name of a credential value, read leniently. Fields other than
/// `blob` are ignored, so a record written by a newer build still names its
/// blob for garbage collection.
#[derive(Deserialize)]
pub(crate) struct BlobRef {
    pub(crate) blob: FileHash,
}

impl BlobRef {
    /// Blob named by the credential value `value`. `None` if the value is
    /// not a JSON object with a `blob` hash.
    pub(crate) fn of(value: &str) -> Option<FileHash> {
        serde_json::from_str::<Self>(value).ok().map(|r| r.blob)
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    fn record() -> FileRecord {
        FileRecord {
            blob: FileHash([0xab; 32]),
            key: FileKey::from_bytes([7; 32]),
            sha256: FileHash([0x01; 32]),
            size: 12,
            name: "notes.txt".to_string(),
            mime: Some("text/plain".to_string()),
        }
    }

    #[test]
    fn record_round_trips_through_value() {
        let value = record().encode().unwrap();
        assert_eq!(FileRecord::decode(value.expose_secret()).unwrap(), record());
    }

    #[test]
    fn debug_shows_no_key_bytes() {
        let text = format!("{:?}", record());
        assert!(text.contains("FileKey(..)"), "{text}");
        let key_b64 = B64.encode([7u8; 32]);
        assert!(!text.contains(&key_b64), "{text}");
        assert!(!text.contains("[7, 7"), "{text}");
    }

    #[test]
    fn hash_parse_refuses_upper_case_and_wrong_length() {
        let hash = FileHash([0xab; 32]);
        assert_eq!(FileHash::parse(&hash.to_string()), Some(hash));
        assert_eq!(FileHash::parse(&hash.to_string().to_uppercase()), None);
        assert_eq!(FileHash::parse("ab"), None);
        assert_eq!(FileHash::parse("../../etc/passwd"), None);
    }

    #[test]
    fn key_of_wrong_length_refused() {
        let mut json = serde_json::to_value(record()).unwrap();
        json["key"] = B64.encode([7u8; 31]).into();
        assert!(serde_json::from_value::<FileRecord>(json).is_err());
    }

    #[test]
    fn blob_ref_reads_record_with_unknown_field() {
        let mut json = serde_json::to_value(record()).unwrap();
        json["thumbnail"] = "x".into();
        let value = json.to_string();
        assert!(FileRecord::decode(&value).is_err());
        assert_eq!(BlobRef::of(&value), Some(FileHash([0xab; 32])));
        assert_eq!(BlobRef::of("hunter2"), None);
        assert_eq!(BlobRef::of(""), None);
    }
}
