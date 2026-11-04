//! `meta.json`, the format version and vault id of one vault directory.
//!
//! The bytes of a `meta.json` are a function of its two fields, so two Macs
//! that enable sync at once write identical files. Milestone 10 writes it at
//! setup. Like every file read from the synced folder, it is untrusted.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use super::state_file::FormatVersion;
use crate::secrets::vaults::format::short_id::ShortId;

/// Version of the `meta.json` format.
pub const META_FORMAT_VERSION: u32 = 1;

/// Failure to read a `meta.json`.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum MetaFileError {
    /// Version newer than [`META_FORMAT_VERSION`].
    #[error("meta file is from a newer format: {0}")]
    VersionSkew(String),
    #[error("meta file is malformed: {0}")]
    Malformed(String),
    /// Vault id other than the one of its directory.
    #[error("meta file of vault directory {directory} names vault {vault_id}")]
    OtherVault { directory: String, vault_id: Uuid },
}

/// Parsed `meta.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetaFile {
    pub format_version: u32,
    pub vault_id: Uuid,
}

impl MetaFile {
    /// Meta file of vault `vault_id` in the current format.
    pub fn new(vault_id: Uuid) -> Self {
        Self {
            format_version: META_FORMAT_VERSION,
            vault_id,
        }
    }

    /// Meta file of the JSON `bytes`, read from the directory of vault
    /// `vault_id`. The version is checked before the other fields. A newer
    /// version is version skew, and an older one is malformed.
    pub fn parse(bytes: &[u8], vault_id: Uuid) -> Result<Self, MetaFileError> {
        match FormatVersion::of(bytes).map_err(MetaFileError::Malformed)? {
            META_FORMAT_VERSION => {},
            newer if newer > META_FORMAT_VERSION => {
                return Err(MetaFileError::VersionSkew(format!("version {newer}")));
            },
            older => return Err(MetaFileError::Malformed(format!("version {older}"))),
        }
        let file = serde_json::from_slice::<Self>(bytes)
            .map_err(|e| MetaFileError::Malformed(e.to_string()))?;
        if file.vault_id != vault_id {
            return Err(MetaFileError::OtherVault {
                directory: ShortId::encode_uuid(vault_id),
                vault_id: file.vault_id,
            });
        }
        Ok(file)
    }

    /// JSON of the meta file, with the fields in a fixed order and no
    /// whitespace.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("meta file has only plain fields")
    }
}
