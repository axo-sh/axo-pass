use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::secrets::vaults::files::FileHash;
use crate::secrets::vaults::format::encrypted_blob::EncryptedBlob;
use crate::secrets::vaults::format::encrypted_vault::EncryptedVaultItem;
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::model::VaultMetadata;

/// Current bundle format version. Import rejects anything newer. Version 2
/// writes short ids. Version 1 has hyphenated ids, which import still reads.
/// The `blobs` of a vault are an optional field of version 2. A build that
/// predates them ignores the field and imports the file records without
/// their blobs.
pub const BUNDLE_VERSION: u32 = 2;

/// A vault file key in raw (unwrapped) form. Serializes as base64 so it can be
/// stored as the plaintext of an `EncryptedBlob`.
#[serde_as]
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct RawFileKey(#[serde_as(as = "Base64")] pub Vec<u8>);

/// Bundle export format. A single age operation protects a random bundle key;
/// each vault's file key is wrapped with that bundle key via AES-256-GCM.
///
/// Only the file keys and the items are encrypted. File blobs are ciphertext
/// under the per-file keys of the item records, so they hold no plaintext.
/// `version`, `id`, `exported_at`, and each vault's `name` and `default_key`
/// are stored in plaintext and are not covered by any AAD, so one bundle file
/// discloses the name and key of every vault in it, and anyone with write
/// access to the file can rename or reorder entries undetected.
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct ExportedBundle {
    pub version: u32,
    #[serde_as(as = "ShortId")]
    pub id: Uuid,

    #[serde(with = "time::serde::rfc3339", default = "OffsetDateTime::now_utc")]
    pub exported_at: OffsetDateTime,

    /// `bundle_key` encrypted with the export mode (age scrypt for a
    /// passphrase, age x25519 for a recipient), ASCII-armored. The only
    /// scrypt derivation in the file.
    pub age_bundle_key: String,

    pub vaults: Vec<BundledVault>,
}

/// One vault inside a bundle.
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct BundledVault {
    #[serde_as(as = "ShortId")]
    pub id: Uuid,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Preferred key to import as. Overridable on import, and generated when
    /// absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_key: Option<String>,

    /// The vault's raw file key, encrypted with the bundle key.
    pub wrapped_file_key: EncryptedBlob<RawFileKey>,

    /// The vault's already-encrypted metadata and items, copied verbatim from
    /// the on-disk vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<EncryptedBlob<VaultMetadata>>,
    #[serde_as(as = "BTreeMap<ShortId, _>")]
    pub items: BTreeMap<Uuid, EncryptedVaultItem>,

    /// File blobs that the records of `items` name, as stored: the sealed
    /// bytes under the blob name, base64 encoded. Absent if the vault holds
    /// no file. A blob that the export could not read is not listed, and the
    /// import reports its file as missing. The blobs are bound to the vault
    /// id, so they are read only under the id of this entry.
    #[serde_as(as = "BTreeMap<_, Base64>")]
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub blobs: BTreeMap<FileHash, Vec<u8>>,
}

impl ExportedBundle {
    /// AAD binding a wrapped file key to its bundle and vault. Ids are in the
    /// hyphenated UUID form, not the short form of the bundle file.
    pub fn file_key_aad(bundle_id: Uuid, vault_id: Uuid) -> Vec<String> {
        vec![
            bundle_id.to_string(),
            vault_id.to_string(),
            "file-key".to_string(),
        ]
    }
}
