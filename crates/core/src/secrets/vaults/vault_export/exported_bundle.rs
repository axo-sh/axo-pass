use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::secrets::vaults::vault::encrypted_blob::EncryptedBlob;
use crate::secrets::vaults::vault::encrypted_vault::EncryptedVaultItem;

/// Current bundle format version. Import rejects anything newer.
pub const BUNDLE_VERSION: u32 = 1;

/// A vault file key in raw (unwrapped) form. Serializes as base64 so it can be
/// stored as the plaintext of an `EncryptedBlob`.
#[serde_as]
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct RawFileKey(#[serde_as(as = "Base64")] pub Vec<u8>);

/// Bundle export format. A single age operation protects a random bundle key;
/// each vault's file key is wrapped with that bundle key via AES-256-GCM.
#[derive(Serialize, Deserialize)]
pub struct ExportedBundle {
    pub version: u32,
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
#[derive(Serialize, Deserialize)]
pub struct BundledVault {
    pub id: Uuid,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Preferred key to import as. Overridable on import, and generated when
    /// absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_key: Option<String>,

    /// The vault's raw file key, encrypted with the bundle key.
    pub wrapped_file_key: EncryptedBlob<RawFileKey>,

    /// The vault's already-encrypted items, copied verbatim from the on-disk
    /// vault.
    pub items: BTreeMap<Uuid, EncryptedVaultItem>,
}

impl ExportedBundle {
    /// AAD binding a wrapped file key to its bundle and vault.
    pub fn file_key_aad(bundle_id: Uuid, vault_id: Uuid) -> Vec<String> {
        vec![
            bundle_id.to_string(),
            vault_id.to_string(),
            "file-key".to_string(),
        ]
    }
}
