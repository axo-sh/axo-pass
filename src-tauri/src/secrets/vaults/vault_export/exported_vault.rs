use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::secrets::vaults::vault::encrypted_vault::EncryptedVaultItem;

/// Vault export format. Uses age-encrypted file key instead of
/// Secure Enclave-encrypted key
#[derive(Serialize, Deserialize)]
pub struct ExportedVault {
    pub id: Uuid,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_key: Option<String>, // default key to import as, but can be overridden on import

    pub age_file_key: String, // age ASCII-armored encrypted AES-256 key
    pub items: BTreeMap<Uuid, EncryptedVaultItem>,
}
