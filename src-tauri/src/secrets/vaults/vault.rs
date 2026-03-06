use std::collections::BTreeMap;
use std::path::PathBuf;

use aes_gcm::aead::{KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key};
use secrecy::zeroize::Zeroize;
use secrecy::{SecretBox, SerializableSecret};
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use uuid::Uuid;

use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::vaults::errors::Error;

// note: vault secret is already encrypted, but we also wrap it in SecretBox
// to additionally prevent it from being logged
#[derive(Serialize, Deserialize, Clone)]
pub struct VaultSecret(pub String);

impl SerializableSecret for VaultSecret {}

impl Zeroize for VaultSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
pub struct VaultItemCredential {
    pub id: Uuid,
    pub title: Option<String>,
    pub value: SecretBox<VaultSecret>,
}

#[derive(Serialize, Deserialize)]
pub struct VaultItem {
    pub id: Uuid,
    pub title: String,
    pub credentials: BTreeMap<String, VaultItemCredential>,
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct Vault {
    pub id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub file_key: VaultFileKey,
    pub items: BTreeMap<String, VaultItem>,
}

impl Vault {
    pub fn new(name: Option<String>, user_encryption_key: ManagedKey) -> Result<Self, Error> {
        log::debug!("Creating new vault...");
        log::debug!("Creating new vault: generating file key...");
        let actual_file_key = Aes256Gcm::generate_key(OsRng);
        log::debug!(
            "Creating new vault: encrypting file key with user key {user_encryption_key:?}..."
        );
        let Some(file_key) = user_encryption_key.encrypt(&actual_file_key) else {
            return Err(Error::VaultFileKeyEncryptionError);
        };
        let vault_id = Uuid::new_v4();
        Ok(Self {
            id: vault_id,
            name,
            file_key: VaultFileKey::Personal(file_key.into_bytes()),
            items: BTreeMap::new(),
        })
    }

    pub fn decrypt_file_key(&self, user_encryption_key: &ManagedKey) -> Result<Aes256Gcm, Error> {
        let candidate_keys = match &self.file_key {
            VaultFileKey::Personal(file_key_bytes) => vec![file_key_bytes],
            VaultFileKey::Members(members) => {
                members.iter().map(|member| &member.wrapped_key).collect()
            },
            VaultFileKey::MembersFile { .. } => {
                todo!()
            },
        };

        // try all candidate keys
        for file_key_bytes in candidate_keys {
            if let Some(decrypted_key) = user_encryption_key.decrypt(file_key_bytes) {
                #[allow(deprecated)]
                let key = Key::<Aes256Gcm>::from_slice(&decrypted_key);
                return Ok(Aes256Gcm::new(key));
            }
        }
        Err(Error::VaultFileKeyDecryptionError)
    }
}

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum VaultFileKey {
    Personal(#[serde_as(as = "Base64")] Vec<u8>),
    Members(Vec<VaultMember>),
    MembersFile { path: PathBuf },
}

#[derive(Serialize, Deserialize)]
pub struct VaultMember {
    pub public_key: String,
    pub wrapped_key: Vec<u8>, // file_key encrypted with this member's public key
}
