use std::collections::BTreeMap;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{KeyInit, OsRng};
use secrecy::zeroize::Zeroize;
use secrecy::{SecretBox, SerializableSecret};
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use uuid::Uuid;

use crate::secrets::errors::Error;
use crate::secrets::keychain::managed_key::ManagedKey;

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
    pub value: SecretBox<VaultSecret>, // this is the encrypted value
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

    #[serde_as(as = "Base64")]
    pub file_key: Vec<u8>, // encrypted file key

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
            file_key: file_key.into_bytes(),
            items: BTreeMap::new(),
        })
    }
}
