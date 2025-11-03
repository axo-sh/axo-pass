use std::collections::BTreeMap;
use std::path::Path;
use std::{fs, io};

use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as b64;
use secrecy::zeroize::Zeroize;
use secrecy::{ExposeSecret, SecretBox, SecretString, SerializableSecret};
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use uuid::Uuid;

use crate::secrets::errors::Error;
use crate::secrets::keychain::keychain_query::KeyChainQuery;
use crate::secrets::keychain::managed_key::{KeyClass, ManagedKey, ManagedKeyQuery};

pub const DEFAULT_VAULT: &str = "default-vault";

const VAULT_ENCRYPTION_KEY_LABEL: &str = "vault-encryption-key";

#[derive(Serialize, Deserialize, Clone)]
pub struct VaultSecret(String);

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
    value: SecretBox<VaultSecret>, // this is the encrypted value
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
    pub title: Option<String>,

    #[serde_as(as = "Base64")]
    file_key: Vec<u8>,

    #[serde(skip)]
    cipher: Option<Aes256Gcm>,

    #[serde(flatten)]
    pub data: BTreeMap<String, VaultItem>,
}

impl Vault {
    pub fn new(user_encryption_key: ManagedKey) -> Result<Self, Error> {
        log::debug!("Creating new vault...");
        log::debug!("Creating new vault: generating file key...");
        let actual_file_key = Aes256Gcm::generate_key(OsRng);
        log::debug!(
            "Creating new vault: encrypting file key with user key {user_encryption_key:?}..."
        );
        let Some(file_key) = user_encryption_key.encrypt(&actual_file_key) else {
            return Err(Error::VaultFileKeyEncryptionError);
        };
        log::debug!("Creating new vault: Creating cipher...");
        let cipher = Some(Aes256Gcm::new(&actual_file_key));
        log::debug!("Creating new vault: finalizing...");
        Ok(Self {
            id: Uuid::new_v4(),
            title: None,
            file_key: file_key.into_bytes(),
            cipher,
            data: BTreeMap::new(),
        })
    }

    pub fn unlock(&mut self) -> anyhow::Result<()> {
        // decrypt key &self.metadata.file_key with managed key
        let Some(managed_key) = ManagedKeyQuery::build()
            .with_label("vault-encryption-key")
            .with_key_class(KeyClass::Private)
            .one()?
        else {
            bail!("Managed key not found in keychain");
        };

        let Some(file_key_bytes) = managed_key.decrypt(&self.file_key) else {
            bail!("Failed to decrypt vault file key");
        };
        #[allow(deprecated)]
        let key = Key::<Aes256Gcm>::from_slice(&file_key_bytes);
        self.cipher = Some(Aes256Gcm::new(key));
        Ok(())
    }

    pub fn get_secret_by_url(&self, url: url::Url) -> anyhow::Result<Option<String>> {
        let item_key = url
            .path_segments()
            .and_then(|segments| segments.into_iter().next())
            .ok_or_else(|| anyhow!("URL missing item key: {}", url))?;
        let credential_key = url
            .path_segments()
            .and_then(|mut segments| {
                segments.next();
                segments.next()
            })
            .ok_or_else(|| anyhow!("URL missing credential key: {}", url))?;

        log::debug!(
            "Getting secret for item_key='{}' credential_key='{}'",
            item_key,
            credential_key
        );
        let secret = self.get_secret(item_key, credential_key)?;
        Ok(secret)
    }

    fn encrypt(&self, cred_value: SecretString, aad: &[u8]) -> anyhow::Result<Vec<u8>> {
        let cipher = self
            .cipher
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Vault is locked"))?;

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: cred_value.expose_secret().as_bytes(),
                    aad,
                },
            )
            .map_err(|err| anyhow!("encryption failure: {err}"))?;

        // first 12 bytes are the nonce
        Ok(nonce.iter().copied().chain(ciphertext).collect())
    }

    pub fn add_secret(
        &mut self,
        item_title: &str,
        item_key: Option<&str>,
        cred_title: &str,
        cred_key: &str,
        cred_value: SecretString,
    ) -> anyhow::Result<()> {
        // normalize values
        let item_title = item_title.trim();
        let re = regex::Regex::new(r"\s+").unwrap();
        let item_key = item_key.unwrap_or(item_title);
        let item_key = re.replace_all(&item_key.to_lowercase(), "_").to_string();
        let cred_key = re.replace_all(&cred_key.to_lowercase(), "_").to_string();

        // get ids and encrypt credential value
        let (item_id, cred_id) = self
            .data
            .get(&item_key)
            .map(|i| {
                (
                    i.id,
                    i.credentials
                        .get(&cred_key)
                        .map(|c| c.id)
                        .unwrap_or_else(Uuid::new_v4),
                )
            })
            .unwrap_or_else(|| (Uuid::new_v4(), Uuid::new_v4()));
        let aad = format!("{item_id}:{cred_id}");
        let secret_leaf = b64.encode(&self.encrypt(cred_value, aad.as_bytes())?);

        // get the entry in data or create it
        let entry = self
            .data
            .entry(item_key.clone())
            .and_modify(|i| {
                i.title = item_title.to_string();
            })
            .or_insert_with(|| VaultItem {
                id: item_id,
                title: item_title.to_string(),
                credentials: BTreeMap::new(),
            });

        entry
            .credentials
            .entry(cred_key.clone())
            .and_modify(|c| {
                c.title = Some(cred_title.to_string());
                c.value = SecretBox::new(Box::new(VaultSecret(secret_leaf.clone())))
            })
            .or_insert_with(move || VaultItemCredential {
                id: cred_id,
                title: Some(cred_title.to_string()),
                value: SecretBox::new(Box::new(VaultSecret(secret_leaf.clone()))),
            });

        Ok(())
    }

    pub fn get_secret(&self, key: &str, credential: &str) -> anyhow::Result<Option<String>> {
        let Some(cipher) = &self.cipher else {
            bail!("Vault is locked")
        };
        let Some(item) = self.data.get(key) else {
            return Ok(None);
        };

        let Some(cred) = item.credentials.get(credential) else {
            return Ok(None);
        };

        let ciphertext = b64.decode(cred.value.expose_secret().0.clone())?;
        #[allow(deprecated)]
        let nonce = Nonce::from_slice(&ciphertext[..12]); // 96-bits; unique per message
        let aad = format!("{}:{}", item.id, cred.id);
        log::debug!("Decrypting credential value with AAD='{aad}'");
        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &ciphertext[12..],
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|err| anyhow!("decryption failure: {err}"))?;
        let secret = String::from_utf8(plaintext)?;
        Ok(Some(secret))
    }
}

pub fn init_vault(app_data_dir: &Path) -> Result<Vault, Error> {
    let user_encryption_key = match ManagedKeyQuery::build()
        .with_label(VAULT_ENCRYPTION_KEY_LABEL)
        .with_key_class(KeyClass::Private)
        .one()
    {
        Ok(Some(user_encryption_key)) => user_encryption_key,
        Ok(None) => {
            // create new vault-encryption-key
            log::debug!("Vault encryption key not found, initializing new key...");
            ManagedKey::create(VAULT_ENCRYPTION_KEY_LABEL).map_err(|e| {
                Error::KeychainError(anyhow::anyhow!(
                    "Failed to create vault encryption key: {e}"
                ))
            })?
        },
        Err(e) => {
            return Err(Error::KeychainError(anyhow::anyhow!(
                "Failed to retrieve user encryption key: {e}"
            )));
        },
    };

    let mut vault = Vault::new(user_encryption_key)?;
    log::debug!("Vault created, saving new vault to disk...");
    vault
        .add_secret(
            "test item",
            Some("test_item"),
            "cred item",
            "cred_item",
            "super-secret-value".into(),
        )
        .map_err(|e| {
            Error::VaultAddSecretError(anyhow::anyhow!("Failed to add test secret to vault: {e}"))
        })?;

    save_vault(app_data_dir, DEFAULT_VAULT, &vault)?;
    Ok(vault)
}

pub fn read_vault(app_data_dir: &Path, vault_name: Option<&str>) -> Result<Vault, Error> {
    let vault_file_path = app_data_dir
        .join(vault_name.unwrap_or(DEFAULT_VAULT))
        .with_extension("json");
    log::debug!("Reading vault from file: {:?}", vault_file_path);
    let vault_data = fs::read_to_string(&vault_file_path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            Error::VaultNotFound
        } else {
            Error::VaultReadError(e)
        }
    })?;
    let vault: Vault =
        serde_json::from_str(&vault_data).map_err(Error::VaultDeserializationError)?;
    Ok(vault)
}

pub fn save_vault(app_data_dir: &Path, vault_name: &str, vault: &Vault) -> Result<(), Error> {
    // make sure app_data_dir exists
    fs::create_dir_all(app_data_dir).map_err(Error::VaultDirCreateError)?;

    let secrets_file_path = app_data_dir.join(vault_name).with_extension("json");
    let secrets_data =
        serde_json::to_string_pretty(vault).map_err(Error::VaultSerializationError)?;
    fs::write(&secrets_file_path, secrets_data).map_err(Error::VaultWriteError)?;
    Ok(())
}
