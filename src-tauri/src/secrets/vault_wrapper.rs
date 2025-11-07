use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::{fs, io};

use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use anyhow::anyhow;
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as b64;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use uuid::Uuid;

use crate::app::vault::schemas::VaultSchema;
use crate::secrets::errors::Error;
use crate::secrets::keychain::keychain_query::KeyChainQuery;
use crate::secrets::keychain::managed_key::{KeyClass, ManagedKey, ManagedKeyQuery};
use crate::secrets::vault::{Vault, VaultItem, VaultItemCredential, VaultSecret};

pub const DEFAULT_VAULT: &str = "default-vault";

const VAULT_ENCRYPTION_KEY_LABEL: &str = "vault-encryption-key";

pub struct VaultWrapper {
    pub key: String,
    pub path: PathBuf,
    pub cipher: Option<Aes256Gcm>,
    vault: Vault,
}

impl VaultWrapper {
    pub fn new_vault(
        name: Option<String>,
        vault_dir: &Path,
        vault_key: &str,
        user_encryption_key: ManagedKey,
    ) -> Result<Self, Error> {
        let vault = Vault::new(name, user_encryption_key)?;
        let vault_path = vault_dir.join(vault_key).with_extension("json");
        let vault_wrapper = Self {
            key: vault_key.to_string(),
            path: vault_path,
            cipher: None,
            vault,
        };
        vault_wrapper.save()?;
        Ok(vault_wrapper)
    }

    pub fn load(vault_dir: &Path, vault_key: Option<&str>) -> Result<VaultWrapper, Error> {
        let vault_key = vault_key.unwrap_or(DEFAULT_VAULT);
        let vault_file_path = vault_dir.join(vault_key).with_extension("json");
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
        Ok(VaultWrapper {
            key: vault_key.to_string(),
            path: vault_file_path,
            cipher: None,
            vault,
        })
    }

    pub fn unlock(&mut self) -> Result<(), Error> {
        let managed_key = get_vault_encryption_key()?;
        self.unlock_with_key(managed_key)
    }

    pub fn unlock_with_key(&mut self, managed_key: ManagedKey) -> Result<(), Error> {
        if self.cipher.is_some() {
            return Ok(());
        }
        let Some(file_key_bytes) = managed_key.decrypt(&self.vault.file_key) else {
            return Err(Error::VaultFileKeyDecryptionError);
        };

        #[allow(deprecated)]
        let key = Key::<Aes256Gcm>::from_slice(&file_key_bytes);
        self.cipher = Some(Aes256Gcm::new(key));
        Ok(())
    }

    pub fn save(&self) -> Result<(), Error> {
        let Some(vault_dir) = self.path.parent() else {
            return Err(Error::VaultDirCreateError(io::Error::new(
                io::ErrorKind::NotFound,
                "Vault directory not found",
            )));
        };

        fs::create_dir_all(vault_dir).map_err(Error::VaultDirCreateError)?;
        let vault_data =
            serde_json::to_string_pretty(&self.vault).map_err(Error::VaultSerializationError)?;
        fs::write(self.path.clone(), vault_data).map_err(Error::VaultWriteError)?;
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

    fn encrypt(&self, cred_value: SecretString, aad: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = self.cipher.as_ref().ok_or_else(|| Error::VaultLocked)?;

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: cred_value.expose_secret().as_bytes(),
                    aad,
                },
            )
            .inspect_err(|e| log::debug!("encryption error: {e}"))
            .map_err(|_| Error::VaultSecretEncryptionError)?;

        // first 12 bytes are the nonce
        Ok(nonce.iter().copied().chain(ciphertext).collect())
    }

    pub fn list_items(&self) -> impl Iterator<Item = (&String, &VaultItem)> {
        self.vault.data.iter()
    }

    pub fn add_item(&mut self, item_title: String, item_key: String) {
        self.vault
            .data
            .entry(normalize_key(&item_key))
            .or_insert_with(|| VaultItem {
                id: Uuid::new_v4(),
                title: item_title.trim().to_string(),
                credentials: BTreeMap::new(),
            });
    }

    pub fn update_item(
        &mut self,
        item_key: &str,
        new_title: String,
        credentials: BTreeMap<String, (Option<String>, Option<SecretString>)>,
    ) -> anyhow::Result<()> {
        let new_title = new_title.trim();
        let mut encrypted_values: BTreeMap<String, String> = BTreeMap::new();
        let item = self
            .vault
            .data
            .get(item_key)
            .ok_or_else(|| anyhow!("Item with key {item_key} not found"))?;

        for (cred_key, (_, new_cred_value)) in &credentials {
            if let Some(new_value) = new_cred_value
                && let Some(credential) = item.credentials.get(cred_key)
            {
                let aad = format!("{}:{}", item.id, credential.id);
                let encrypted = self.encrypt(new_value.clone(), aad.as_bytes())?;
                let secret_leaf = b64.encode(&encrypted);
                encrypted_values.insert(cred_key.clone(), secret_leaf);
            }
        }

        // Now update the item with mutable access
        let item = self
            .vault
            .data
            .get_mut(item_key)
            .ok_or_else(|| anyhow!("Item with key {item_key} not found"))?;

        item.title = new_title.to_string();

        // Update credentials by their keys
        for (cred_key, (new_cred_title, _)) in credentials {
            if let Some(credential) = item.credentials.get_mut(&cred_key) {
                // Update title if provided
                if let Some(title) = new_cred_title {
                    credential.title = Some(title);
                }

                // Update encrypted value if we encrypted one
                if let Some(secret_leaf) = encrypted_values.get(&cred_key) {
                    credential.value = SecretBox::new(Box::new(VaultSecret(secret_leaf.clone())));
                }
            }
        }

        Ok(())
    }

    pub fn delete_item(&mut self, item_key: &str) -> anyhow::Result<()> {
        if self.vault.data.remove(item_key).is_none() {
            log::debug!("Did not find item {item_key} to delete");
        };
        Ok(())
    }

    pub fn add_secret(
        &mut self,
        item_title: &str,
        item_key: &str,
        cred_title: &str,
        cred_key: &str,
        cred_value: SecretString,
    ) -> Result<(), Error> {
        // normalize values
        let item_title = item_title.trim();
        let item_key = normalize_key(item_key);
        let cred_key = normalize_key(cred_key);

        // get ids and encrypt credential value
        let (item_id, cred_id) = self
            .vault
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
            .vault
            .data
            .entry(item_key.clone())
            .and_modify(|i| {
                // Only update title if a non-empty title is provided
                if !item_title.is_empty() {
                    i.title = item_title.to_string();
                }
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

    pub fn get_secret(
        &self,
        item_key: &str,
        credential_key: &str,
    ) -> Result<Option<String>, Error> {
        let Some(cipher) = &self.cipher else {
            return Err(Error::VaultLocked);
        };
        let Some(item) = self.vault.data.get(item_key) else {
            return Ok(None);
        };
        let Some(cred) = item.credentials.get(credential_key) else {
            return Ok(None);
        };

        let ciphertext = b64
            .decode(cred.value.expose_secret().0.clone())
            .inspect_err(|e| log::debug!("base64 decode error: {e}"))
            .map_err(|_| Error::VaultSecretDecryptionError)?;

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
            .inspect_err(|err| log::debug!("decryption failure: {err}"))
            .map_err(|_| Error::VaultSecretDecryptionError)?;

        let secret = String::from_utf8(plaintext)
            .inspect_err(|err| log::debug!("decryption failure: {err}"))
            .map_err(|_| Error::VaultSecretDecryptionError)?;
        Ok(Some(secret))
    }

    pub fn get_item_credential(
        &self,
        item_key: &str,
        credential_key: &str,
    ) -> anyhow::Result<Option<&VaultItemCredential>> {
        let item = self
            .vault
            .data
            .get(item_key)
            .ok_or_else(|| anyhow!("Item {item_key} not found."))?;

        let credential = item
            .credentials
            .get(credential_key)
            .ok_or_else(|| anyhow!("Credential {item_key}/{credential_key} not found"))?;

        Ok(Some(credential))
    }

    pub fn delete_item_credential(
        &mut self,
        item_key: &str,
        credential_key: &str,
    ) -> anyhow::Result<()> {
        let item = self
            .vault
            .data
            .get_mut(item_key)
            .ok_or_else(|| anyhow!("Item {item_key} not found."))?;

        if item.credentials.remove(credential_key).is_none() {
            log::debug!("Could not not find credential {item_key}/{credential_key} to delete");
        };

        Ok(())
    }
}

static WHITESPACE_REGEX: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"\s+").unwrap());

pub fn normalize_key(key: &str) -> String {
    WHITESPACE_REGEX
        .replace_all(&key.trim().to_lowercase(), "-")
        .to_string()
}

pub fn get_vault_encryption_key() -> Result<ManagedKey, Error> {
    match ManagedKeyQuery::build()
        .with_label(VAULT_ENCRYPTION_KEY_LABEL)
        .with_key_class(KeyClass::Private)
        .one()
    {
        Ok(Some(user_encryption_key)) => Ok(user_encryption_key),
        Ok(None) => {
            log::debug!("Vault encryption key not found, initializing new key...");
            Ok(ManagedKey::create(VAULT_ENCRYPTION_KEY_LABEL).map_err(Error::KeyCreationFailed)?)
        },
        Err(e) => Err(Error::KeyRetrievalFailed(e)),
    }
}

impl From<&VaultWrapper> for VaultSchema {
    fn from(vw: &VaultWrapper) -> Self {
        VaultSchema {
            key: vw.key.clone(),
            title: vw.vault.name.clone(),
            data: vw
                .vault
                .data
                .iter()
                .map(|(key, item)| (key.clone(), item.into()))
                .collect(),
        }
    }
}
