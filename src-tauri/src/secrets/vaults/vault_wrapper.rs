use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::{fs, io};

use secrecy::{SecretBox, SecretString};
use url::Url;

use crate::secrets::keychain::keychain_query::KeyChainQuery;
use crate::secrets::keychain::managed_key::{KeyClass, ManagedKey, ManagedKeyQuery};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::vault::encrypted_vault::EncryptedVault;
use crate::secrets::vaults::vault::{Vault, VaultItemCredentialOverview, VaultItemOverview};

pub const DEFAULT_VAULT: &str = "default";

const VAULT_ENCRYPTION_KEY_LABEL: &str = "vault-encryption-key";

enum VaultState {
    Locked { name: Option<String> },
    Unlocked { vault: Vault },
}

// in-memory representation of a vault
pub struct VaultWrapper {
    pub key: String,
    pub path: PathBuf,
    state: VaultState,
}

fn vault_file_path(vault_dir: &Path, vault_key: &str) -> Result<PathBuf, Error> {
    let vault_key =
        normalized_key(vault_key).ok_or_else(|| Error::InvalidVaultKey(vault_key.to_string()))?;
    Ok(vault_dir.join(format!("{vault_key}.json")))
}

impl VaultWrapper {
    pub fn new_vault(
        name: Option<String>,
        vault_dir: &Path,
        vault_key: &str,
        user_encryption_key: ManagedKey,
    ) -> Result<Self, Error> {
        log::debug!("Creating new vault...");
        let vault_key = normalized_key(vault_key)
            .ok_or_else(|| Error::InvalidVaultKey(vault_key.to_string()))?;

        let vault_path = vault_file_path(vault_dir, &vault_key)?;
        let vault_overview = Vault::new(name, user_encryption_key)?;
        let vault_wrapper = Self {
            key: vault_key.to_string(),
            path: vault_path,
            state: VaultState::Unlocked {
                vault: vault_overview,
            },
        };
        vault_wrapper.save()?;
        Ok(vault_wrapper)
    }

    pub fn load(vault_dir: &Path, vault_key: Option<String>) -> Result<Self, Error> {
        let vault_key = vault_key.unwrap_or(DEFAULT_VAULT.to_string());
        let vault_path = vault_file_path(vault_dir, &vault_key)?;
        Self::load_from_path(Some(vault_key), &vault_path)
    }

    pub fn load_from_path(vault_key: Option<String>, vault_path: &Path) -> Result<Self, Error> {
        let vault = EncryptedVault::load(vault_path)?;

        // todo: decide what to do for key for external vaults, some options:
        // 1. use file name as key
        // 2. use the vault.id as the key
        // 3. use the vault.name
        // 4. add a key field to the vault file and use that
        let vault_key = vault_key.unwrap_or_else(|| vault.id.to_string());
        if !validate_key(&vault_key) {
            return Err(Error::InvalidVaultKey(vault_key.to_string()));
        }

        Ok(Self {
            key: vault_key,
            path: vault_path.to_path_buf(),
            state: VaultState::Locked {
                name: vault.name.clone(),
            },
        })
    }

    pub fn unlock(&mut self) -> Result<(), Error> {
        if matches!(self.state, VaultState::Unlocked { .. }) {
            return Ok(());
        }
        let managed_key = get_vault_encryption_key()?;
        let encrypted_vault = EncryptedVault::load(&self.path)?;
        let vault = Vault::from_encrypted(managed_key, encrypted_vault)
            .inspect_err(|e| log::debug!("failed to build vault: {e}"))
            .map_err(|_| Error::VaultFileKeyDecryptionError)?;
        self.state = VaultState::Unlocked { vault };
        Ok(())
    }

    pub fn save(&self) -> Result<(), Error> {
        let Some(vault_dir) = self.path.parent() else {
            return Err(Error::VaultDirCreateError(io::Error::new(
                io::ErrorKind::NotFound,
                "Vault directory not found",
            )));
        };

        let VaultState::Unlocked { vault } = &self.state else {
            return Err(Error::VaultLocked);
        };
        let encrypted_vault = vault.into_encrypted()?;
        let vault_data = serde_json::to_string_pretty(&encrypted_vault)
            .map_err(Error::VaultSerializationError)?;

        fs::create_dir_all(vault_dir).map_err(Error::VaultDirCreateError)?;
        fs::write(self.path.clone(), vault_data).map_err(Error::VaultWriteError)?;
        Ok(())
    }

    pub fn set_vault_key(&mut self, new_vault_key: String) -> Result<(), Error> {
        if !validate_key(&new_vault_key) {
            return Err(Error::InvalidVaultKey(new_vault_key));
        }

        let vault_dir = self
            .path
            .parent()
            .expect("Vault path has no parent directory");
        let new_path = vault_file_path(vault_dir, &new_vault_key)?;

        if let Err(err) = std::fs::rename(&self.path, &new_path) {
            return Err(Error::VaultKeyUpdateFailed(err));
        }

        self.key = new_vault_key;
        self.path = new_path;
        self.save()?;
        Ok(())
    }

    pub fn vault_name(&self) -> Option<&str> {
        match &self.state {
            VaultState::Locked { name } => name.as_deref(),
            VaultState::Unlocked { vault, .. } => vault.name.as_deref(),
        }
    }

    pub fn set_vault_name(&mut self, new_name: String) -> Result<(), Error> {
        let VaultState::Unlocked { vault, .. } = &mut self.state else {
            return Err(Error::VaultLocked);
        };
        vault.name = Some(new_name);
        Ok(())
    }

    pub fn list_items(&self) -> Result<Vec<&VaultItemOverview>, Error> {
        let VaultState::Unlocked { vault, .. } = &self.state else {
            return Err(Error::VaultLocked);
        };
        Ok(vault.list_items())
    }

    pub fn get_item_overview(&self, item_key: &str) -> Result<Option<&VaultItemOverview>, Error> {
        let VaultState::Unlocked { vault, .. } = &self.state else {
            return Err(Error::VaultLocked);
        };
        match vault.get_item(item_key) {
            Ok(item) => Ok(Some(item)),
            Err(Error::InvalidItemKey(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Get or create an item by key. When the item already exists the
    /// item_title is ignored (consistent with how add_credential callers pass
    /// an empty title for existing items).
    pub fn add_item(
        &mut self,
        item_title: &str,
        item_key: &str,
    ) -> Result<&VaultItemOverview, Error> {
        let VaultState::Unlocked { vault, .. } = &mut self.state else {
            return Err(Error::VaultLocked);
        };
        vault.add_or_update_item(item_key, item_title)
    }

    pub fn update_item(
        &mut self,
        item_key: &str,
        item_title: String,
        credentials: BTreeMap<String, (String, SecretString)>,
    ) -> anyhow::Result<()> {
        self.add_item(&item_title, item_key)?;
        for (cred_key, (cred_title, secret)) in credentials {
            self.add_secret(item_key, &cred_key, &cred_title, secret)?;
        }
        Ok(())
    }

    pub fn delete_item(&mut self, item_key: &str) -> Result<(), Error> {
        let VaultState::Unlocked { vault, .. } = &mut self.state else {
            return Err(Error::VaultLocked);
        };
        vault.delete_item(item_key)
    }

    pub fn add_secret(
        &mut self,
        item_key: &str,
        cred_key: &str,
        cred_title: &str,
        cred_value: SecretString,
    ) -> Result<(), Error> {
        let VaultState::Unlocked { vault } = &mut self.state else {
            return Err(Error::VaultLocked);
        };
        vault.add_or_update_item_credential(item_key, cred_key, cred_title, cred_value)?;
        Ok(())
    }

    pub fn get_secret(
        &self,
        item_key: &str,
        cred_key: &str,
    ) -> Result<Option<SecretBox<String>>, Error> {
        let VaultState::Unlocked { vault } = &self.state else {
            return Err(Error::VaultLocked);
        };
        vault.get_item_credential_secret(item_key, cred_key)
    }

    pub fn get_secret_by_url(&self, url: Url) -> Result<Option<SecretBox<String>>, Error> {
        let mut segments = url
            .path_segments()
            .ok_or(Error::InvalidVaultItemReference("invalid url".to_string()))?;
        let item_key = segments.next().ok_or(Error::InvalidVaultItemReference(
            "missing item key".to_string(),
        ))?;
        let credential_key = segments.next().ok_or(Error::InvalidVaultItemReference(
            "missing credential key".to_string(),
        ))?;
        log::debug!("Parsed reference {item_key}/{credential_key}");
        self.get_secret(item_key, credential_key)
    }

    pub fn get_secret_overview(
        &self,
        item_key: &str,
        credential_key: &str,
    ) -> Result<Option<&VaultItemCredentialOverview>, Error> {
        let VaultState::Unlocked { vault, .. } = &self.state else {
            return Err(Error::VaultLocked);
        };
        match vault.get_item_credential(item_key, credential_key) {
            Ok(cred) => Ok(Some(cred)),
            Err(Error::InvalidCredentialKey(_)) | Err(Error::InvalidItemKey(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn delete_item_credential(&mut self, item_key: &str, cred_key: &str) -> Result<(), Error> {
        let VaultState::Unlocked { vault, .. } = &mut self.state else {
            return Err(Error::VaultLocked);
        };
        vault.delete_item_credential(item_key, cred_key)
    }
}

static WHITESPACE_REGEX: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"\s+").unwrap());

static VAULT_KEY_REGEX: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[a-z][a-z0-9-_]+[a-z0-9]$").unwrap());

pub fn validate_key(key: &str) -> bool {
    VAULT_KEY_REGEX.is_match(key)
}

pub fn normalized_key(key: &str) -> Option<String> {
    let normalized = WHITESPACE_REGEX
        .replace_all(&key.trim().to_lowercase(), "-")
        .to_string();
    if validate_key(&normalized) {
        Some(normalized)
    } else {
        None
    }
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
