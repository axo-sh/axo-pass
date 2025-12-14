use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::core::dirs::vaults_dir;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::vault_wrapper::{
    VaultWrapper, get_vault_encryption_key, normalize_key, validate_key,
};

#[derive(Default)]
pub struct VaultsManager {
    pub vaults_dir: PathBuf,
    vaults: HashMap<String, VaultWrapper>,
}

impl VaultsManager {
    pub fn new() -> Self {
        let vaults_dir = vaults_dir();
        Self {
            vaults: Self::discover_vaults(&vaults_dir),
            vaults_dir: vaults_dir.to_owned(),
        }
    }

    pub fn add_vault(
        &mut self,
        name: Option<String>,
        vault_key: &str,
    ) -> Result<&VaultWrapper, Error> {
        let vault_key = normalize_key(vault_key);
        if !validate_key(&vault_key) {
            return Err(Error::InvalidVaultKey(vault_key));
        }

        let user_encryption_key = get_vault_encryption_key()?;

        let vw = VaultWrapper::new_vault(name, &self.vaults_dir, &vault_key, user_encryption_key)?;

        log::debug!("Vault created, saving new vault to disk...");
        vw.save()?;

        self.vaults.insert(vault_key.clone(), vw);
        Ok(self.vaults.get(&vault_key).unwrap())
    }

    fn discover_vaults(vaults_dir: &Path) -> HashMap<String, VaultWrapper> {
        let mut vaults = HashMap::new();
        if let Ok(entries) = fs::read_dir(vaults_dir) {
            for path in entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_file() && p.extension().and_then(|s| s.to_str()) == Some("json"))
            {
                if let Some(file_stem) = path.file_stem().and_then(|s| s.to_str()) {
                    match VaultWrapper::load(vaults_dir, Some(file_stem)) {
                        Ok(vw) => {
                            vaults.insert(file_stem.to_string(), vw);
                        },
                        Err(e) => {
                            log::error!("Skipping {file_stem}, failed to load: {e:?}");
                        },
                    }
                }
            }
        }

        vaults
    }

    pub fn iter_vault_keys(&self) -> impl Iterator<Item = String> + '_ {
        self.vaults.keys().cloned()
    }

    pub fn iter_vaults(&self) -> impl Iterator<Item = (&String, &VaultWrapper)> {
        self.vaults.iter()
    }

    pub fn get_vault_mut(&mut self, key: &str) -> Result<&mut VaultWrapper, Error> {
        if !self.vaults.contains_key(key) {
            log::debug!(
                "Vault not loaded, reading vault from vaults dir: {}",
                self.vaults_dir.display()
            );
            let vw = VaultWrapper::load(&self.vaults_dir, Some(key)).inspect_err(|e| {
                log::error!("Error reading vault: {:?}", e);
            })?;
            self.vaults.insert(key.to_string(), vw);
        }

        Ok(self.vaults.get_mut(key).unwrap())
    }

    pub fn get_vault(&mut self, key: &str) -> Result<&VaultWrapper, Error> {
        self.get_vault_mut(key).map(|v| &*v)
    }

    pub fn delete_vault(&mut self, key: &str) -> Result<(), Error> {
        // remove from in-memory map
        let Some(vw) = self.vaults.remove(key) else {
            return Err(Error::VaultNotFound(key.to_string()));
        };

        // macOS 15+ "trash" to move the file to the trash instead of deleting it
        // permanently
        Command::new("trash")
            .arg(&vw.path)
            .output()
            .map_err(Error::VaultDeleteError)?;
        Ok(())
    }

    pub fn get_secret_by_url(&mut self, item_url: &str) -> Result<Option<String>, Error> {
        let Ok(u) = url::Url::parse(item_url) else {
            return Err(Error::InvalidVaultItemReference(item_url.to_string()));
        };
        if u.scheme() != "axo" {
            return Err(Error::InvalidVaultItemReference(item_url.to_string()));
        }
        let Some(vault_key) = u.host_str() else {
            return Err(Error::InvalidVaultItemReference(item_url.to_string()));
        };
        let Some(vault) = self.vaults.get_mut(vault_key) else {
            return Err(Error::VaultNotFound(vault_key.to_string()));
        };
        vault.unlock().inspect_err(|e| {
            log::error!("Error unlocking vault {vault_key}: {e:?}");
        })?;
        match vault.get_secret_by_url(u) {
            Ok(secret) => Ok(secret),
            Err(e) => {
                log::error!("Error retrieving {item_url}: {e:?}");
                Err(Error::SecretRetrievalFailed(item_url.to_string(), e))
            },
        }
    }
}
