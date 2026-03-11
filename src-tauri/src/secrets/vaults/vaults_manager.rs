use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use secrecy::ExposeSecret;

use crate::core::config::APP_CONFIG;
use crate::core::dirs::vaults_dir;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::vault_wrapper::{VaultWrapper, get_vault_encryption_key};

#[derive(Default)]
pub struct VaultsManager {
    vaults_dir: PathBuf,
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
        let user_encryption_key = get_vault_encryption_key()?;

        let vw = VaultWrapper::new_vault(name, &self.vaults_dir, vault_key, user_encryption_key)?;
        let vault_key = vw.key.clone(); // normalized key

        log::debug!("Vault created, saving new vault to disk...");
        vw.save()?;

        self.vaults.insert(vault_key.clone(), vw);
        Ok(self.vaults.get(&vault_key).unwrap())
    }

    fn discover_vaults(vaults_dir: &Path) -> HashMap<String, VaultWrapper> {
        let mut vaults = HashMap::new();

        // read vaults from default vault dir
        let entries = fs::read_dir(vaults_dir).into_iter().flatten().flatten();
        for entry in entries {
            let path = entry.path();

            // require json file
            if !path.is_file() || path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }

            // get vault key from file name
            let Some(key) = path.file_stem().map(|s| s.to_string_lossy().to_string()) else {
                continue;
            };

            // load vault using key (this is a bit redundant with VaultWrapper::load, which
            // recreates the path)
            match VaultWrapper::load_from_path(Some(key.to_owned()), &path) {
                Ok(vw) => {
                    vaults.insert(key.to_string(), vw);
                },
                Err(e) => log::error!("Skipping {key}, failed to load: {e:?}"),
            }
        }

        // read external vaults (as referenced in the app config)
        if let Ok(config) = APP_CONFIG.lock().inspect_err(|e| {
            log::error!("Failed to load external vaults: {e}");
        }) {
            for (vault_key, vault_config) in config.external_vaults.clone() {
                if let Ok(vault) =
                    VaultWrapper::load_from_path(Some(vault_key.clone()), &vault_config.path)
                {
                    if vaults.contains_key(&vault_key) {
                        log::error!(
                            "Vault with duplicate {vault_key} found at {}, skipping",
                            vault_config.path.display()
                        );
                        continue;
                    }
                    vaults.insert(vault_key, vault);
                }
            }
        }

        vaults
    }

    pub fn iter_vault_keys(&self) -> impl Iterator<Item = String> + '_ {
        self.vaults.keys().cloned()
    }

    pub fn update_vault_key(&mut self, old_key: &str, new_key: &str) -> Result<(), Error> {
        // remove vault using old_key
        let Some(mut vw) = self.vaults.remove(old_key) else {
            return Err(Error::VaultNotFound(old_key.to_string()));
        };

        // update its key and save it
        vw.set_vault_key(new_key.to_string())?;
        vw.save()?;

        // re-insert it with the new key
        self.vaults.insert(new_key.to_string(), vw);
        Ok(())
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
            let vw =
                VaultWrapper::load(&self.vaults_dir, Some(key.to_owned())).inspect_err(|e| {
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
            Ok(secret) => Ok(secret.map(|s| s.expose_secret().to_string())),
            Err(e) => {
                log::error!("Error retrieving {item_url}: {e:?}");
                Err(Error::SecretRetrievalFailed(item_url.to_string(), e.into()))
            },
        }
    }
}
