use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::anyhow;

use crate::secrets::vault_wrapper::VaultWrapper;

#[derive(Default)]
pub struct AppState {
    app_data_dir: PathBuf,
    pub vaults: HashMap<String, VaultWrapper>,
}

impl AppState {
    pub fn new(app_data_dir: PathBuf) -> Self {
        Self {
            app_data_dir,
            vaults: HashMap::new(),
        }
    }

    pub fn get_vault_mut(&mut self, name: &str) -> anyhow::Result<&mut VaultWrapper> {
        if !self.vaults.contains_key(name) {
            log::debug!(
                "Vault not loaded, reading vault from app data dir: {:?}",
                self.app_data_dir
            );
            let vw = VaultWrapper::load(&self.app_data_dir, Some(name)).map_err(|e| {
                log::error!("Error reading vault: {:?}", e);
                anyhow!("Failed to read vault: {e}")
            })?;
            self.vaults.insert(name.to_string(), vw.into());
        }

        Ok(self.vaults.get_mut(name).unwrap())
    }

    pub fn get_vault(&mut self, name: &str) -> anyhow::Result<&VaultWrapper> {
        self.get_vault_mut(name).map(|v| &*v)
    }
}
