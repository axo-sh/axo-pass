use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::secrets::errors::Error;
use crate::secrets::vault_wrapper::VaultWrapper;

#[derive(Default)]
pub struct AppState {
    pub vaults_dir: PathBuf,
    pub vaults: HashMap<String, VaultWrapper>,
}

impl AppState {
    pub fn new(app_data_dir: PathBuf) -> Self {
        let vaults_dir = app_data_dir.join("vaults");
        let vaults = Self::discover_vaults(&vaults_dir);
        Self { vaults, vaults_dir }
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

    pub fn get_vault_mut(&mut self, name: &str) -> Result<&mut VaultWrapper, Error> {
        if !self.vaults.contains_key(name) {
            log::debug!(
                "Vault not loaded, reading vault from vaults dir: {:?}",
                self.vaults_dir
            );
            let vw = VaultWrapper::load(&self.vaults_dir, Some(name)).inspect_err(|e| {
                log::error!("Error reading vault: {:?}", e);
            })?;
            self.vaults.insert(name.to_string(), vw);
        }

        Ok(self.vaults.get_mut(name).unwrap())
    }

    pub fn get_vault(&mut self, name: &str) -> Result<&VaultWrapper, Error> {
        self.get_vault_mut(name).map(|v| &*v)
    }
}
