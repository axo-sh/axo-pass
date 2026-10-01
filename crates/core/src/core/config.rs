use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex};
use std::{fs, io};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::core::dirs::app_data_dir;
use crate::core::updates::{UpdateCheckRecord, UpdateCheckResult};

const CONFIG_FILENAME: &str = "config.toml";

pub static APP_CONFIG: LazyLock<Mutex<AppConfig>> =
    LazyLock::new(|| Mutex::new(AppConfig::load_or_create().unwrap()));

#[derive(Serialize, Deserialize, Clone)]
pub struct AppConfig {
    #[serde(default = "uuid::Uuid::new_v4")]
    pub id: uuid::Uuid,
    pub update_check_disabled: Option<bool>,
    pub updates: Option<UpdateCheckRecord>,
    #[serde(default)]
    pub external_vaults: BTreeMap<String, ExternalVaultConfig>,
    /// `~/.ssh` keys the Axo agent advertises and loads on first use, keyed by
    /// canonical `SHA256:...` fingerprint. This file is user-writable, so an
    /// entry grants nothing: every use of a loaded key still prompts unless an
    /// app grant applies.
    #[serde(default)]
    pub ssh_autoload: BTreeMap<String, AutoloadEntry>,
}

impl Default for AppConfig {
    fn default() -> Self {
        AppConfig {
            id: uuid::Uuid::new_v4(),
            update_check_disabled: None,
            updates: None,
            external_vaults: BTreeMap::new(),
            ssh_autoload: BTreeMap::new(),
        }
    }
}

impl AppConfig {
    fn config_path() -> PathBuf {
        app_data_dir().join(CONFIG_FILENAME)
    }

    fn load_or_create() -> Result<Self, anyhow::Error> {
        let path = Self::config_path();
        if path.exists() {
            fs::read_to_string(&path)
                .context("reading config file")
                .and_then(|data| toml::from_str(&data).context("parsing config file"))
        } else {
            log::debug!("Creating new config file at {}", path.display());
            let config = Self::default();
            if let Err(e) = config.save() {
                log::warn!("Failed to save initial config: {e}");
            }
            Ok(config)
        }
    }

    /// Read the config file as it is now. For long-running processes such as
    /// the agent, where [`APP_CONFIG`] would hold the copy read at startup.
    /// Returns the default config when the file is missing or invalid, and
    /// never creates it.
    pub fn load_fresh() -> Self {
        let path = Self::config_path();
        match fs::read_to_string(&path) {
            Ok(data) => toml::from_str(&data).unwrap_or_else(|e| {
                log::warn!("Failed to parse {}: {e}", path.display());
                Self::default()
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Self::default(),
            Err(e) => {
                log::warn!("Failed to read {}: {e}", path.display());
                Self::default()
            },
        }
    }

    pub fn save(&self) -> Result<(), io::Error> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let contents = toml::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(path, contents)
    }

    pub fn record_update_check(&mut self, result: UpdateCheckResult) {
        self.updates = Some(UpdateCheckRecord {
            checked_at: OffsetDateTime::now_utc(),
            result: result.clone(),
        });
    }

    pub fn add_external_vault(&mut self, vault_key: &str, path: PathBuf) -> Result<(), io::Error> {
        let vault_key = vault_key.to_string();
        if let Entry::Vacant(e) = self.external_vaults.entry(vault_key) {
            e.insert(ExternalVaultConfig { path });
            self.save()?;
        }
        Ok(())
    }

    /// Turn auto-load on or off for the key `fingerprint` (canonical
    /// `SHA256:...`) stored at `path`.
    pub fn set_ssh_autoload(
        &mut self,
        fingerprint: &str,
        path: PathBuf,
        enabled: bool,
    ) -> Result<(), io::Error> {
        if enabled {
            self.ssh_autoload
                .insert(fingerprint.to_string(), AutoloadEntry { path });
        } else {
            self.ssh_autoload.remove(fingerprint);
        }
        self.save()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ExternalVaultConfig {
    pub path: PathBuf,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AutoloadEntry {
    /// The private key file.
    pub path: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_autoload_round_trip() {
        let mut config = AppConfig::default();
        config.ssh_autoload.insert(
            "SHA256:abc".to_string(),
            AutoloadEntry {
                path: PathBuf::from("/Users/me/.ssh/id_ed25519"),
            },
        );
        let text = toml::to_string_pretty(&config).unwrap();
        let parsed: AppConfig = toml::from_str(&text).unwrap();
        assert_eq!(parsed.ssh_autoload, config.ssh_autoload);
    }

    #[test]
    fn ssh_autoload_defaults_to_empty() {
        let parsed: AppConfig =
            toml::from_str("id = \"6f1c2b7e-8a43-4c1d-9b55-0d2f3e4a5b6c\"").unwrap();
        assert!(parsed.ssh_autoload.is_empty());
    }
}
