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
    LazyLock::new(|| Mutex::new(AppConfig::load_or_create()));

#[derive(Serialize, Deserialize, Clone)]
pub struct AppConfig {
    #[serde(default = "uuid::Uuid::new_v4")]
    pub id: uuid::Uuid,
    pub update_check_disabled: Option<bool>,
    pub updates: Option<UpdateCheckRecord>,
}

impl Default for AppConfig {
    fn default() -> Self {
        AppConfig {
            id: uuid::Uuid::new_v4(),
            update_check_disabled: None,
            updates: None,
        }
    }
}

impl AppConfig {
    fn config_path() -> PathBuf {
        app_data_dir().join(CONFIG_FILENAME)
    }

    fn load_or_create() -> Self {
        let path = Self::config_path();
        let config: AppConfig = if path.exists() {
            fs::read_to_string(&path)
                .context("reading config file")
                .and_then(|data| toml::from_str(&data).context("parsing config file"))
                .unwrap_or_else(|e| {
                    log::warn!("Failed to load config file: {e:#}");
                    Self::default()
                })
        } else {
            log::debug!("Creating new config file at {}", path.display());
            Self::default()
        };

        if let Err(e) = config.save() {
            log::warn!("Failed to save initial config: {e}");
        }
        config
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
}
