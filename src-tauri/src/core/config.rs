use std::path::PathBuf;
use std::sync::{LazyLock, Mutex};
use std::{fs, io};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::core::dirs::app_data_dir;
use crate::core::updates::{UpdateCheckRecord, UpdateCheckResult};

const CONFIG_FILENAME: &str = "config.toml";

pub static APP_CONFIG: LazyLock<Mutex<AppConfig>> =
    LazyLock::new(|| Mutex::new(AppConfig::load_or_create()));

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct AppConfig {
    pub update_check_disabled: Option<bool>,
    pub updates: Option<UpdateCheckRecord>,
}

impl AppConfig {
    fn config_path() -> PathBuf {
        app_data_dir().join(CONFIG_FILENAME)
    }

    fn load_or_create() -> Self {
        let path = Self::config_path();
        if path.exists() {
            match fs::read_to_string(&path) {
                Ok(contents) => match toml::from_str(&contents) {
                    Ok(config) => return config,
                    Err(e) => {
                        log::warn!("Failed to parse config file: {}", e);
                    },
                },
                Err(e) => {
                    log::warn!("Failed to read config file: {}", e);
                },
            }
        }
        let config = Self::default();
        if let Err(e) = config.save() {
            log::warn!("Failed to save initial config: {}", e);
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
