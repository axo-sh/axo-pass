use crate::app::config::AppConfig;
use crate::secrets::vaults_manager::VaultsManager;

#[derive(Default)]
pub struct AppState {
    pub vaults: VaultsManager,
    pub config: AppConfig,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            vaults: VaultsManager::new(),
            config: AppConfig::load_or_create(),
        }
    }
}
