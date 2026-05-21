use axo_pass_core::secrets::vaults::VaultsManager;

#[derive(Default)]
pub struct AppState {
    pub vaults: VaultsManager,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            vaults: VaultsManager::new(),
        }
    }
}
