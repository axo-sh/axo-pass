use std::path::PathBuf;

pub fn app_data_dir() -> PathBuf {
    // ~/Library/Application Support/Axo Pass
    dirs::data_dir().unwrap().join("Axo Pass")
}

pub fn log_data_dir() -> PathBuf {
    // ~/Library/Logs/Axo Pass
    dirs::home_dir().unwrap().join("Library/Logs/Axo Pass")
}

pub fn vaults_dir() -> PathBuf {
    app_data_dir().join("vaults")
}
