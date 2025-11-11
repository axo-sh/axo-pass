use std::path::PathBuf;

pub fn app_data_dir() -> PathBuf {
    dirs::data_dir().unwrap().join("AxoPass")
}

pub fn vaults_dir() -> PathBuf {
    app_data_dir().join("vaults")
}
