use std::path::PathBuf;

use crate::core::provenance::team_identifier;

/// The App Group shared by the app and its AutoFill credential provider
/// extension, minus the team identifier prefix macOS requires.
pub const APP_GROUP_SUFFIX: &str = "com.breakfastlabs.frittata.shared";

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

/// The App Group identifier: `<team>.com.breakfastlabs.frittata.shared`.
///
/// The team identifier comes from our own code signature. An unsigned or ad-hoc
/// local build has none, and the extension cannot run under one either, so this
/// returns `None` rather than guessing an identifier nothing will use.
///
/// The app never touches the group's container directory. An unsandboxed app
/// doing so raises the "access data from other apps" consent prompt.
pub fn app_group_identifier() -> Option<String> {
    let team = team_identifier()?;
    Some(format!("{team}.{APP_GROUP_SUFFIX}"))
}
