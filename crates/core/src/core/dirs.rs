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

/// The App Group container both the app and the sandboxed AutoFill extension
/// can reach: ~/Library/Group Containers/<team>.com.breakfastlabs.frittata.shared
///
/// The team identifier comes from our own code signature. An unsigned or ad-hoc
/// local build has none, and the extension cannot run under one either, so this
/// returns `None` rather than guessing a path nothing will use.
pub fn app_group_dir() -> Option<PathBuf> {
    let team = team_identifier()?;
    Some(
        dirs::home_dir()?
            .join("Library/Group Containers")
            .join(format!("{team}.{APP_GROUP_SUFFIX}")),
    )
}
