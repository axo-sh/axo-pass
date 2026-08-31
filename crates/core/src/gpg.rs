use std::process::Command;

use thiserror::Error;

use crate::core::find_bin_folder::find_bin_folder;

#[derive(Debug, Error)]
pub enum GpgError {
    #[error("Could not find gpg binary")]
    GpgNotFound,

    #[error("Failed to reload gpg-agent: {0}")]
    ReloadFailed(String),

    #[error("GPG signing failed: {0}")]
    SigningFailed(String),

    #[error("Failed to run gpg: {0}")]
    Io(#[from] std::io::Error),
}

/// Reloads gpg-agent and runs a test signing operation, to confirm GPG
/// signing works end-to-end (agent + pinentry reachable, key usable).
pub fn test_integration() -> Result<(), GpgError> {
    log::debug!("Starting GPG integration test");

    let Some(bin_dir) = find_bin_folder("gpg") else {
        return Err(GpgError::GpgNotFound);
    };
    log::debug!("Using gpg binary directory: {}", bin_dir.display());
    let updated_path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    // Reload the gpg-agent to ensure it picks up any changes
    let reload_output = Command::new("gpgconf")
        .args(["--reload", "gpg-agent"])
        .env("PATH", &updated_path)
        .output()
        .inspect_err(|e| log::error!("Failed to reload gpg-agent: {e}"))?;

    if !reload_output.status.success() {
        let stderr = String::from_utf8_lossy(&reload_output.stderr).to_string();
        log::debug!("GPG agent reload failed: {stderr}");
        return Err(GpgError::ReloadFailed(stderr));
    }

    let echo_output = Command::new("sh")
        .args(["-c", "echo 1234 | gpg -as -"])
        .env("PATH", &updated_path)
        .output()
        .inspect_err(|e| log::debug!("Failed to run gpg: {e}"))?;

    if echo_output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&echo_output.stderr).to_string();
        log::debug!("GPG signing failed: {stderr}");
        Err(GpgError::SigningFailed(stderr))
    }
}
