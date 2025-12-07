use std::path::PathBuf;
use std::process::Command;

// Running as a MacOS app means zshrc etc won't be sourced, and so PATH may not
// be configured with the gpg binary location eg if installed with Homebrew.
// This searches some common locations.
fn find_gpg_bin_folder() -> Option<PathBuf> {
    let gpg_path_output = Command::new("which").arg("gpg").output().ok()?;
    if gpg_path_output.status.success() {
        let gpg_path = String::from_utf8_lossy(&gpg_path_output.stdout)
            .trim()
            .to_string();
        let gpg_path = PathBuf::from(gpg_path);
        return gpg_path.parent().map(|p| p.to_path_buf());
    }

    // check homebrew location as well
    let brew_path = PathBuf::from("/opt/homebrew/bin");
    if brew_path.join("gpg").exists() {
        return Some(brew_path);
    }
    None
}

#[tauri::command]
pub async fn gpg_test_integration() -> Result<(), String> {
    log::debug!("Starting GPG integration test");

    let Some(bin_dir) = find_gpg_bin_folder() else {
        return Err("Could not find gpg binary".to_string());
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
        .inspect_err(|e| log::error!("Failed to reload gpg-agent: {e}"))
        .map_err(|e| format!("Failed to reload gpg-agent: {e}"))?;

    if !reload_output.status.success() {
        let stderr = String::from_utf8_lossy(&reload_output.stderr);
        log::debug!("GPG agent reload failed: {stderr}");
        return Err(format!("GPG agent reload failed: {stderr}"));
    }

    let echo_output = Command::new("sh")
        .args(["-c", "echo 1234 | gpg -as -"])
        .env("PATH", &updated_path)
        .output()
        .inspect_err(|e| log::debug!("Failed to run gpg: {e}"))
        .map_err(|e| format!("Failed to run gpg: {e}"))?;

    if echo_output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&echo_output.stderr);
        log::debug!("GPG signing failed: {stderr}");
        Err(format!("GPG signing failed: {stderr}"))
    }
}
