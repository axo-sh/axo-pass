use std::process::Command;

#[tauri::command]
pub async fn gpg_test_integration() -> Result<(), String> {
    // Reload the gpg-agent to ensure it picks up any changes
    let reload_output = Command::new("gpgconf")
        .args(["--reload", "gpg-agent"])
        .output()
        .map_err(|e| format!("Failed to reload gpg-agent: {e}"))?;

    if !reload_output.status.success() {
        let stderr = String::from_utf8_lossy(&reload_output.stderr);
        return Err(format!("gpgconf --reload failed: {stderr}"));
    }

    // Run echo 1234 | gpg -as -
    let echo_output = Command::new("sh")
        .args(["-c", "echo 1234 | gpg -as -"])
        .output()
        .map_err(|e| format!("Failed to run gpg: {e}"))?;

    if echo_output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&echo_output.stderr);
        Err(format!("GPG signing failed: {stderr}"))
    }
}
