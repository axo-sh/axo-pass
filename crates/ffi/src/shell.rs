use axo_pass_core::shell_integration;

use crate::*;

#[derive(uniffi::Record)]
pub struct ShellIntegrationStatus {
    /// Whether the `.zshrc` block is present and the `ap` symlink is in place.
    pub configured: bool,
    /// Whether the `ap` shell integration block is present in `.zshrc`.
    pub zshrc_configured: bool,
    /// Whether the shell hook is in `.zshrc` or was found in a new zsh.
    pub hook_configured: bool,
    /// Whether `~/.local/bin/ap` is a symlink to the current `ap` binary.
    pub symlink_ok: bool,
    /// Absolute path to the `.zshrc` file that was checked / written.
    pub zshrc_path: String,
    /// Absolute path to the `ap` symlink.
    pub symlink_path: String,
    /// Lines written between the sentinels.
    pub block: String,
}

fn shell_integration_status() -> ShellIntegrationStatus {
    let status = shell_integration::check_status();
    ShellIntegrationStatus {
        configured: status.configured(),
        zshrc_configured: status.zshrc_configured,
        hook_configured: status.hook_configured(),
        symlink_ok: status.symlink_ok,
        zshrc_path: status.zshrc_path.to_string_lossy().to_string(),
        symlink_path: status
            .symlink_path
            .map(|path| path.to_string_lossy().to_string())
            .unwrap_or_default(),
        block: shell_integration::block_body(),
    }
}

/// What a GPG key or subkey may be used for.
#[uniffi::export(async_runtime = "tokio")]
impl AxoPass {
    /// Report whether the `ap` shell integration block is present in `.zshrc`
    /// and the `ap` symlink is in place.
    /// Mirrors `get_shell_integration_status` in the Tauri app.
    pub fn check_shell_integration(&self) -> ShellIntegrationStatus {
        shell_integration_status()
    }

    /// Start a new zsh and report whether it loaded the shell hook, wherever
    /// the user added it. The result feeds later status checks.
    pub async fn verify_shell_hook(&self) -> Result<ShellIntegrationStatus, FfiError> {
        tokio::task::spawn_blocking(|| {
            shell_integration::verify_shell_hook();
            shell_integration_status()
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))
    }

    /// Create or refresh the `~/.local/bin/ap` symlink without touching
    /// `.zshrc`.
    pub async fn install_ap_symlink(&self) -> Result<ShellIntegrationStatus, FfiError> {
        tokio::task::spawn_blocking(|| {
            shell_integration::install_symlink().map_err(FfiError::Internal)?;
            Ok(shell_integration_status())
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }

    /// Append the `ap` shell integration block to `.zshrc` if not already
    /// present. Mirrors `configure_shell_integration` in the Tauri app.
    pub async fn write_shell_integration(&self) -> Result<ShellIntegrationStatus, FfiError> {
        tokio::task::spawn_blocking(|| {
            shell_integration::write_integration().map_err(FfiError::Internal)?;
            Ok(shell_integration_status())
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }
}
