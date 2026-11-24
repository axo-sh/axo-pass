use axo_pass_core::shell_integration;

use crate::*;

#[derive(uniffi::Record)]
pub struct ShellIntegrationStatus {
    /// Whether the `ap` shell integration block is present in `.zshrc`.
    pub configured: bool,
    /// Absolute path to the `.zshrc` file that was checked / written.
    pub zshrc_path: String,
    /// Lines written between the sentinels, including the bundled askpass path.
    pub block: String,
}

/// What a GPG key or subkey may be used for.
#[uniffi::export(async_runtime = "tokio")]
impl AxoPass {
    /// Report whether the `ap` shell integration block is present in `.zshrc`.
    /// Mirrors `get_shell_integration_status` in the Tauri app.
    pub fn check_shell_integration(&self) -> ShellIntegrationStatus {
        let (configured, path) = shell_integration::check_status();
        ShellIntegrationStatus {
            configured,
            zshrc_path: path.to_string_lossy().to_string(),
            block: shell_integration::block_body(),
        }
    }

    /// Append the `ap` shell integration block to `.zshrc` if not already
    /// present. Mirrors `configure_shell_integration` in the Tauri app.
    pub async fn write_shell_integration(&self) -> Result<ShellIntegrationStatus, FfiError> {
        tokio::task::spawn_blocking(|| {
            let path = shell_integration::write_integration().map_err(FfiError::Internal)?;
            Ok(ShellIntegrationStatus {
                configured: true,
                zshrc_path: path.to_string_lossy().to_string(),
                block: shell_integration::block_body(),
            })
        })
        .await
        .map_err(|e| FfiError::Internal(e.to_string()))?
    }
}
