use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use anyhow::{Context, anyhow};

pub fn ssh_dir_path() -> Result<PathBuf, anyhow::Error> {
    Ok(dirs::home_dir()
        .ok_or(anyhow!("Could not determine home directory"))?
        .join(".ssh"))
}

pub fn get_ssh_dir() -> Result<PathBuf, anyhow::Error> {
    let ssh_dir = ssh_dir_path()?;
    if !ssh_dir.exists() {
        fs::create_dir_all(&ssh_dir).context("Failed to create .ssh directory")?;
        fs::set_permissions(&ssh_dir, Permissions::from_mode(0o700))
            .context("Failed to set .ssh permissions")?;
    }
    Ok(ssh_dir)
}
