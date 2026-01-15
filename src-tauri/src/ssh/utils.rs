use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use anyhow::{Context, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as b64;
use ssh_encoding::Encode;
use ssh_key::public::KeyData;

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

pub fn compute_sha256_fingerprint(public_key: &KeyData) -> String {
    // custom method to generate without the prefix
    let fp = public_key.fingerprint(ssh_key::HashAlg::Sha256);
    b64.encode(fp.as_bytes())
}

pub fn compute_md5_fingerprint(public_key: &KeyData) -> String {
    let mut encoded = Vec::new();
    public_key
        .encode(&mut encoded)
        .expect("Failed to encode public key");

    let digest = md5::compute(&encoded);
    digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}
