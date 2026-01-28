use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use anyhow::{Context, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as b64;
use ssh_encoding::Encode;
use ssh_key::PrivateKey;
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

pub fn get_ssh_key_fingerprint(key_path: &str) -> Option<String> {
    if !PathBuf::from(&key_path).exists() {
        return None;
    }

    // try to read key directly
    if let Some(data) = fs::read_to_string(key_path).ok()
        && let Some(pk) = PrivateKey::from_openssh(data).ok()
    {
        return Some(compute_sha256_fingerprint(pk.public_key().key_data()));
    };

    // fallback to using ssh-keygen
    match std::process::Command::new("ssh-keygen")
        .arg("-l")
        .arg("-E")
        .arg("sha256")
        .arg("-f")
        .arg(key_path)
        .output()
    {
        Ok(output) => {
            if output.status.success()
                && let Ok(stdout) = String::from_utf8(output.stdout)
                && let Some(fingerprint) = stdout.split_whitespace().nth(1)
            {
                Some(
                    fingerprint
                        .split_once(':')
                        .map(|(_, fp)| fp.to_string())
                        .unwrap_or_else(|| fingerprint.to_owned()),
                )
            } else {
                log::error!(
                    "ssh-keygen failed or produced invalid output: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                None
            }
        },
        Err(err) => {
            log::error!("Failed to get key ID from ssh-keygen: {err}");
            None
        },
    }
}

pub fn compute_sha256_fingerprint(public_key: &KeyData) -> String {
    // custom method to generate without the prefix
    let fp = public_key.fingerprint(ssh_key::HashAlg::Sha256);
    b64.encode(fp.as_bytes())
}

// truncated fingerprint for logging
pub fn compute_short_sha256_fingerprint(public_key: &KeyData) -> String {
    let fp = public_key.fingerprint(ssh_key::HashAlg::Sha256);
    fp.to_string().strip_prefix(fp.prefix()).unwrap()[1..7].to_string() + "..."
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
