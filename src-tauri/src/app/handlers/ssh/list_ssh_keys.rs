use std::path::Path;

use serde::{Deserialize, Serialize};
use ssh_key::{Algorithm, HashAlg, PublicKey};
use typeshare::typeshare;

use crate::secrets::keychain::generic_password::PasswordEntry;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub struct SshKeyInfo {
    pub name: String,
    pub path: String,
    pub key_type: SshKeyType,
    pub has_public_key: bool,
    pub fingerprint: Option<String>,
    pub has_saved_password: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub enum SshKeyType {
    Rsa,
    Ed25519,
    Ecdsa,
    Dsa,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub struct ListSshKeysResponse {
    pub keys: Vec<SshKeyInfo>,
}

#[tauri::command]
pub async fn list_ssh_keys() -> Result<ListSshKeysResponse, String> {
    let ssh_dir = dirs::home_dir()
        .ok_or("Could not determine home directory")?
        .join(".ssh");

    if !ssh_dir.exists() {
        return Ok(ListSshKeysResponse { keys: Vec::new() });
    }

    let entries =
        std::fs::read_dir(&ssh_dir).map_err(|e| format!("Failed to read .ssh directory: {e}"))?;

    let mut keys = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();

        if !path.is_file() {
            continue;
        }

        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name.to_string(),
            None => continue,
        };

        // Skip public keys, config files, and known_hosts
        if file_name.ends_with(".pub")
            || file_name == "config"
            || file_name == "known_hosts"
            || file_name == "known_hosts.old"
            || file_name == "authorized_keys"
        {
            continue;
        }

        // Check if this looks like a private key and parse it
        if let Some((key_type, fingerprint)) = parse_ssh_key(&path) {
            let public_key_path = path.with_extension("pub");
            let has_public_key = public_key_path.exists();
            let path_str = path.to_string_lossy().to_string();
            let has_saved_password = fingerprint
                .as_ref()
                .and_then(|fp| PasswordEntry::ssh(fp).exists().ok())
                .unwrap_or(false);

            keys.push(SshKeyInfo {
                name: file_name,
                path: path_str,
                key_type,
                has_public_key,
                fingerprint,
                has_saved_password,
            });
        }
    }

    keys.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(ListSshKeysResponse { keys })
}

/// Parse an SSH key file and return the key type and fingerprint.
/// Tries to read the public key file first (works for all keys),
/// then falls back to parsing the private key directly (only works for
/// unencrypted keys).
fn parse_ssh_key(path: &Path) -> Option<(SshKeyType, Option<String>)> {
    // First, check if the file looks like a private key by reading the first line
    let content = std::fs::read_to_string(path).ok()?;
    let first_line = content.lines().next()?;

    if !first_line.contains("PRIVATE KEY") {
        return None;
    }

    // Try to read the corresponding public key file first (most reliable)
    let public_key_path = path.with_extension("pub");
    if let Ok(pubkey) = PublicKey::read_openssh_file(&public_key_path) {
        let key_type = algorithm_to_key_type(pubkey.algorithm());
        let fingerprint = pubkey.fingerprint(HashAlg::Sha256).to_string();
        // Remove the "SHA256:" prefix
        let fingerprint = fingerprint
            .strip_prefix("SHA256:")
            .unwrap_or(&fingerprint)
            .to_string();
        return Some((key_type, Some(fingerprint)));
    }

    // Fall back to parsing the private key (only works for unencrypted keys)
    if let Ok(privkey) = ssh_key::PrivateKey::read_openssh_file(path) {
        let key_type = algorithm_to_key_type(privkey.algorithm());
        let fingerprint = privkey.fingerprint(HashAlg::Sha256).to_string();
        // Remove the "SHA256:" prefix
        let fingerprint = fingerprint
            .strip_prefix("SHA256:")
            .unwrap_or(&fingerprint)
            .to_string();
        return Some((key_type, Some(fingerprint)));
    }

    // If we can't parse the key, detect type from content and return without
    // fingerprint
    let key_type = detect_key_type_from_content(&content);
    Some((key_type, None))
}

fn algorithm_to_key_type(algorithm: Algorithm) -> SshKeyType {
    match algorithm {
        Algorithm::Rsa { .. } => SshKeyType::Rsa,
        Algorithm::Ed25519 => SshKeyType::Ed25519,
        Algorithm::Ecdsa { .. } => SshKeyType::Ecdsa,
        Algorithm::Dsa => SshKeyType::Dsa,
        _ => SshKeyType::Unknown,
    }
}

fn detect_key_type_from_content(content: &str) -> SshKeyType {
    let first_line = content.lines().next().unwrap_or("");

    if first_line.contains("RSA") {
        SshKeyType::Rsa
    } else if first_line.contains("EC") {
        SshKeyType::Ecdsa
    } else if first_line.contains("DSA") {
        SshKeyType::Dsa
    } else if first_line.contains("OPENSSH") {
        // OpenSSH format - check for key type hints in the content
        if content.contains("ssh-ed25519") {
            SshKeyType::Ed25519
        } else if content.contains("ssh-rsa") {
            SshKeyType::Rsa
        } else if content.contains("ecdsa") {
            SshKeyType::Ecdsa
        } else {
            // Default to Unknown for encrypted OpenSSH keys we can't parse
            SshKeyType::Unknown
        }
    } else {
        SshKeyType::Unknown
    }
}
