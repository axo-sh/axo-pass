//! Auto-loaded keys: `~/.ssh` keys the Axo agent advertises from the start and
//! loads the first time something signs with them.
//!
//! The list lives in `config.toml`, which the agent can read. The file is
//! user-writable, so an entry grants nothing on its own: the agent asks for
//! confirmation on every use of a loaded key unless an app grant applies.

use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use ssh_key::{HashAlg, PrivateKey, PublicKey};

use crate::core::config::{APP_CONFIG, AppConfig};

/// One configured key, with its public half read from disk.
#[derive(Debug, Clone)]
pub struct AutoloadKey {
    /// Canonical `SHA256:...` fingerprint.
    pub fingerprint: String,
    /// The private key file.
    pub path: PathBuf,
    pub public_key: PublicKey,
}

/// Canonical `SHA256:...` fingerprint of a public key.
fn fingerprint(public_key: &PublicKey) -> String {
    public_key.fingerprint(HashAlg::Sha256).to_string()
}

/// The public key of the private key file at `path`. OpenSSH stores the public
/// key unencrypted, so this works for encrypted keys too. Encrypted keys keep
/// their comment in the encrypted part, so the comment comes from the `.pub`
/// file when it holds the same key.
pub fn read_public_key(path: &Path) -> anyhow::Result<PublicKey> {
    let private = PrivateKey::read_openssh_file(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let public = private.public_key();
    if !public.comment().is_empty() {
        return Ok(public.clone());
    }
    match PublicKey::read_openssh_file(&path.with_extension("pub")) {
        Ok(file) if file.key_data() == public.key_data() => {
            Ok(PublicKey::new(public.key_data().clone(), file.comment()))
        },
        _ => Ok(public.clone()),
    }
}

/// Read and, if needed, decrypt the private key at `path`. Fails when the file
/// no longer holds the key `expected_fingerprint`.
pub fn read_private_key(
    path: &Path,
    expected_fingerprint: &str,
    passphrase: Option<&str>,
) -> anyhow::Result<PrivateKey> {
    let private = PrivateKey::read_openssh_file(path)
        .with_context(|| format!("reading {}", path.display()))?;
    if fingerprint(private.public_key()) != expected_fingerprint {
        bail!(
            "{} no longer holds the key {expected_fingerprint}",
            path.display()
        );
    }
    if !private.is_encrypted() {
        return Ok(private);
    }
    let passphrase = passphrase.ok_or_else(|| anyhow!("{} is encrypted", path.display()))?;
    private
        .decrypt(passphrase)
        .map_err(|e| anyhow!("decrypting {}: {e}", path.display()))
}

/// Whether the private key at `path` is encrypted.
pub fn is_encrypted(path: &Path) -> anyhow::Result<bool> {
    let private = PrivateKey::read_openssh_file(path)
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(private.is_encrypted())
}

/// The configured keys, read from `config` as it is on disk now. Entries whose
/// file is unreadable or holds a different key are skipped.
pub fn list(config: &AppConfig) -> Vec<AutoloadKey> {
    config
        .ssh_autoload
        .iter()
        .filter_map(|(expected, entry)| {
            let public_key = read_public_key(&entry.path)
                .inspect_err(|e| log::warn!("Skipping auto-load key {expected}: {e:#}"))
                .ok()?;
            if fingerprint(&public_key) != *expected {
                log::warn!(
                    "Skipping auto-load key {expected}: {} holds a different key",
                    entry.path.display()
                );
                return None;
            }
            Some(AutoloadKey {
                fingerprint: expected.clone(),
                path: entry.path.clone(),
                public_key,
            })
        })
        .collect()
}

/// Turn auto-load on or off for the key `fingerprint` (canonical
/// `SHA256:...`) stored at `path`. Enabling checks that the file holds that
/// key. The key's app grants are kept either way: they apply only while
/// auto-load is on.
pub fn set(fingerprint_sha256: &str, path: &Path, enabled: bool) -> anyhow::Result<()> {
    if enabled {
        let public_key = read_public_key(path)?;
        if fingerprint(&public_key) != fingerprint_sha256 {
            bail!(
                "{} does not hold the key {fingerprint_sha256}",
                path.display()
            );
        }
    }

    APP_CONFIG
        .lock()
        .map_err(|e| anyhow!("config lock poisoned: {e}"))?
        .set_ssh_autoload(fingerprint_sha256, path.to_path_buf(), enabled)
        .context("saving config")
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD_NO_PAD as b64;
    use ssh_key::LineEnding;

    use super::*;
    use crate::core::config::AutoloadEntry;

    fn write_fixture_key(dir: &Path) -> (PathBuf, String) {
        let data = include_str!("../../../cli/src/cli/commands/ssh_agent/fixtures/b64_rsa");
        let key = PrivateKey::from_bytes(&b64.decode(data.trim()).unwrap()).unwrap();
        let path = dir.join("id_test");
        key.write_openssh_file(&path, LineEnding::LF).unwrap();
        (path, fingerprint(key.public_key()))
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("axo-autoload-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn lists_matching_entries_only() {
        let dir = temp_dir("list");
        let (path, fp) = write_fixture_key(&dir);
        let mut config = AppConfig::default();
        config
            .ssh_autoload
            .insert(fp.clone(), AutoloadEntry { path: path.clone() });
        config.ssh_autoload.insert(
            "SHA256:other".to_string(),
            AutoloadEntry { path: path.clone() },
        );
        config.ssh_autoload.insert(
            "SHA256:missing".to_string(),
            AutoloadEntry {
                path: dir.join("missing"),
            },
        );

        let keys = list(&config);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].fingerprint, fp);
        assert_eq!(keys[0].path, path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reads_unencrypted_private_key() {
        let dir = temp_dir("read");
        let (path, fp) = write_fixture_key(&dir);
        assert!(!is_encrypted(&path).unwrap());
        let key = read_private_key(&path, &fp, None).unwrap();
        assert_eq!(fingerprint(key.public_key()), fp);
        assert!(read_private_key(&path, "SHA256:other", None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
