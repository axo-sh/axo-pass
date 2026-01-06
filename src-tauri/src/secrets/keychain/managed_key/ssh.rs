use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use anyhow::{Context, anyhow, bail};
use ssh_encoding::Encode;
use ssh_key::public::KeyData;
use ssh_key::{Mpint, Signature};
use uuid::Uuid;

use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::keychain_query::KeyChainQuery;
use crate::secrets::keychain::managed_key::{KeyClass, ManagedKey, ManagedKeyQuery};
use crate::ssh::utils::get_ssh_dir;

const SSH_KEY_LABEL_PREFIX: &str = "ssh-key-";

const ECDSA_P256: ssh_key::Algorithm = ssh_key::Algorithm::Ecdsa {
    curve: ssh_key::EcdsaCurve::NistP256,
};

pub struct ManagedSshKey {
    id: Uuid,
    managed_key: ManagedKey,
    public_key: KeyData,
}

impl ManagedSshKey {
    pub fn label(&self) -> String {
        format!("id_se_{}", self.id.simple())
    }

    pub fn pubkey_path(&self) -> Result<PathBuf, anyhow::Error> {
        let ssh_dir = get_ssh_dir()?;
        Ok(ssh_dir.join(format!("{}.pub", self.label())))
    }

    pub fn fingerprint(&self) -> ssh_key::Fingerprint {
        self.public_key.fingerprint(ssh_key::HashAlg::Sha256)
    }

    pub fn public_key(&self) -> KeyData {
        self.public_key.clone()
    }

    pub fn sign(&self, data: &[u8]) -> Result<Signature, anyhow::Error> {
        let der_sig_bytes = self
            .managed_key
            .sign(data)
            .map_err(|e| anyhow!("Failed to sign data: {e}"))?;

        // The Secure Enclave returns ECDSA P-256 signatures in DER/ASN.1 format.
        // Parse it and encode r and s encoded as MPInts for SSH.
        let (r, s) = p256::ecdsa::Signature::from_der(&der_sig_bytes)
            .map_err(|e| anyhow!("Failed to parse DER signature: {e}"))?
            .split_bytes();
        let mut ssh_sig_bytes = Vec::new();
        for component in [r, s] {
            Mpint::from_positive_bytes(&component)?
                .encode(&mut ssh_sig_bytes)
                .map_err(|e| anyhow!("Failed to encode: {e}"))?;
        }

        Signature::new(ECDSA_P256, ssh_sig_bytes)
            .map_err(|e| anyhow!("Failed to create SSH signature: {e}"))
    }

    pub fn delete(&self) -> anyhow::Result<()> {
        self.managed_key.delete()?;

        // Also try to delete the associated public key file
        let pubkey_path = self.pubkey_path()?;
        if pubkey_path.exists() {
            fs::remove_file(&pubkey_path).context("Failed to delete public key file")?;
        }
        Ok(())
    }
}

impl ManagedSshKey {
    pub async fn create() -> Result<(), KeychainError> {
        let key_id = Uuid::new_v4().simple();
        let label = format!("{SSH_KEY_LABEL_PREFIX}{key_id}");

        let managed_key = ManagedKey::create(&label)?;

        // get the pubkey in openssh format
        let pubkey_openssh =
            ssh_key::PublicKey::new(managed_key.public_key()?, &key_id.to_string())
                .to_openssh()
                .map_err(|e| {
                    KeychainError::PublicKeyCreationFailed(anyhow!(
                        "Failed to format OpenSSH key: {e}"
                    ))
                })?;

        // save pubkey_openssh to pubkey_path
        let pubkey_path = get_ssh_dir()?.join(&format!("id_se_{key_id}.pub"));
        fs::write(&pubkey_path, format!("{pubkey_openssh}\n")).map_err(|e| {
            KeychainError::PublicKeyCreationFailed(anyhow!("Failed to write public key: {e}"))
        })?;
        fs::set_permissions(&pubkey_path, Permissions::from_mode(0o644)).map_err(|e| {
            KeychainError::PublicKeyCreationFailed(anyhow!(
                "Failed to set public key permissions: {e}"
            ))
        })?;

        log::debug!("Saved public key to {}", pubkey_path.display());
        Ok(())
    }

    pub fn find(label: &str) -> Result<Option<ManagedSshKey>, anyhow::Error> {
        // strip_prefix returns None if prefix not found
        let Some(key_id) = label.strip_prefix(SSH_KEY_LABEL_PREFIX) else {
            bail!("Invalid label");
        };
        let key = ManagedKeyQuery::build()
            .with_label(label)
            .with_key_class(KeyClass::Private)
            .one();

        match key {
            Ok(Some(managed_key)) => {
                let uuid = Uuid::try_parse(key_id).context("Failed to parse key ID as UUID")?;
                Ok(Some(ManagedSshKey {
                    id: uuid,
                    public_key: managed_key.public_key()?,
                    managed_key,
                }))
            },
            Ok(None) => Ok(None),
            Err(e) => {
                bail!("Failed to query managed key: {e}");
            },
        }
    }

    pub fn find_by_pubkey(pubkey: &KeyData) -> Result<Option<ManagedSshKey>, anyhow::Error> {
        let pubkey_fp = pubkey.fingerprint(ssh_key::HashAlg::Sha256);
        log::debug!("Looking for managed SSH key with fingerprint: {pubkey_fp}");
        for managed_key in Self::list()? {
            let this_fp = managed_key.public_key.fingerprint(ssh_key::HashAlg::Sha256);
            log::debug!("Checking managed SSH key with fingerprint: {this_fp}");
            if this_fp == pubkey_fp {
                log::debug!("Found managed SSH key with matching fingerprint: {pubkey_fp}");
                return Ok(Some(managed_key));
            }
        }
        Ok(None)
    }

    pub fn list() -> Result<Vec<ManagedSshKey>, anyhow::Error> {
        let managed_keys = ManagedKeyQuery::build()
            .with_key_class(KeyClass::Private)
            .list()
            .unwrap();

        let mut out = Vec::new();
        for managed_key in managed_keys {
            if let Some(label) = &managed_key.label
                && let Some(key_id) = label.strip_prefix(SSH_KEY_LABEL_PREFIX)
                && let Ok(uuid) = Uuid::try_parse(key_id)
            {
                out.push(ManagedSshKey {
                    id: uuid,
                    public_key: managed_key.public_key()?,
                    managed_key,
                });
            };
        }
        Ok(out)
    }
}
