use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;

use anyhow::{Context, anyhow, bail};
use ssh_agent_lib::proto;
use ssh_key::public::KeyData;
use uuid::Uuid;

use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::keychain::keychain_query::KeyChainQuery;
use crate::secrets::keychain::managed_key::{KeyClass, ManagedKey, ManagedKeyQuery};
use crate::ssh::utils::get_ssh_dir;

const SSH_KEY_LABEL_PREFIX: &str = "ssh-key-";

pub struct ManagedSshKey {
    id: Uuid,
    managed_key: ManagedKey,
    public_key: KeyData,
}

impl ManagedSshKey {
    pub fn name(&self) -> String {
        format!("id_se_{}.pub", self.id.simple())
    }

    pub fn fingerprint(&self) -> ssh_key::Fingerprint {
        self.public_key.fingerprint(ssh_key::HashAlg::Sha256)
    }

    pub fn delete(&self) -> anyhow::Result<()> {
        self.managed_key.delete()?;

        // Also try to delete the associated public key file
        let pubkey_path = get_ssh_dir()?.join(self.name());
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

impl Into<proto::Identity> for ManagedSshKey {
    fn into(self) -> proto::Identity {
        proto::Identity {
            pubkey: self.public_key.clone(),
            comment: self.id.simple().to_string(),
        }
    }
}
