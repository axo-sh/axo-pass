use ssh_agent_lib::proto;
use ssh_key::public::KeyData;

use crate::cli::commands::ssh_agent::credential::{Credential, CredentialError};
use crate::core::auth;
use crate::secrets::keychain::managed_key::ManagedSshKey;
use crate::ssh::ssh_keys::SshKeyType;

pub struct ManagedCredential(pub ManagedSshKey);

impl From<ManagedSshKey> for ManagedCredential {
    fn from(key: ManagedSshKey) -> Self {
        Self(key)
    }
}

impl Credential for ManagedCredential {
    fn key_type(&self) -> SshKeyType {
        SshKeyType::Ecdsa
    }

    fn public_key_data(&self) -> KeyData {
        self.0.public_key().clone()
    }

    fn sign(&self, req: proto::SignRequest, caller: Option<&str>) -> Result<ssh_key::Signature, CredentialError> {
        let managed_key_label = self.0.label();
        auth::sign_with_managed_key(&managed_key_label, &req.data, caller).map_err(|e| {
            log::debug!("Failed to sign with managed key {managed_key_label}: {e}");
            CredentialError::SigningFailed
        })
    }
}
