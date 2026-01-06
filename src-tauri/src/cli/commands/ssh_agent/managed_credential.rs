use ssh_key::Signature;

use crate::cli::commands::ssh_agent::credential::{Credential, CredentialError};
use crate::secrets::keychain::managed_key::ManagedSshKey;

pub struct ManagedCredential(pub ManagedSshKey);

impl From<ManagedSshKey> for ManagedCredential {
    fn from(key: ManagedSshKey) -> Self {
        Self(key)
    }
}

impl Credential for ManagedCredential {
    fn sign(&self, data: &[u8]) -> Result<Signature, CredentialError> {
        self.0.sign(data).map_err(|e| {
            log::error!("Failed to sign with managed credential: {e}");
            CredentialError::SigningFailed
        })
    }
}
