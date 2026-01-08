mod signer;

use ssh_agent_lib::proto;

use crate::cli::commands::ssh_agent::credential::{Credential, CredentialError};
use crate::secrets::keychain::managed_key::ManagedSshKey;

pub struct ManagedCredential(pub ManagedSshKey);

impl From<ManagedSshKey> for ManagedCredential {
    fn from(key: ManagedSshKey) -> Self {
        Self(key)
    }
}

impl Credential for ManagedCredential {
    fn sign(&self, req: proto::SignRequest) -> Result<ssh_key::Signature, CredentialError> {
        signer::sign_with_managed_key(&self.0.label(), &req.data)
    }
}
