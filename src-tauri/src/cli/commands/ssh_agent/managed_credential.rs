mod signer;

use ssh_agent_lib::proto;
use ssh_key::public::KeyData;

use crate::cli::commands::ssh_agent::credential::{Credential, CredentialError};
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

    fn sign(&self, req: proto::SignRequest) -> Result<ssh_key::Signature, CredentialError> {
        signer::sign_with_managed_key(&self.0.label(), &req.data)
    }
}
