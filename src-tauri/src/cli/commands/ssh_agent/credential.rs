use ssh_agent_lib::proto;
use ssh_key::Signature;
use ssh_key::public::KeyData;
use thiserror::Error;

use crate::ssh::ssh_keys::SshKeyType;

#[derive(Error, Debug)]
pub enum CredentialError {
    #[error("Credential has expired")]
    Expired,

    #[error("Credential is locked and requires user authentication")]
    Locked,

    #[error("Failed to sign data with credential")]
    SigningFailed,
}

pub trait Credential {
    fn key_type(&self) -> SshKeyType;
    fn sign(&self, req: proto::SignRequest) -> Result<Signature, CredentialError>;
    fn public_key_data(&self) -> KeyData;
    fn dest_constraints(&self) -> Vec<proto::extension::DestinationConstraint> {
        Vec::new()
    }
}
