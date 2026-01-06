use ssh_key::Signature;
use thiserror::Error;

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
    fn sign(&self, data: &[u8]) -> Result<Signature, CredentialError>;
}
