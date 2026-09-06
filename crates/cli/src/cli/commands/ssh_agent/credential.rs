use axo_pass_core::ssh::ssh_keys::SshKeyType;
use ssh_agent_lib::proto;
use ssh_key::Signature;
use ssh_key::public::KeyData;
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
    fn key_type(&self) -> SshKeyType;

    /// The key's comment, when it has a non-empty one.
    fn comment(&self) -> Option<String> {
        None
    }

    /// The app-side label for a managed Secure Enclave key. `None` for a key
    /// the agent holds directly.
    fn key_label(&self) -> Option<String> {
        None
    }

    // caller, if provided, is displayed in the auth prompt
    fn sign(
        &self,
        req: proto::SignRequest,
        caller: Option<&str>,
    ) -> Result<Signature, CredentialError>;

    fn public_key_data(&self) -> KeyData;

    fn dest_constraints(&self) -> Vec<proto::extension::DestinationConstraint> {
        Vec::new()
    }
}
