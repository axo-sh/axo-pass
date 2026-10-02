use std::os::fd::BorrowedFd;

use axo_pass_core::core::provenance::ProcessNode;
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

    // caller, if provided, is displayed in the auth prompt. caller_chain is the
    // full requesting process chain, shown when the prompt is expanded.
    // requester is the client's socket: a prompt is dropped if it disconnects.
    fn sign(
        &self,
        req: proto::SignRequest,
        caller: Option<&str>,
        caller_chain: &[ProcessNode],
        requester: Option<BorrowedFd<'_>>,
    ) -> Result<Signature, CredentialError>;

    fn public_key_data(&self) -> KeyData;

    fn dest_constraints(&self) -> Vec<proto::extension::DestinationConstraint> {
        Vec::new()
    }
}
