use std::sync::Arc;

use anyhow::anyhow;
use rsa::signature::SignerMut;
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{self, AddIdentity, AddIdentityConstrained, SignRequest, signature};
use ssh_key::Signature;
use tokio::sync::Mutex;

use crate::cli::commands::ssh_agent::stored_credential::StoredCredential;

#[derive(Clone)]
pub struct SshAgentSession {
    state: Arc<Mutex<Vec<StoredCredential>>>,
}

impl SshAgentSession {
    pub fn new(state: Arc<Mutex<Vec<StoredCredential>>>) -> Self {
        SshAgentSession { state }
    }

    pub async fn add_credential_to_state(
        &mut self,
        credential: proto::Credential,
        constraints: Vec<proto::KeyConstraint>,
    ) {
        let credential = StoredCredential::from(credential).add_constraints(constraints);
        log::debug!("Adding identity details: {:?}", credential);
        self.state.lock().await.push(credential);
    }
}

#[ssh_agent_lib::async_trait]
impl Session for SshAgentSession {
    async fn request_identities(&mut self) -> Result<Vec<proto::Identity>, AgentError> {
        let creds = self.state.lock().await;
        let identities = creds
            .iter()
            .filter_map(|c| c.try_into().ok())
            .collect::<Vec<proto::Identity>>();
        Ok(identities)
    }

    async fn add_identity(&mut self, req: AddIdentity) -> Result<(), AgentError> {
        self.add_credential_to_state(req.credential, Vec::new())
            .await;
        Ok(())
    }

    async fn add_identity_constrained(
        &mut self,
        req: AddIdentityConstrained,
    ) -> Result<(), AgentError> {
        self.add_credential_to_state(req.identity.credential, req.constraints)
            .await;
        Ok(())
    }

    async fn sign(&mut self, req: SignRequest) -> Result<Signature, AgentError> {
        let creds = self.state.lock().await;
        match req.flags {
            signature::RSA_SHA2_256 | signature::RSA_SHA2_512 => {
                todo!("RSA SHA2 signatures");
            },
            _ => {},
        }

        let stored_cred = creds
            .iter()
            .find(|c| match TryInto::<proto::Identity>::try_into(*c) {
                Ok(identity) => identity.pubkey == req.pubkey,
                _ => false,
            })
            .ok_or_else(|| AgentError::Other(anyhow!("Key not found").into()))?;

        let _ = stored_cred
            .validate()
            .map_err(|e| AgentError::Other(Box::new(e))); // validation failed

        let sig = match &stored_cred.credential {
            proto::Credential::Key { privkey, .. } => {
                let mut privkey_clone = privkey.clone();
                privkey_clone.sign(&req.data)
            },
            proto::Credential::Cert { .. } => {
                todo!("signing with certificate not implemented");
            },
        };
        Ok(sig)
    }

    async fn extension(
        &mut self,
        extension: proto::Extension,
    ) -> Result<Option<proto::Extension>, AgentError> {
        if let Ok(Some(_)) = extension.parse_message::<proto::extension::SessionBind>() {
            log::debug!("todo: implement session bind extension");
            return Ok(None);
        }

        Err(AgentError::from(proto::ProtoError::UnsupportedCommand {
            command: 27,
        }))
    }
}
