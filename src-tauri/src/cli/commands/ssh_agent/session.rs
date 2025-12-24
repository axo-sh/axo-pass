use std::sync::Arc;

use anyhow::anyhow;
use rsa::signature::SignerMut;
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{
    self, AddIdentity, AddIdentityConstrained, RemoveIdentity, SignRequest, signature,
};
use ssh_key::Signature;
use tokio::sync::Mutex;
use ssh_key::public::KeyData;

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

    pub async fn find_credential(&self, pubkey: &KeyData) -> Option<StoredCredential> {
        for cred in self.state.lock().await.iter() {
            log::debug!("Stored credential: {:?}", cred);
            if let Ok(identity) = TryInto::<proto::Identity>::try_into(cred)
                && identity.pubkey == *pubkey
            {
                return Some(cred.clone());
            }
        }
        None
    }

    pub async fn remove_credential(&mut self, pubkey: &KeyData) -> Option<StoredCredential> {
        let mut state = self.state.lock().await;
        if let Some(pos) = state.iter().position(|cred| {
            if let Ok(identity) = TryInto::<proto::Identity>::try_into(cred) {
                identity.pubkey == *pubkey
            } else {
                false
            }
        }) {
            return Some(state.remove(pos));
        }
        None
    }
}

#[ssh_agent_lib::async_trait]
impl Session for SshAgentSession {
    async fn request_identities(&mut self) -> Result<Vec<proto::Identity>, AgentError> {
        log::debug!("request: list ssh identities");
        let creds = self.state.lock().await;
        let identities = creds
            .iter()
            .filter_map(|c| c.try_into().ok())
            .collect::<Vec<proto::Identity>>();
        Ok(identities)
    }

    async fn add_identity(&mut self, req: AddIdentity) -> Result<(), AgentError> {
        log::debug!("request: add ssh identity");
        self.add_credential_to_state(req.credential, Vec::new())
            .await;
        Ok(())
    }

    async fn add_identity_constrained(
        &mut self,
        req: AddIdentityConstrained,
    ) -> Result<(), AgentError> {
        log::debug!("request: add ssh identity with constraints");
        self.add_credential_to_state(req.identity.credential, req.constraints)
            .await;
        Ok(())
    }

    async fn remove_identity(&mut self, req: RemoveIdentity) -> Result<(), AgentError> {
        if self.remove_credential(&req.pubkey).await.is_none() {
            log::debug!("request: remove ssh identity - key not found");
        } else {
            log::debug!("request: remove ssh identity");
        }
        Ok(())
    }

    async fn remove_all_identities(&mut self) -> Result<(), AgentError> {
        self.state.lock().await.clear();
        Ok(())
    }
    async fn sign(&mut self, req: SignRequest) -> Result<Signature, AgentError> {
        log::debug!("request: sign with identity");
        match req.flags {
            signature::RSA_SHA2_256 | signature::RSA_SHA2_512 => {
                todo!("RSA SHA2 signatures");
            },
            _ => {},
        }

        let Some(stored_cred) = self.find_credential(&req.pubkey).await else {
            return Err(AgentError::Other(anyhow!("Key not found").into()));
        };

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
