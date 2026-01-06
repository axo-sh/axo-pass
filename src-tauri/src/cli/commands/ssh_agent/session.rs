use std::sync::Arc;

use anyhow::anyhow;
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{
    self, AddIdentity, AddIdentityConstrained, RemoveIdentity, SignRequest, signature,
};
use ssh_key::Signature;
use ssh_key::public::KeyData;
use tokio::sync::{Mutex, broadcast};

use crate::cli::commands::ssh_agent::credential::Credential;
use crate::cli::commands::ssh_agent::managed_credential::ManagedCredential;
use crate::cli::commands::ssh_agent::stored_credential::StoredCredential;
use crate::secrets::keychain::managed_key::ManagedSshKey;

#[derive(Clone)]
pub struct SshAgentSession {
    state: Arc<Mutex<Vec<StoredCredential>>>,
    shutdown_sender: broadcast::Sender<()>,
}

impl SshAgentSession {
    pub fn new(
        state: Arc<Mutex<Vec<StoredCredential>>>,
        shutdown_sender: broadcast::Sender<()>,
    ) -> Self {
        SshAgentSession {
            state,
            shutdown_sender,
        }
    }

    pub async fn add_credential_to_state(
        &mut self,
        credential: proto::Credential,
        constraints: Vec<proto::KeyConstraint>,
    ) {
        let credential = StoredCredential::from(credential).add_constraints(constraints);

        // if credential already exists, remove it first
        if let Ok(identity) = TryInto::<proto::Identity>::try_into(&credential)
            && self.find_credential(&identity.pubkey).await.is_some()
        {
            log::debug!("Credential already exists, will replace.");
            self.remove_credential(&identity.pubkey).await;
        }

        log::debug!("Adding identity details: {:?}", credential);
        self.state.lock().await.push(credential);
    }

    pub async fn find_credential(&self, pubkey: &KeyData) -> Option<Box<dyn Credential>> {
        for cred in self.state.lock().await.iter() {
            log::debug!("Stored credential: {:?}", cred);
            if let Ok(identity) = TryInto::<proto::Identity>::try_into(cred)
                && identity.pubkey == *pubkey
            {
                return Some(Box::new(cred.clone()));
            }
        }
        // also look for credential in managed keys
        if let Some(managed_ssh_key) = ManagedSshKey::find_by_pubkey(pubkey)
            .inspect_err(|e| log::error!("Failed to list managed SSH keys: {e}"))
            .unwrap_or_default()
        {
            return Some(Box::new(ManagedCredential(managed_ssh_key)));
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
        let mut identities = vec![];
        for identity in creds.iter().filter_map(|c| c.try_into().ok()) {
            identities.push(identity);
        }
        let managed_keys = ManagedSshKey::list()
            .inspect_err(|e| log::error!("Failed to list managed SSH keys: {e}"))
            .unwrap_or_default();
        for managed_key in managed_keys {
            identities.push(proto::Identity {
                pubkey: managed_key.public_key(),
                comment: managed_key.label(),
            });
        }
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

        log::debug!("Signing with identity...");
        stored_cred
            .sign(&req.data)
            .map_err(|e| AgentError::Other(Box::new(e)))
    }

    async fn extension(
        &mut self,
        extension: proto::Extension,
    ) -> Result<Option<proto::Extension>, AgentError> {
        if let Ok(Some(_)) = extension.parse_message::<proto::extension::SessionBind>() {
            log::debug!("todo: implement session bind extension");
            return Ok(None);
        }

        if extension.name == "ssh-shutdown@pass.axo.sh" {
            log::info!("Received shutdown extension, signaling server shutdown");
            let _ = self.shutdown_sender.send(());
            return Ok(None);
        }

        Err(AgentError::from(proto::ProtoError::UnsupportedCommand {
            command: 27,
        }))
    }
}
