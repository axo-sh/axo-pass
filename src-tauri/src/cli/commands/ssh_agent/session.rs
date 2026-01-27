use std::sync::Arc;

use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{
    self, AddIdentity, AddIdentityConstrained, RemoveIdentity, SignRequest,
};
use ssh_key::Signature;
use ssh_key::public::KeyData;
use tokio::sync::{Mutex, broadcast};

use crate::cli::commands::ssh_agent::credential::Credential;
use crate::cli::commands::ssh_agent::managed_credential::ManagedCredential;
use crate::cli::commands::ssh_agent::session_binding::SessionBinding;
use crate::cli::commands::ssh_agent::stored_credential::StoredCredential;
use crate::cli::commands::ssh_agent::userauth_request::UserauthRequest;
use crate::secrets::keychain::managed_key::ManagedSshKey;
use crate::ssh::utils::compute_short_sha256_fingerprint;

pub const AXO_SHUTDOWN_EXT: &str = "ssh-shutdown@pass.axo.sh";

#[derive(Clone)]
pub struct SshAgentSession {
    state: Arc<Mutex<Vec<StoredCredential>>>,
    pub(crate) sessions: Vec<SessionBinding>,
    pub(crate) session_bind_attempted: bool,
    shutdown_sender: broadcast::Sender<()>,
}

impl SshAgentSession {
    pub fn new(
        state: Arc<Mutex<Vec<StoredCredential>>>,
        shutdown_sender: broadcast::Sender<()>,
    ) -> Self {
        SshAgentSession {
            state,
            sessions: Vec::new(),
            session_bind_attempted: false,
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

        log::debug!("Adding {:?}", credential);
        self.state.lock().await.push(credential);
    }

    pub async fn find_credential(&self, pubkey: &KeyData) -> Option<Box<dyn Credential>> {
        for cred in self.state.lock().await.iter() {
            if let Ok(identity) = TryInto::<proto::Identity>::try_into(cred)
                && identity.pubkey == *pubkey
            {
                log::debug!("Found {:?}", cred);
                return Some(Box::new(cred.clone()) as _);
            }
        }

        // also look for credential in managed keys
        if let Ok(Some(managed_ssh_key)) = ManagedSshKey::find_by_pubkey(pubkey)
            .inspect_err(|e| log::error!("Failed to list managed SSH keys: {e}"))
        {
            log::debug!(
                "Found managed_ssh_key {}",
                compute_short_sha256_fingerprint(pubkey)
            );
            return Some(Box::new(ManagedCredential(managed_ssh_key)) as _);
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

        // only return permitted identities
        for stored_cred in creds.iter() {
            let boxed_cred: Box<dyn Credential> = Box::new(stored_cred.clone());
            if let Err(e) = self.identity_permitted(&*boxed_cred, None) {
                log::debug!("Skipping {stored_cred:?} due to destination constraints: {e}");
            } else if let Ok(identity) = stored_cred.try_into().inspect_err(|e| {
                log::error!("Failed to convert stored credential to identity: {stored_cred:?}: {e}")
            }) {
                identities.push(identity);
            }
        }

        // get managed keys as well
        let managed_keys = ManagedSshKey::list()
            .inspect_err(|e| log::error!("Failed to list managed SSH keys: {e}"))
            .unwrap_or_default();
        for managed_key in managed_keys {
            identities.push(managed_key.into());
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
        let fingerprint = compute_short_sha256_fingerprint(&req.pubkey);
        let Some(stored_cred) = self.find_credential(&req.pubkey).await else {
            log::debug!("request: sign with identity {fingerprint} - key not found");
            return Err(AgentError::Other("Key not found".into()));
        };

        if stored_cred.dest_constraints().is_empty() {
            log::debug!("request: sign with identity {fingerprint} (no constraints)");
        } else {
            // we have an openssh destination constraints, so we must validate session
            // binding.
            if self.sessions.is_empty() {
                return Err(AgentError::Other(
                    "Refusing use of destination-constrained key to sign on unbound connection"
                        .into(),
                ));
            }

            // we require that the request is an openssh userauth request, per openssh spec
            // (RFC4252 SSH2_MSG_USERAUTH_REQUEST with additional server host key)
            // https://www.openssh.org/agent-restrict.html
            // https://github.com/openssh/openssh-portable/blob/master/ssh-agent.c (see process_sign_request2)
            // https://github.com/openssh/openssh-portable/blob/a6f8f793d427a831be1b350741faa4f34066d55f/ssh-agent.c#L864-L914
            let userauth_req = UserauthRequest::parse(&req.data).map_err(|e| {
                log::error!(
                    "Expected signature payload to be an openssh \
                        userauth request for destination-constrained key: {e}"
                );
                AgentError::Other(format!("Failed to parse userauth request: {e}").into())
            })?;

            // stored_cred.public_key_data() should be same as req.pubkey
            if userauth_req.pubkey != stored_cred.public_key_data() {
                return Err(AgentError::Other(
                    "Public key in request does not match expected signing key".into(),
                ));
            }

            // Check identity permitted
            log::debug!("request: sign with identity {fingerprint}: {userauth_req}");
            self.identity_permitted(&*stored_cred, None).map_err(|e| {
                log::error!("Identity not permitted by destination constraints: {e}");
                AgentError::Other("Identity not permitted by destination constraints".into())
            })?;

            // Ensure session id is the most recent one
            let most_recent_session = &self.sessions.last().unwrap().inner;
            if userauth_req.session_id != most_recent_session.session_id {
                return Err(AgentError::Other(
                    format!(
                        "Unexpected session ID on signature request for target user {} with key {:?} {}",
                        userauth_req.user.unwrap_or("ANY".to_string()),
                        stored_cred.key_type(),
                        stored_cred
                            .public_key_data()
                            .fingerprint(ssh_key::HashAlg::Sha256)
                    )
                    .into(),
                ));
            }

            // Ensure that the hostkey embedded in the signature matches
            // the one most recently bound to the socket. An exception is
            // made for the initial forwarding hop.
            if self.sessions.len() > 1 && userauth_req.hostkey.is_none() {
                return Err(AgentError::Other(
                    "Refusing use of destination-constrained key: \
                    No hostkey recorded in signature for forwarded connection"
                        .into(),
                ));
            } else if let Some(hostkey) = userauth_req.hostkey
                && hostkey != most_recent_session.host_key
            {
                return Err(AgentError::Other(
                    "Refusing use of destination-constrained key: \
                        mismatch between hostkey in request and most \
                        recently bound session"
                        .into(),
                ));
            }
        }

        // passed all checks, perform signing
        stored_cred
            .sign(req)
            .map_err(|e| AgentError::Other(e.into()))
    }

    async fn extension(
        &mut self,
        extension: proto::Extension,
    ) -> Result<Option<proto::Extension>, AgentError> {
        log::debug!("request: ssh agent extension {}", extension.name);

        // Check for session bind extension
        if let Ok(Some(bind)) = extension.parse_message::<proto::extension::SessionBind>() {
            self.session_bind_attempted = true;

            // note that the hostkey for destination constraints is fetched by ssh-add from
            // the local known_hosts files (used to map the host names given on the
            // command-line to hostkeys before passing them to ssh-agent). This
            // means that all the keys for all the hosts that the user lists
            // must be present in the right place (the machine running ssh-add)
            // and the right time (when ssh-add is run).

            // Validate the server's signature of the session id using the public hostkey.
            // note: destination restricted keys cannot be used for signing
            bind.verify_signature()?;

            self.sessions.push(SessionBinding::new(bind));
            log::debug!(
                "Session bindings after bind: {}",
                self.sessions
                    .iter()
                    .map(|s| format!("{s:?}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            return Ok(None);
        }

        // Check for our shutdown extension
        if extension.name == AXO_SHUTDOWN_EXT {
            log::info!("Received shutdown extension, signaling server shutdown");
            let _ = self.shutdown_sender.send(());
            return Ok(None);
        }

        // Unknown/unsupported extension
        Err(AgentError::from(proto::ProtoError::UnsupportedCommand {
            command: 27,
        }))
    }
}

impl Drop for SshAgentSession {
    fn drop(&mut self) {
        if !self.sessions.is_empty() {
            log::debug!(
                "Closing SSH agent sessions: {}",
                self.sessions
                    .iter()
                    .map(|s| format!("{s:?}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD_NO_PAD as b64;
    use ssh_key::PrivateKey;

    use super::*;

    #[tokio::test]
    async fn test_session_sign() {
        let data = include_str!("./fixtures/b64_rsa");
        let private_key = PrivateKey::from_bytes(b64.decode(data).unwrap().as_slice()).unwrap();

        let public_key = private_key.public_key().clone();

        // Create credential
        let credential = proto::Credential::Key {
            privkey: private_key.key_data().clone(),
            comment: "test-key".to_string(),
        };

        // Setup session
        let state = Arc::new(Mutex::new(Vec::new()));
        let (shutdown_tx, _) = broadcast::channel(1);
        let mut session = SshAgentSession::new(state, shutdown_tx);

        // Add identity
        session
            .add_credential_to_state(credential, Vec::new())
            .await;

        // Create sign request
        let test_data = b"test data to sign";
        let sign_req = proto::SignRequest {
            pubkey: public_key.key_data().clone(),
            data: test_data.to_vec(),
            flags: 0,
        };

        // Test signing
        session.sign(sign_req).await.expect("Signing failed");
    }
}
