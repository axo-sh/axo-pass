use std::sync::Arc;

use axo_pass_core::audit::{Action, Actor, Outcome};
use axo_pass_core::ssh::utils::compute_short_sha256_fingerprint;
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{
    self, AddIdentity, AddIdentityConstrained, RemoveIdentity, SignRequest,
};
use ssh_key::Signature;
use ssh_key::public::KeyData;
use tokio::sync::{Mutex, broadcast};

use crate::cli::commands::ssh_agent::audit;
use crate::cli::commands::ssh_agent::credential::Credential;
use crate::cli::commands::ssh_agent::managed_credential::list_managed_credentials;
use crate::cli::commands::ssh_agent::session_binding::SessionBinding;
use crate::cli::commands::ssh_agent::stored_credential::StoredCredential;
use crate::cli::commands::ssh_agent::userauth_request::UserauthRequest;

pub const AXO_SHUTDOWN_EXT: &str = "ssh-shutdown@pass.axo.sh";

pub struct SshAgentSession {
    caller: Option<String>,
    actor: Option<Actor>,
    state: Arc<Mutex<Vec<StoredCredential>>>,
    pub(crate) sessions: Vec<SessionBinding>,
    pub(crate) session_bind_attempted: bool,
    shutdown_sender: broadcast::Sender<()>,
}

impl SshAgentSession {
    pub fn new(
        state: Arc<Mutex<Vec<StoredCredential>>>,
        caller: Option<String>,
        actor: Option<Actor>,
        shutdown_sender: broadcast::Sender<()>,
    ) -> Self {
        SshAgentSession {
            caller,
            actor,
            state,
            sessions: Vec::new(),
            session_bind_attempted: false,
            shutdown_sender,
        }
    }

    pub async fn add_credential_to_state(
        &mut self,
        credential: proto::PrivateCredential,
        constraints: Vec<proto::KeyConstraint>,
    ) {
        let credential = StoredCredential::from(credential).add_constraints(constraints);
        let pubkey_data = credential.public_key_data();

        // if credential already exists, remove it first. Only stored
        // credentials matter here: a managed key cannot be added over the agent
        // protocol, and consulting the app about one would start it.
        if self.find_stored_credential(&pubkey_data).await.is_some() {
            log::debug!("Credential already exists, will replace.");
            self.remove_credential(&pubkey_data).await;
        }

        log::debug!("Adding {:?}", credential);
        let mut detail: Vec<(&str, String)> = Vec::new();
        if credential.expires_at.is_some() {
            detail.push(("lifetime_constrained", "true".to_string()));
        }
        if credential.requires_auth {
            detail.push(("confirm", "true".to_string()));
        }
        if !credential.dest_constraints.is_empty() {
            detail.push((
                "destination_constraints",
                credential.dest_constraints.len().to_string(),
            ));
        }
        audit::record_key_change(
            Action::SshKeyAdd,
            self.actor.as_ref(),
            self.caller.as_deref(),
            &pubkey_data,
            credential.comment().as_deref(),
            &detail,
        );
        self.state.lock().await.push(credential);
    }

    /// Look only among the credentials added to this agent, leaving the app's
    /// managed keys alone.
    pub async fn find_stored_credential(&self, pubkey: &KeyData) -> Option<StoredCredential> {
        for cred in self.state.lock().await.iter() {
            if let Ok(identity) = TryInto::<proto::Identity>::try_into(cred)
                && *identity.credential.key_data() == *pubkey
            {
                log::debug!("Found {:?}", cred);
                return Some(cred.clone());
            }
        }
        None
    }

    pub async fn find_credential(&self, pubkey: &KeyData) -> Option<Box<dyn Credential>> {
        if let Some(cred) = self.find_stored_credential(pubkey).await {
            return Some(Box::new(cred) as _);
        }

        // also look for credential in managed keys
        if let Some(managed) = list_managed_credentials()
            .into_iter()
            .find(|cred| cred.public_key == *pubkey)
        {
            log::debug!(
                "Found managed key {} {}",
                managed.key_label,
                compute_short_sha256_fingerprint(pubkey)
            );
            return Some(Box::new(managed) as _);
        }

        None
    }

    pub async fn remove_credential(&mut self, pubkey: &KeyData) -> Option<StoredCredential> {
        let mut state = self.state.lock().await;
        if let Some(pos) = state.iter().position(|cred| {
            if let Ok(identity) = TryInto::<proto::Identity>::try_into(cred) {
                *identity.credential.key_data() == *pubkey
            } else {
                false
            }
        }) {
            return Some(state.remove(pos));
        }
        None
    }

    /// Run the checks that gate a signature and, if they pass, produce it.
    /// Callers record the `ssh.sign` audit event around this.
    async fn signature_for(
        &self,
        req: SignRequest,
        pubkey_data: &KeyData,
    ) -> Result<Signature, AgentError> {
        let fingerprint = compute_short_sha256_fingerprint(pubkey_data);
        let Some(stored_cred) = self.find_credential(pubkey_data).await else {
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
            .sign(req, self.caller.as_deref())
            .map_err(|e| AgentError::Other(e.into()))
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
        identities.extend(list_managed_credentials().iter().map(Into::into));
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
        let pubkey_data = req.credential.key_data();
        match self.remove_credential(&pubkey_data).await {
            None => log::debug!("request: remove ssh identity - key not found"),
            Some(removed) => {
                log::debug!("request: remove ssh identity");
                audit::record_key_change(
                    Action::SshKeyRemove,
                    self.actor.as_ref(),
                    self.caller.as_deref(),
                    &pubkey_data,
                    removed.comment().as_deref(),
                    &[],
                );
            },
        }
        Ok(())
    }

    async fn remove_all_identities(&mut self) -> Result<(), AgentError> {
        self.state.lock().await.clear();
        Ok(())
    }

    async fn sign(&mut self, req: SignRequest) -> Result<Signature, AgentError> {
        let pubkey_data = req.credential.key_data().clone();
        let request_data = req.data.clone();

        // Looked up here for the audit record. `signature_for` does its own
        // lookup, with the checks that gate the signature. The credential is not
        // held across an await: it is not `Send`.
        let (key_label, comment, managed) = {
            let cred = self.find_credential(&pubkey_data).await;
            let key_label = cred.as_ref().and_then(|c| c.key_label());
            let comment = cred.as_ref().and_then(|c| c.comment());
            (key_label.clone(), comment, key_label.is_some())
        };

        // One `ssh.sign` event is recorded for the request, whatever the outcome.
        let result = self.signature_for(req, &pubkey_data).await;

        audit::record_sign(
            self.actor.as_ref(),
            self.caller.as_deref(),
            &pubkey_data,
            &request_data,
            managed,
            comment.as_deref(),
            key_label.as_deref(),
            &result,
        );
        result
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
            audit::record_lifecycle(
                Action::SshSessionBind,
                Outcome::Succeeded,
                self.actor.as_ref(),
                self.caller.as_deref(),
            );
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
        let audit_dir = std::env::temp_dir().join(format!("axo-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&audit_dir);
        unsafe { std::env::set_var("AXO_PASS_AUDIT_DIR", &audit_dir) };

        let data = include_str!("./fixtures/b64_rsa");
        let private_key = PrivateKey::from_bytes(b64.decode(data).unwrap().as_slice()).unwrap();

        let public_key = private_key.public_key().clone();

        // Create credential
        let credential = proto::PrivateCredential::Key {
            privkey: private_key.key_data().clone(),
            comment: "test-key".to_string(),
        };

        // Setup session
        let state = Arc::new(Mutex::new(Vec::new()));
        let (shutdown_tx, _) = broadcast::channel(1);
        let mut session = SshAgentSession::new(state, None, None, shutdown_tx);

        // Add identity
        session
            .add_credential_to_state(credential, Vec::new())
            .await;

        // Create sign request
        let test_data = b"test data to sign";
        let sign_req = proto::SignRequest {
            credential: proto::PublicCredential::Key(public_key.into()),
            data: test_data.to_vec(),
            flags: 0,
        };

        // Test signing
        session.sign(sign_req).await.expect("Signing failed");

        // The sign path recorded one `ssh.sign` event.
        let page = axo_pass_core::audit::read(&axo_pass_core::audit::AuditFilter {
            actions: vec![axo_pass_core::audit::Action::SshSign],
            ..Default::default()
        });
        assert!(
            page.events
                .iter()
                .any(|e| e.outcome == axo_pass_core::audit::Outcome::Succeeded),
            "expected a successful ssh.sign audit event"
        );

        let _ = std::fs::remove_dir_all(&audit_dir);
    }
}
