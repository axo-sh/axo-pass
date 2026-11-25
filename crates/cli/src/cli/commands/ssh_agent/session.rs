use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::Arc;

use axo_pass_core::audit::{Action, Actor, Outcome};
use axo_pass_core::core::app_broker::SignPurpose;
use axo_pass_core::core::provenance::ProcessNode;
use axo_pass_core::ssh::agent_client::{AXO_AGENT_INFO_EXT, AXO_RESTART_EXT, AXO_SHUTDOWN_EXT};
use axo_pass_core::ssh::utils::compute_short_sha256_fingerprint;
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{
    self, AddIdentity, AddIdentityConstrained, RemoveIdentity, SignRequest,
};
use ssh_key::Signature;
use ssh_key::public::KeyData;
use time::UtcDateTime;
use tokio::sync::{Mutex, broadcast};

use crate::cli::commands::agent::current_agent_info;
use crate::cli::commands::ssh_agent::audit::{self, SignKeySource};
use crate::cli::commands::ssh_agent::autoload_credential::{
    self, LoadError, find_autoload_key, is_autoload_key, list_autoload_keys,
};
use crate::cli::commands::ssh_agent::credential::Credential;
use crate::cli::commands::ssh_agent::managed_credential::list_managed_credentials;
use crate::cli::commands::ssh_agent::server::StopReason;
use crate::cli::commands::ssh_agent::session_binding::SessionBinding;
use crate::cli::commands::ssh_agent::stored_credential::StoredCredential;
use crate::cli::commands::ssh_agent::userauth_request::UserauthRequest;

/// Serializes first-use loading of auto-load keys across sessions, so
/// concurrent requests for one key prompt once.
static AUTOLOAD_LOCK: Mutex<()> = Mutex::const_new(());

pub struct SshAgentSession {
    caller: Option<String>,
    actor: Option<Actor>,
    /// A duplicate of the client's socket. Requests to the app watch it, so a
    /// prompt is dropped when the client disconnects. `ssh_agent_lib` does not
    /// read the socket while a request is being served, so nothing else would
    /// notice.
    client: Option<OwnedFd>,
    state: Arc<Mutex<Vec<StoredCredential>>>,
    pub(crate) sessions: Vec<SessionBinding>,
    pub(crate) session_bind_attempted: bool,
    shutdown_sender: broadcast::Sender<StopReason>,
}

impl SshAgentSession {
    pub fn new(
        state: Arc<Mutex<Vec<StoredCredential>>>,
        caller: Option<String>,
        actor: Option<Actor>,
        client: Option<OwnedFd>,
        shutdown_sender: broadcast::Sender<StopReason>,
    ) -> Self {
        SshAgentSession {
            caller,
            actor,
            client,
            state,
            sessions: Vec::new(),
            session_bind_attempted: false,
            shutdown_sender,
        }
    }

    fn requester(&self) -> Option<BorrowedFd<'_>> {
        self.client.as_ref().map(OwnedFd::as_fd)
    }

    /// The requesting process chain, as resolved from the socket peer. Passed
    /// to the broker so a signing prompt can show the full ancestry.
    fn caller_chain(&self) -> &[ProcessNode] {
        self.actor
            .as_ref()
            .map_or(&[], |a| a.chain_detail.as_slice())
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

        self.store_credential(credential).await;
    }

    /// Record the `ssh.key_add` event for `credential` and add it to the
    /// shared state.
    async fn store_credential(&self, credential: StoredCredential) {
        let pubkey_data = credential.public_key_data();
        log::debug!("Adding {:?}", credential);
        let mut detail: Vec<(&str, String)> = Vec::new();
        if credential.autoload {
            detail.push(("autoload", "true".to_string()));
        }
        if credential.vault_loaded {
            detail.push(("key_source", "vault".to_string()));
        }
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

    /// Remove the credentials whose lifetime has run out, recording an
    /// `ssh.key_remove` event for each. A removed key is neither listed nor
    /// signed with, so `ssh` reads the key file again and an auto-load key is
    /// loaded again on its next use.
    async fn remove_expired(&self) {
        let now = UtcDateTime::now();
        let expired: Vec<StoredCredential> = self
            .state
            .lock()
            .await
            .extract_if(.., |cred| cred.is_expired(now))
            .collect();

        // Recorded with the state unlocked: an audit write can block.
        for cred in expired {
            log::debug!("Removing expired {cred:?}");
            audit::record_key_change(
                Action::SshKeyRemove,
                None,
                None,
                &cred.public_key_data(),
                cred.comment().as_deref(),
                &[("reason", "expired".to_string())],
            );
        }
    }

    /// Look only among the credentials added to this agent, leaving the app's
    /// managed keys alone.
    pub async fn find_stored_credential(&self, pubkey: &KeyData) -> Option<StoredCredential> {
        self.remove_expired().await;
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
        if let Some(mut cred) = self.find_stored_credential(pubkey).await {
            // An auto-load key keeps its per-use check when it was added by
            // hand. A `-c` constraint on the added copy still takes precedence.
            if !cred.autoload && is_autoload_key(pubkey) {
                cred.autoload = true;
            }
            return Some(Box::new(cred) as _);
        }

        // also look for credential in managed keys
        if let Some(managed) = list_managed_credentials(self.requester())
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

    /// Load `pubkey` into the shared state if it is an auto-load key that is
    /// not loaded yet. The signature that caused the load still goes through
    /// the confirm-on-use check.
    async fn load_autoload_key(&self, pubkey: &KeyData) -> Result<(), AgentError> {
        if self.find_stored_credential(pubkey).await.is_some() {
            return Ok(());
        }
        let Some(key) = find_autoload_key(pubkey) else {
            return Ok(());
        };

        // Concurrent first uses of one key wait here, then find it loaded.
        let _guard = AUTOLOAD_LOCK.lock().await;
        if self.find_stored_credential(pubkey).await.is_some() {
            return Ok(());
        }

        let credential = autoload_credential::load(
            &key,
            self.caller.as_deref(),
            self.caller_chain(),
            self.requester(),
        )
        .map_err(|e| {
            match &e {
                LoadError::Cancelled(_) => log::debug!("{e}"),
                LoadError::Failed(_) => {
                    log::error!("Failed to load auto-load key {}: {e}", key.fingerprint)
                },
            }
            AgentError::Other(e.into())
        })?;
        self.store_credential(credential).await;
        Ok(())
    }

    /// Load `pubkey` into the shared state if it is a vault key with auto-load
    /// on that is not loaded yet. Returns whether this call loaded it. The
    /// vault access prompt that loads it covers the signature that caused
    /// the load. Every later use is confirmed like an auto-load key, and
    /// does not touch the vault.
    async fn load_vault_key(
        &self,
        pubkey: &KeyData,
        purpose: Option<&SignPurpose>,
    ) -> Result<bool, AgentError> {
        if self.find_stored_credential(pubkey).await.is_some() {
            return Ok(false);
        }
        let Some(managed) = list_managed_credentials(self.requester())
            .into_iter()
            .find(|cred| cred.public_key == *pubkey && cred.loads_into_agent())
        else {
            return Ok(false);
        };

        // Concurrent first uses of one key wait here, then find it loaded.
        let _guard = AUTOLOAD_LOCK.lock().await;
        if self.find_stored_credential(pubkey).await.is_some() {
            return Ok(false);
        }

        let credential = managed
            .load(
                self.caller.as_deref(),
                self.caller_chain(),
                purpose,
                self.requester(),
            )
            .map_err(|e| {
                match &e {
                    LoadError::Cancelled(_) => log::debug!("{e}"),
                    LoadError::Failed(_) => {
                        log::error!("Failed to load vault key {}: {e}", managed.key_label)
                    },
                }
                AgentError::Other(e.into())
            })?;
        self.store_credential(credential).await;
        Ok(true)
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
    ///
    /// With `approved_by_load`, the vault access prompt that loaded the key
    /// approved this signature, so it is not confirmed again.
    async fn signature_for(
        &self,
        req: SignRequest,
        pubkey_data: &KeyData,
        approved_by_load: bool,
    ) -> Result<Signature, AgentError> {
        let fingerprint = compute_short_sha256_fingerprint(pubkey_data);
        // Looked up before `find_credential`, which holds a value that is not
        // `Send` for the rest of the function.
        let loaded = if approved_by_load {
            self.find_stored_credential(pubkey_data).await
        } else {
            None
        };
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
        let purpose = self.sign_purpose(&req.data);
        let signed = match &loaded {
            Some(credential) => credential.sign_approved(req),
            None => stored_cred.sign(
                req,
                self.caller.as_deref(),
                self.caller_chain(),
                purpose.as_ref(),
                self.requester(),
            ),
        };
        signed.map_err(|e| AgentError::Other(e.into()))
    }

    /// Describe what `data` is a signature over, for the prompt: an
    /// `ssh-keygen -Y sign` namespace or an SSH login. `None` for anything
    /// else.
    fn sign_purpose(&self, data: &[u8]) -> Option<SignPurpose> {
        if let Some(purpose) = SignPurpose::sshsig(data) {
            return Some(purpose);
        }
        let req = UserauthRequest::parse(data).ok()?;
        let host = req.hostkey.as_ref().map(|hostkey| {
            audit::host_name(hostkey, &self.sessions)
                .unwrap_or_else(|| compute_short_sha256_fingerprint(hostkey))
        });
        Some(SignPurpose::Login {
            user: req.user,
            host,
        })
    }
}

#[ssh_agent_lib::async_trait]
impl Session for SshAgentSession {
    async fn request_identities(&mut self) -> Result<Vec<proto::Identity>, AgentError> {
        log::debug!("request: list ssh identities");
        self.remove_expired().await;
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

        // auto-load keys not loaded yet. They carry no destination constraints.
        for key in list_autoload_keys() {
            let key_data = key.public_key.key_data();
            if !creds.iter().any(|c| c.public_key_data() == *key_data) {
                identities.push(proto::Identity {
                    credential: proto::PublicCredential::Key(key_data.clone()),
                    comment: key.public_key.comment().to_string(),
                });
            }
        }

        // get managed keys as well. A vault key the agent loaded is listed above.
        identities.extend(
            list_managed_credentials(self.requester())
                .iter()
                .filter(|credential| credential.auto_load)
                .filter(|credential| {
                    !creds
                        .iter()
                        .any(|c| c.public_key_data() == credential.public_key)
                })
                .map(Into::into),
        );
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
        match self.remove_credential(pubkey_data).await {
            None => log::debug!("request: remove ssh identity - key not found"),
            Some(removed) => {
                log::debug!("request: remove ssh identity");
                audit::record_key_change(
                    Action::SshKeyRemove,
                    self.actor.as_ref(),
                    self.caller.as_deref(),
                    pubkey_data,
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

        // An auto-load key is read from disk on first use, before the lookups
        // below, so they find it. A vault key with auto-load on is loaded from
        // the app the same way, and the value says whether this request loaded
        // it.
        let purpose = self.sign_purpose(&request_data);
        let loaded = match self.load_autoload_key(&pubkey_data).await {
            Ok(()) => self.load_vault_key(&pubkey_data, purpose.as_ref()).await,
            Err(e) => Err(e),
        };

        // Looked up here for the audit record. `signature_for` does its own
        // lookup, with the checks that gate the signature. The credential is not
        // held across an await: it is not `Send`.
        let (key_label, comment, source) = {
            let cred = self.find_credential(&pubkey_data).await;
            let key_label = cred.as_ref().and_then(|c| c.key_label());
            let comment = cred.as_ref().and_then(|c| c.comment());
            let source = cred
                .as_ref()
                .map_or(SignKeySource::Agent, |c| c.key_source());
            (key_label, comment, source)
        };

        // One `ssh.sign` event is recorded for the request, whatever the outcome.
        let result = match loaded {
            Err(e) => Err(e),
            Ok(approved_by_load) => {
                self.signature_for(req, &pubkey_data, approved_by_load)
                    .await
            },
        };

        audit::record_sign(
            self.actor.as_ref(),
            self.caller.as_deref(),
            &pubkey_data,
            &request_data,
            source,
            comment.as_deref(),
            key_label.as_deref(),
            &self.sessions,
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
            let _ = self.shutdown_sender.send(StopReason::Shutdown);
            return Ok(None);
        }

        if extension.name == AXO_RESTART_EXT {
            log::info!("Received restart extension, signaling server restart");
            let _ = self.shutdown_sender.send(StopReason::Restart);
            return Ok(None);
        }

        if extension.name == AXO_AGENT_INFO_EXT {
            let details = serde_json::to_vec(&current_agent_info())
                .map_err(|e| AgentError::Other(e.into()))?;
            return Ok(Some(proto::Extension {
                name: AXO_AGENT_INFO_EXT.to_string(),
                details: details.into(),
            }));
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

    /// The audit dir is process-global via an env var, so tests that set it
    /// must not run concurrently.
    static AUDIT_DIR_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn session_sign() {
        let _guard = AUDIT_DIR_LOCK.lock().await;
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
        let mut session = SshAgentSession::new(state, None, None, None, shutdown_tx);

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
            page.events.iter().any(|e| {
                e.outcome == axo_pass_core::audit::Outcome::Succeeded
                    && e.detail.get("key_source").map(String::as_str) == Some("agent")
            }),
            "expected a successful ssh.sign audit event from an agent key"
        );

        let _ = std::fs::remove_dir_all(&audit_dir);
    }

    fn rsa_key() -> PrivateKey {
        let data = include_str!("./fixtures/b64_rsa");
        PrivateKey::from_bytes(b64.decode(data).unwrap().as_slice()).unwrap()
    }

    fn vault_loaded_credential() -> StoredCredential {
        let mut credential = StoredCredential::from(proto::PrivateCredential::Key {
            privkey: rsa_key().key_data().clone(),
            comment: "vault-key".to_string(),
        });
        credential.autoload = true;
        credential.vault_loaded = true;
        credential
    }

    /// The `ssh.sign` events recorded for one signature from `source`, in an
    /// audit dir reset to `name`. The caller holds `AUDIT_DIR_LOCK`.
    fn record_vault_sign(
        name: &str,
        source: SignKeySource,
    ) -> Vec<axo_pass_core::audit::AuditEvent> {
        let audit_dir = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&audit_dir);
        unsafe { std::env::set_var("AXO_PASS_AUDIT_DIR", &audit_dir) };

        let pubkey = rsa_key().public_key().key_data().clone();
        let result = Err(AgentError::Other("declined".into()));
        audit::record_sign(
            None,
            Some("git (ssh)"),
            &pubkey,
            b"data",
            source,
            Some("vault-key"),
            None,
            &[],
            &result,
        );

        let page = axo_pass_core::audit::read(&axo_pass_core::audit::AuditFilter {
            actions: vec![axo_pass_core::audit::Action::SshSign],
            ..Default::default()
        });
        let _ = std::fs::remove_dir_all(&audit_dir);
        page.events
    }

    #[tokio::test]
    async fn vault_loaded_key_found_in_state() {
        let _guard = AUDIT_DIR_LOCK.lock().await;
        let state = Arc::new(Mutex::new(Vec::new()));
        let (shutdown_tx, _) = broadcast::channel(1);
        let session = SshAgentSession::new(state, None, None, None, shutdown_tx);
        session.store_credential(vault_loaded_credential()).await;

        let pubkey = rsa_key().public_key().key_data().clone();
        let found = session
            .find_credential(&pubkey)
            .await
            .expect("credential found without asking the app");

        assert_eq!(found.key_source(), SignKeySource::LoadedVault);
        assert!(found.dest_constraints().is_empty());
    }

    #[tokio::test]
    async fn vault_loaded_signature_recorded_by_agent() {
        let _guard = AUDIT_DIR_LOCK.lock().await;

        let events = record_vault_sign("axo-audit-vault-loaded", SignKeySource::LoadedVault);

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].detail.get("key_source").map(String::as_str),
            Some("vault")
        );
    }

    #[tokio::test]
    async fn app_signed_vault_signature_not_recorded_by_agent() {
        let _guard = AUDIT_DIR_LOCK.lock().await;

        let events = record_vault_sign("axo-audit-vault-app", SignKeySource::Vault);

        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn autoload_key_requires_confirm() {
        let _guard = AUDIT_DIR_LOCK.lock().await;
        let audit_dir =
            std::env::temp_dir().join(format!("axo-audit-autoload-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&audit_dir);
        unsafe { std::env::set_var("AXO_PASS_AUDIT_DIR", &audit_dir) };

        let data = include_str!("./fixtures/b64_rsa");
        let private_key = PrivateKey::from_bytes(b64.decode(data).unwrap().as_slice()).unwrap();
        let public_key = private_key.public_key().clone();

        let mut credential = StoredCredential::from(proto::PrivateCredential::Key {
            privkey: private_key.key_data().clone(),
            comment: "autoload-key".to_string(),
        });
        credential.autoload = true;

        let state = Arc::new(Mutex::new(Vec::new()));
        let (shutdown_tx, _) = broadcast::channel(1);
        let session = SshAgentSession::new(state, None, None, None, shutdown_tx);
        session.store_credential(credential).await;

        let stored = session
            .find_stored_credential(public_key.key_data())
            .await
            .expect("credential stored");
        assert_eq!(stored.confirm_policy(), Some(true));

        let page = axo_pass_core::audit::read(&axo_pass_core::audit::AuditFilter {
            actions: vec![axo_pass_core::audit::Action::SshKeyAdd],
            ..Default::default()
        });
        assert!(
            page.events
                .iter()
                .any(|e| e.detail.get("autoload").map(String::as_str) == Some("true")),
            "expected an ssh.key_add event with autoload=true"
        );

        let _ = std::fs::remove_dir_all(&audit_dir);
    }

    #[tokio::test]
    async fn expired_key_removed() {
        let _guard = AUDIT_DIR_LOCK.lock().await;
        let audit_dir =
            std::env::temp_dir().join(format!("axo-audit-expired-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&audit_dir);
        unsafe { std::env::set_var("AXO_PASS_AUDIT_DIR", &audit_dir) };

        let pubkey = rsa_key().public_key().key_data().clone();
        let mut credential = StoredCredential::from(proto::PrivateCredential::Key {
            privkey: rsa_key().key_data().clone(),
            comment: "expiring-key".to_string(),
        });
        credential.expires_at = Some(UtcDateTime::now() + time::Duration::minutes(10));

        let state = Arc::new(Mutex::new(Vec::new()));
        let (shutdown_tx, _) = broadcast::channel(1);
        let session = SshAgentSession::new(state.clone(), None, None, None, shutdown_tx);
        session.store_credential(credential).await;

        // Within its lifetime the key is found and stays in the agent.
        assert!(session.find_stored_credential(&pubkey).await.is_some());
        assert_eq!(state.lock().await.len(), 1);

        state.lock().await[0].expires_at = Some(UtcDateTime::now() - time::Duration::seconds(1));

        // The sweep that listing and lookup both run removes the key.
        session.remove_expired().await;
        assert!(state.lock().await.is_empty());
        assert!(session.find_stored_credential(&pubkey).await.is_none());

        let page = axo_pass_core::audit::read(&axo_pass_core::audit::AuditFilter {
            actions: vec![axo_pass_core::audit::Action::SshKeyRemove],
            ..Default::default()
        });
        assert!(
            page.events
                .iter()
                .any(|e| e.detail.get("reason").map(String::as_str) == Some("expired")),
            "expected an ssh.key_remove event with reason=expired"
        );

        let _ = std::fs::remove_dir_all(&audit_dir);
    }
}
