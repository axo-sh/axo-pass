use ssh_agent_lib::agent::Session;
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{AddIdentity, AddIdentityConstrained, Credential, Identity};

#[derive(Clone)]
pub struct SshAgentSession {}

impl SshAgentSession {
    pub fn new() -> Self {
        SshAgentSession {}
    }
}

#[ssh_agent_lib::async_trait]
impl Session for SshAgentSession {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        Ok(vec![])
    }

    async fn add_identity(&mut self, identity: AddIdentity) -> Result<(), AgentError> {
        log::debug!("Adding identity: {:?}", identity);
        match identity.credential {
            Credential::Key { privkey, comment } => {
                log::debug!("// {comment}");
                log::debug!("Private key type: {:?}", privkey);
            },
            Credential::Cert {
                algorithm,
                certificate,
                privkey,
                comment,
            } => {
                log::debug!("Algorithm: {algorithm}");
                log::debug!("Certificate: {certificate:?}");
                log::debug!("Private Key: {privkey:?}");
                log::debug!("Comment: {comment}");
            },
        }
        Ok(())
    }

    async fn add_identity_constrained(
        &mut self,
        identity: AddIdentityConstrained,
    ) -> Result<(), AgentError> {
        Ok(())
    }
}
