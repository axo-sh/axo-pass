use axo_pass_core::core::sign_broker::{self, ManagedIdentity, SignBrokerError};
use axo_pass_core::ssh::ssh_keys::SshKeyType;
use ssh_agent_lib::proto;
use ssh_key::PublicKey;
use ssh_key::public::KeyData;

use crate::cli::commands::ssh_agent::credential::{Credential, CredentialError};

/// A Secure Enclave key held by the app.
///
/// The agent cannot reach these keys itself: they live in the data protection
/// keychain, which needs an entitlement AMFI only grants to code carrying a
/// provisioning profile, and a plain executable has nowhere to hold one. So the
/// agent knows a managed key by its public half alone and asks the app whenever
/// the private half is needed.
#[derive(Debug, Clone)]
pub struct ManagedCredential {
    pub key_label: String,
    pub public_key: KeyData,
    pub comment: String,
}

impl TryFrom<ManagedIdentity> for ManagedCredential {
    type Error = ssh_key::Error;

    fn try_from(identity: ManagedIdentity) -> Result<Self, Self::Error> {
        let public_key = PublicKey::from_openssh(&identity.public_key)?;
        Ok(Self {
            key_label: identity.key_label,
            comment: public_key.comment().to_string(),
            public_key: public_key.key_data().clone(),
        })
    }
}

impl From<&ManagedCredential> for proto::Identity {
    fn from(credential: &ManagedCredential) -> Self {
        proto::Identity {
            pubkey: credential.public_key.clone(),
            comment: credential.comment.clone(),
        }
    }
}

/// Run a blocking broker call from async context.
///
/// These wait on the app, and on the user answering its prompt, so the runtime
/// gets its worker thread back for the duration. `block_in_place` does that but
/// requires the multi-threaded runtime the agent runs on. Elsewhere, in tests
/// above all, the work runs on a scratch thread instead.
fn call_broker<T, F>(work: F) -> T
where
    F: FnOnce() -> T + Send,
    T: Send,
{
    use tokio::runtime::{Handle, RuntimeFlavor};

    match Handle::try_current().map(|handle| handle.runtime_flavor()) {
        Ok(RuntimeFlavor::MultiThread) => tokio::task::block_in_place(work),
        _ => std::thread::scope(|scope| scope.spawn(work).join().unwrap()),
    }
}

/// Every managed key the app is willing to sign with. Starts the app if it is
/// not running, so listing identities does not silently come back empty.
///
/// A failure is reported as an empty list rather than an error: the agent still
/// serves the keys added to it directly, and failing here would break
/// `ssh-add -l` for those too.
pub fn list_managed_credentials() -> Vec<ManagedCredential> {
    let identities = match call_broker(sign_broker::list_identities) {
        Ok(identities) => identities,
        Err(e) => {
            log::warn!("Could not list managed keys: {e}");
            return Vec::new();
        },
    };

    identities
        .into_iter()
        .filter_map(|identity| {
            let key_label = identity.key_label.clone();
            ManagedCredential::try_from(identity)
                .inspect_err(|e| log::error!("Skipping managed key {key_label}: {e}"))
                .ok()
        })
        .collect()
}

impl Credential for ManagedCredential {
    fn key_type(&self) -> SshKeyType {
        SshKeyType::Ecdsa
    }

    fn public_key_data(&self) -> KeyData {
        self.public_key.clone()
    }

    fn sign(
        &self,
        req: proto::SignRequest,
        caller: Option<&str>,
    ) -> Result<ssh_key::Signature, CredentialError> {
        let result =
            call_broker(|| sign_broker::request_signature(&self.key_label, &req.data, caller));

        result.map_err(|e| {
            match e {
                SignBrokerError::Cancelled => {
                    log::debug!("User declined signing with {}", self.key_label)
                },
                e => log::error!("Failed to sign with managed key {}: {e}", self.key_label),
            }
            CredentialError::SigningFailed
        })
    }
}
