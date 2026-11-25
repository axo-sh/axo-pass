use std::os::fd::BorrowedFd;

use axo_pass_core::core::app_broker::{self, BrokerError, KeySource, ManagedIdentity, SignPurpose};
use axo_pass_core::core::provenance::ProcessNode;
use axo_pass_core::ssh::ssh_keys::SshKeyType;
use ssh_agent_lib::proto;
use ssh_key::PublicKey;
use ssh_key::public::KeyData;

use crate::cli::commands::ssh_agent::audit::SignKeySource;
use crate::cli::commands::ssh_agent::autoload_credential::LoadError;
use crate::cli::commands::ssh_agent::credential::{Credential, CredentialError};
use crate::cli::commands::ssh_agent::stored_credential::StoredCredential;

/// A key held by the app: a Secure Enclave key or an SSH key stored in a vault.
///
/// The agent cannot reach these keys itself. Secure Enclave keys live in the
/// data protection keychain, which needs an entitlement AMFI only grants to
/// code carrying a provisioning profile, and a plain executable has nowhere to
/// hold one. Vault keys need the vault encryption key, which the app unlocks
/// behind a prompt. So the agent knows a managed key by its public half alone
/// and asks the app whenever the private half is needed.
#[derive(Debug, Clone)]
pub struct ManagedCredential {
    pub key_label: String,
    pub public_key: KeyData,
    pub comment: String,
    pub source: KeySource,
    /// The agent lists the key in `request_identities`. The agent signs with a
    /// key that is not listed if a client names it.
    pub auto_load: bool,
}

impl ManagedCredential {
    /// Whether the agent loads the key on first use. True for a vault key with
    /// auto-load on. The app signs with any other managed key and the agent
    /// never holds it.
    pub fn loads_into_agent(&self) -> bool {
        matches!(self.source, KeySource::Vault { .. }) && self.auto_load
    }

    /// Ask the app for the private key. Blocks while the user answers the vault
    /// access prompt. The credential is marked auto-load, so every later use is
    /// confirmed unless an app grant applies. The signature that caused the
    /// load is covered by the vault prompt.
    pub fn load(
        &self,
        caller: Option<&str>,
        caller_chain: &[ProcessNode],
        purpose: Option<&SignPurpose>,
        requester: Option<BorrowedFd<'_>>,
    ) -> Result<StoredCredential, LoadError> {
        let fingerprint = self
            .public_key
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string();
        let comment = (!self.comment.is_empty()).then_some(self.comment.as_str());
        let private = call_broker(|| {
            app_broker::request_vault_key(
                &fingerprint,
                comment,
                caller,
                caller_chain,
                purpose,
                requester,
            )
        })
        .map_err(|e| match e {
            BrokerError::Cancelled | BrokerError::RequesterDisconnected => {
                LoadError::Cancelled(fingerprint.clone())
            },
            e => LoadError::Failed(format!("Could not load the vault key {fingerprint}: {e}")),
        })?;

        let comment = if private.comment().is_empty() {
            self.comment.clone()
        } else {
            private.comment().to_string()
        };
        log::debug!("Loaded vault key {fingerprint} {}", self.key_label);

        let mut credential = StoredCredential::from(proto::PrivateCredential::Key {
            privkey: private.key_data().clone(),
            comment,
        });
        credential.autoload = true;
        credential.vault_loaded = true;
        Ok(credential)
    }
}

impl TryFrom<ManagedIdentity> for ManagedCredential {
    type Error = ssh_key::Error;

    fn try_from(identity: ManagedIdentity) -> Result<Self, Self::Error> {
        let public_key = PublicKey::from_openssh(&identity.public_key)?;
        Ok(Self {
            key_label: identity.key_label,
            comment: public_key.comment().to_string(),
            public_key: public_key.key_data().clone(),
            source: identity.source,
            auto_load: identity.auto_load,
        })
    }
}

impl From<&ManagedCredential> for proto::Identity {
    fn from(credential: &ManagedCredential) -> Self {
        proto::Identity {
            credential: proto::PublicCredential::Key(credential.public_key_data()),
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
pub(super) fn call_broker<T, F>(work: F) -> T
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
pub fn list_managed_credentials(requester: Option<BorrowedFd<'_>>) -> Vec<ManagedCredential> {
    let identities = match call_broker(|| app_broker::list_identities(requester)) {
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
    fn comment(&self) -> Option<String> {
        Some(self.comment.clone()).filter(|c| !c.is_empty())
    }

    fn key_label(&self) -> Option<String> {
        Some(self.key_label.clone())
    }

    fn key_source(&self) -> SignKeySource {
        match self.source {
            KeySource::SecureEnclave => SignKeySource::SecureEnclave,
            KeySource::Vault { .. } => SignKeySource::Vault,
        }
    }

    fn key_type(&self) -> SshKeyType {
        self.public_key.algorithm().into()
    }

    fn public_key_data(&self) -> KeyData {
        self.public_key.clone()
    }

    fn sign(
        &self,
        req: proto::SignRequest,
        caller: Option<&str>,
        caller_chain: &[ProcessNode],
        purpose: Option<&SignPurpose>,
        requester: Option<BorrowedFd<'_>>,
    ) -> Result<ssh_key::Signature, CredentialError> {
        let fingerprint = self
            .public_key
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string();
        let comment = (!self.comment.is_empty()).then_some(self.comment.as_str());
        let result = call_broker(|| match self.source {
            KeySource::SecureEnclave => app_broker::request_signature(
                &self.key_label,
                Some(&fingerprint),
                comment,
                &req.data,
                req.flags,
                caller,
                caller_chain,
                purpose,
                requester,
            ),
            KeySource::Vault { .. } => app_broker::request_vault_signature(
                &fingerprint,
                comment,
                &req.data,
                req.flags,
                caller,
                caller_chain,
                purpose,
                requester,
            ),
        });

        result.map_err(|e| {
            match e {
                BrokerError::Cancelled => {
                    log::debug!("User declined signing with {}", self.key_label)
                },
                BrokerError::RequesterDisconnected => {
                    log::debug!("Client disconnected while signing with {}", self.key_label)
                },
                e => log::error!("Failed to sign with managed key {}: {e}", self.key_label),
            }
            CredentialError::SigningFailed
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLIC_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl laptop";

    fn identity(source: KeySource) -> ManagedIdentity {
        ManagedIdentity {
            key_label: "label".to_string(),
            public_key: PUBLIC_KEY.to_string(),
            source,
            auto_load: true,
        }
    }

    fn vault_source() -> KeySource {
        KeySource::Vault {
            vault_key: "personal".to_string(),
            item_key: "github".to_string(),
            credential_key: "key".to_string(),
        }
    }

    #[test]
    fn vault_key_with_auto_load_loads_into_agent() {
        let credential = ManagedCredential::try_from(identity(vault_source())).unwrap();

        assert!(credential.loads_into_agent());
    }

    #[test]
    fn vault_key_without_auto_load_signed_by_app() {
        let mut identity = identity(vault_source());
        identity.auto_load = false;

        let credential = ManagedCredential::try_from(identity).unwrap();

        assert!(!credential.loads_into_agent());
        assert_eq!(credential.key_source(), SignKeySource::Vault);
    }

    #[test]
    fn secure_enclave_key_signed_by_app() {
        let credential = ManagedCredential::try_from(identity(KeySource::SecureEnclave)).unwrap();

        assert!(!credential.loads_into_agent());
    }

    #[test]
    fn credential_keeps_secure_enclave_source() {
        let credential = ManagedCredential::try_from(identity(KeySource::SecureEnclave)).unwrap();

        assert_eq!(credential.source, KeySource::SecureEnclave);
        assert_eq!(credential.comment, "laptop");
    }

    #[test]
    fn credential_keeps_vault_source() {
        let source = KeySource::Vault {
            vault_key: "personal".to_string(),
            item_key: "github".to_string(),
            credential_key: "key".to_string(),
        };

        let credential = ManagedCredential::try_from(identity(source.clone())).unwrap();

        assert_eq!(credential.source, source);
    }

    #[test]
    fn credential_reports_audit_key_source() {
        let enclave = ManagedCredential::try_from(identity(KeySource::SecureEnclave)).unwrap();
        let vault = ManagedCredential::try_from(identity(KeySource::Vault {
            vault_key: "personal".to_string(),
            item_key: "github".to_string(),
            credential_key: "key".to_string(),
        }))
        .unwrap();

        assert_eq!(enclave.key_source(), SignKeySource::SecureEnclave);
        assert_eq!(vault.key_source(), SignKeySource::Vault);
    }

    #[test]
    fn credential_refused_for_invalid_public_key() {
        let mut bad = identity(KeySource::SecureEnclave);
        bad.public_key = "not a key".to_string();

        assert!(ManagedCredential::try_from(bad).is_err());
    }
}
