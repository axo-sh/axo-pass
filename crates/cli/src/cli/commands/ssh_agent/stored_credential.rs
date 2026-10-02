use std::fmt::Debug;
use std::os::fd::BorrowedFd;

use axo_pass_core::core::app_broker::{self, BrokerError, SignPurpose};
use axo_pass_core::core::provenance::ProcessNode;
use axo_pass_core::ssh::rsa_signing;
use axo_pass_core::ssh::ssh_keys::SshKeyType;
use axo_pass_core::ssh::utils::compute_short_sha256_fingerprint;
use ssh_agent_lib::proto::{self, extension};
use ssh_key::HashAlg;
use ssh_key::public::KeyData;
use time::{Duration, UtcDateTime};

use crate::cli::commands::ssh_agent::credential::{Credential, CredentialError};
use crate::cli::commands::ssh_agent::managed_credential::call_broker;

#[derive(Clone)]
pub struct StoredCredential {
    pub credential: proto::PrivateCredential,
    pub expires_at: Option<UtcDateTime>,
    /// Added with `ssh-add -c`: every use prompts, and app grants never apply.
    pub requires_auth: bool,
    pub dest_constraints: Vec<extension::DestinationConstraint>,
    /// Configured for auto-load: every use prompts unless an app grant
    /// applies. Independent of `requires_auth`, which takes precedence.
    pub autoload: bool,
}

impl StoredCredential {
    pub fn add_constraints(mut self, constraints: Vec<proto::KeyConstraint>) -> Self {
        for c in constraints {
            match c {
                proto::KeyConstraint::Lifetime(secs) => {
                    let now = UtcDateTime::now();
                    let valid_duration = Duration::seconds(secs as i64);
                    self.expires_at = Some(now + valid_duration);
                },
                proto::KeyConstraint::Confirm => {
                    self.requires_auth = true;
                },
                proto::KeyConstraint::Extension(extension) => {
                    if let Ok(Some(restrict_dest)) =
                        extension.parse_key_constraint::<extension::RestrictDestination>()
                    {
                        self.dest_constraints
                            .extend(restrict_dest.constraints.iter().cloned());
                    }
                },
            }
        }
        self
    }

    pub fn validate(
        &self,
        caller: Option<&str>,
        caller_chain: &[ProcessNode],
        purpose: Option<&SignPurpose>,
        requester: Option<BorrowedFd<'_>>,
    ) -> Result<(), CredentialError> {
        if let Some(expiry) = self.expires_at {
            let now = UtcDateTime::now();
            if now > expiry {
                return Err(CredentialError::Expired);
            }
        }

        if let Some(allow_grants) = self.confirm_policy() {
            self.confirm_use(caller, caller_chain, purpose, allow_grants, requester)?;
        }
        Ok(())
    }

    /// Whether a use must be confirmed, and if so whether an app grant may
    /// confirm it. `None` when no confirmation is needed.
    pub fn confirm_policy(&self) -> Option<bool> {
        if self.requires_auth {
            Some(false)
        } else if self.autoload {
            Some(true)
        } else {
            None
        }
    }

    /// Handles a confirmed signature. Asks the app to render the prompt and
    /// run authentication, so the user sees the same panel as for a managed
    /// key. Refuses the signature when the app cannot be reached or the prompt
    /// fails.
    fn confirm_use(
        &self,
        caller: Option<&str>,
        caller_chain: &[ProcessNode],
        purpose: Option<&SignPurpose>,
        allow_grants: bool,
        requester: Option<BorrowedFd<'_>>,
    ) -> Result<(), CredentialError> {
        let fingerprint = self
            .public_key_data()
            .fingerprint(HashAlg::Sha256)
            .to_string();
        let comment = self.comment();

        match call_broker(|| {
            app_broker::request_authorize_key_use(
                Some(&fingerprint),
                comment.as_deref(),
                caller,
                caller_chain,
                purpose,
                allow_grants,
                requester,
            )
        }) {
            Ok(()) => Ok(()),
            Err(BrokerError::Cancelled) => {
                log::debug!("User declined use of ssh key {fingerprint}");
                Err(CredentialError::Locked)
            },
            Err(BrokerError::RequesterDisconnected) => {
                log::debug!("Client disconnected while confirming use of ssh key {fingerprint}");
                Err(CredentialError::Locked)
            },
            Err(e) => {
                log::error!("Could not confirm use of ssh key {fingerprint}: {e}");
                Err(CredentialError::Locked)
            },
        }
    }

    /// Sign once `validate` has passed.
    fn sign_validated(
        &self,
        req: proto::SignRequest,
    ) -> Result<ssh_key::Signature, CredentialError> {
        match &self.credential {
            proto::PrivateCredential::Key { privkey, .. } => {
                rsa_signing::sign_with_flags(privkey, &req.data, req.flags).map_err(|e| {
                    log::error!("Failed to sign data with private key: {e:#}");
                    CredentialError::SigningFailed
                })
            },
            proto::PrivateCredential::Cert { .. } => {
                todo!("Certificate signing not yet implemented");
            },
        }
    }
}

impl Credential for StoredCredential {
    fn comment(&self) -> Option<String> {
        let comment = match &self.credential {
            proto::PrivateCredential::Key { comment, .. }
            | proto::PrivateCredential::Cert { comment, .. } => comment.clone(),
        };
        Some(comment).filter(|c| !c.is_empty())
    }

    fn key_type(&self) -> SshKeyType {
        match &self.credential {
            proto::PrivateCredential::Key { privkey, .. } => privkey
                .algorithm()
                .map(|a| a.into())
                .unwrap_or(SshKeyType::Unknown),
            proto::PrivateCredential::Cert { certificate, .. } => {
                certificate.public_key().algorithm().into()
            },
        }
    }

    fn public_key_data(&self) -> KeyData {
        match &self.credential {
            proto::PrivateCredential::Key { privkey, .. } => privkey.try_into().clone().unwrap(),
            proto::PrivateCredential::Cert { certificate, .. } => certificate.public_key().clone(),
        }
    }

    fn sign(
        &self,
        req: proto::SignRequest,
        caller: Option<&str>,
        caller_chain: &[ProcessNode],
        purpose: Option<&SignPurpose>,
        requester: Option<BorrowedFd<'_>>,
    ) -> Result<ssh_key::Signature, CredentialError> {
        self.validate(caller, caller_chain, purpose, requester)?;
        self.sign_validated(req)
    }

    fn dest_constraints(&self) -> Vec<extension::DestinationConstraint> {
        self.dest_constraints.clone()
    }
}

impl TryInto<proto::Identity> for &StoredCredential {
    type Error = ssh_key::Error;

    fn try_into(self) -> Result<proto::Identity, Self::Error> {
        match &self.credential {
            proto::PrivateCredential::Key { privkey, comment } => Ok(proto::Identity {
                credential: proto::PublicCredential::Key(privkey.try_into()?),
                comment: comment.clone(),
            }),
            proto::PrivateCredential::Cert {
                certificate,
                comment,
                ..
            } => Ok(proto::Identity {
                credential: proto::PublicCredential::Cert(certificate.clone()),
                comment: comment.clone(),
            }),
        }
    }
}

impl From<proto::PrivateCredential> for StoredCredential {
    fn from(credential: proto::PrivateCredential) -> Self {
        StoredCredential {
            credential,
            expires_at: None,
            requires_auth: false,
            dest_constraints: Vec::new(),
            autoload: false,
        }
    }
}

impl Debug for StoredCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out = match self.try_into() {
            Ok(proto::Identity {
                credential,
                comment,
            }) => {
                let cred_type = &match &self.credential {
                    proto::PrivateCredential::Key { .. } => "key",
                    proto::PrivateCredential::Cert { .. } => "cert",
                };
                let key_data = credential.key_data();
                format!(
                    "{} {cred_type} {} {comment}",
                    &key_data.algorithm(),
                    compute_short_sha256_fingerprint(key_data)
                )
            },
            Err(e) => e.to_string(),
        };
        if self.requires_auth {
            out.push_str(" requires_auth");
        };
        if self.autoload {
            out.push_str(" autoload");
        };
        if let Some(expiry) = self.expires_at {
            out.push_str(&format!(" expires_at={}", expiry));
        }

        write!(f, "StoredCredential {{ {} }}", out)
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD_NO_PAD as b64;
    use ssh_key::PrivateKey;

    use super::*;

    fn credential(requires_auth: bool, autoload: bool) -> StoredCredential {
        let data = include_str!("./fixtures/b64_rsa");
        let private_key = PrivateKey::from_bytes(b64.decode(data).unwrap().as_slice()).unwrap();
        let mut credential = StoredCredential::from(proto::PrivateCredential::Key {
            privkey: private_key.key_data().clone(),
            comment: String::new(),
        });
        credential.requires_auth = requires_auth;
        credential.autoload = autoload;
        credential
    }

    #[test]
    fn confirm_policy() {
        assert_eq!(credential(false, false).confirm_policy(), None);
        assert_eq!(credential(false, true).confirm_policy(), Some(true));
        // `ssh-add -c` prompts every time, even for an auto-load key.
        assert_eq!(credential(true, false).confirm_policy(), Some(false));
        assert_eq!(credential(true, true).confirm_policy(), Some(false));
    }
}
