mod rsa_signing;

use std::fmt::Debug;

use rsa::signature::Signer;
use ssh_agent_lib::proto::{self, extension};
use ssh_key::Algorithm;
use ssh_key::public::KeyData;
use time::{Duration, UtcDateTime};

use crate::cli::commands::ssh_agent::credential::{Credential, CredentialError};
use crate::core::auth::{AuthContext, AuthMethod, run_on_auth_thread};
use crate::ssh::ssh_keys::SshKeyType;
use crate::ssh::utils::compute_short_sha256_fingerprint;

#[derive(Clone)]
pub struct StoredCredential {
    pub credential: proto::Credential,
    pub expires_at: Option<UtcDateTime>,
    pub requires_auth: bool,
    pub dest_constraints: Vec<extension::DestinationConstraint>,
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

    pub fn validate(&self, caller: Option<&str>) -> Result<(), CredentialError> {
        if let Some(expiry) = self.expires_at {
            let now = UtcDateTime::now();
            if now > expiry {
                return Err(CredentialError::Expired);
            }
        }

        if self.requires_auth {
            let reason = match caller {
                Some(c) => format!("unlock a ssh key for {c}"),
                None => "unlock a ssh key".to_string(),
            };
            if let Err(e) =
                run_on_auth_thread(AuthContext::OneTime, AuthMethod::Policy { reason }, |_| {})
            {
                log::error!("Authentication failed: {e}");
                return Err(CredentialError::Locked);
            }
        }
        Ok(())
    }
}

impl Credential for StoredCredential {
    fn key_type(&self) -> SshKeyType {
        match &self.credential {
            proto::Credential::Key { privkey, .. } => privkey
                .algorithm()
                .map(|a| a.into())
                .unwrap_or(SshKeyType::Unknown),
            proto::Credential::Cert { certificate, .. } => {
                certificate.public_key().algorithm().into()
            },
        }
    }

    fn public_key_data(&self) -> KeyData {
        match &self.credential {
            proto::Credential::Key { privkey, .. } => privkey.try_into().clone().unwrap(),
            proto::Credential::Cert { certificate, .. } => certificate.public_key().clone(),
        }
    }

    fn sign(
        &self,
        req: proto::SignRequest,
        caller: Option<&str>,
    ) -> Result<ssh_key::Signature, CredentialError> {
        self.validate(caller)?;
        match &self.credential {
            proto::Credential::Key { privkey, .. } => {
                let key_algorithm = privkey.algorithm().map_err(|e| {
                    log::error!("Failed to get key algorithm: {e}");
                    CredentialError::SigningFailed
                })?;

                // special handling for rsa keys due to bugs in dependencies (see rsa_signing)
                if matches!(key_algorithm, Algorithm::Rsa { .. }) {
                    return rsa_signing::sign_rsa(privkey, &req.data, req.flags);
                };

                privkey.try_sign(&req.data).map_err(|e| {
                    log::error!("Failed to sign data with private key: {e}");
                    CredentialError::SigningFailed
                })
            },
            proto::Credential::Cert { .. } => {
                todo!("Certificate signing not yet implemented");
            },
        }
    }

    fn dest_constraints(&self) -> Vec<extension::DestinationConstraint> {
        self.dest_constraints.clone()
    }
}

impl TryInto<proto::Identity> for &StoredCredential {
    type Error = ssh_key::Error;

    fn try_into(self) -> Result<proto::Identity, Self::Error> {
        match &self.credential {
            proto::Credential::Key { privkey, comment } => Ok(proto::Identity {
                pubkey: privkey.try_into()?,
                comment: comment.clone(),
            }),
            proto::Credential::Cert {
                certificate,
                comment,
                ..
            } => Ok(proto::Identity {
                pubkey: certificate.public_key().clone(),
                comment: comment.clone(),
            }),
        }
    }
}

impl From<proto::Credential> for StoredCredential {
    fn from(credential: proto::Credential) -> Self {
        StoredCredential {
            credential,
            expires_at: None,
            requires_auth: false,
            dest_constraints: Vec::new(),
        }
    }
}

impl Debug for StoredCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out = match self.try_into() {
            Ok(proto::Identity { pubkey, comment }) => {
                let cred_type = &match &self.credential {
                    proto::Credential::Key { .. } => "key",
                    proto::Credential::Cert { .. } => "cert",
                };
                format!(
                    "{} {cred_type} {} {comment}",
                    &pubkey.algorithm(),
                    compute_short_sha256_fingerprint(&pubkey)
                )
            },
            Err(e) => e.to_string(),
        };
        if self.requires_auth {
            out.push_str(" requires_auth");
        };
        if let Some(expiry) = self.expires_at {
            out.push_str(&format!(" expires_at={}", expiry));
        }

        write!(f, "StoredCredential {{ {} }}", out)
    }
}
