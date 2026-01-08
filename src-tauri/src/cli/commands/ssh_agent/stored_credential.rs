mod rsa_signing;

use std::fmt::Debug;

use rsa::signature::Signer;
use ssh_agent_lib::proto;
use ssh_key::Algorithm;
use time::{Duration, UtcDateTime};

use crate::cli::commands::ssh_agent::credential::{Credential, CredentialError};
use crate::core::la_context::evaluate_la_context;

#[derive(Clone)]
pub struct StoredCredential {
    pub credential: proto::Credential,
    pub expires_at: Option<UtcDateTime>,
    pub requires_auth: bool,
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
                    let key_constraint =
                        extension.parse_key_constraint::<proto::extension::RestrictDestination>();
                    if let Ok(Some(rd)) = key_constraint {
                        log::debug!(
                            "SSH key restrict-destination constraint: allowed destinations: {:?}",
                            rd.constraints
                        );
                        log::warn!("restrict-destination constraint is not currently enforced");
                        continue;
                    }
                    log::warn!("Unsupported key constraint: {:?}", extension);
                },
            }
        }
        self
    }

    pub fn validate(&self) -> Result<(), CredentialError> {
        if let Some(expiry) = self.expires_at {
            let now = UtcDateTime::now();
            if now > expiry {
                return Err(CredentialError::Expired);
            }
        }

        if self.requires_auth {
            // todo: show more detail in the auth prompt, e.g.
            // - which key is being used
            // - who is requesting it
            // - for what purpose
            if let Err(err) = evaluate_la_context("unlock a ssh key") {
                log::error!("Failed to authenticate for SSH key: {err}");
                return Err(CredentialError::Locked);
            }
        }
        Ok(())
    }
}

impl Credential for StoredCredential {
    fn sign(&self, req: proto::SignRequest) -> Result<ssh_key::Signature, CredentialError> {
        self.validate()?;
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
        }
    }
}

impl Debug for StoredCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("StoredCredential");

        s.field(
            "credential_type",
            &match &self.credential {
                proto::Credential::Key { .. } => "Key",
                proto::Credential::Cert { .. } => "Cert",
            },
        );

        let identity: Result<proto::Identity, ssh_key::Error> = self.try_into();
        match identity {
            Ok(id) => {
                s.field("algorithm", &id.pubkey.algorithm());
                let fp = &id.pubkey.fingerprint(ssh_key::HashAlg::Sha256);
                s.field("fingerprint", &fp.to_string());
                s.field("comment", &id.comment);
            },
            Err(e) => {
                s.field("public_key_error", &e.to_string());
            },
        }
        s.field("expires_at", &self.expires_at);
        s.field("requires_auth", &self.requires_auth);
        s.finish()
    }
}
