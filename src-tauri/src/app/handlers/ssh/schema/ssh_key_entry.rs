use std::collections::BTreeSet;

use serde::Serialize;
use ssh_agent_lib::proto;
use typeshare::typeshare;

use crate::secrets::keychain::managed_key::ManagedSshKey;
use crate::ssh::ssh_keys::{SshKeyType, SystemSshKey};
use crate::ssh::utils::{compute_md5_fingerprint, compute_sha256_fingerprint};

#[derive(Debug, Clone, Serialize)]
#[typeshare]
pub enum SshKeyLocation {
    Vault,
    Transient,
    SshDir,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub enum SshKeyAgent {
    SystemAgent,
    AxoPassAgent,
}

#[derive(Debug, Clone, Serialize)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub struct SshKeyEntry {
    pub name: String,
    pub location: SshKeyLocation,
    pub path: Option<String>,
    pub public_key: Option<String>,
    pub comment: Option<String>,
    pub key_type: SshKeyType,
    pub fingerprint_sha256: String,
    pub fingerprint_md5: String,
    pub has_saved_password: bool,
    pub is_managed: bool,
    #[typeshare(typescript(type = "SshKeyAgent[]"))]
    pub agent: BTreeSet<SshKeyAgent>,
}

impl From<proto::Identity> for SshKeyEntry {
    fn from(identity: proto::Identity) -> Self {
        let comment = identity.comment;
        SshKeyEntry {
            name: comment.clone(),
            location: SshKeyLocation::Transient,
            path: Some(comment.clone()),
            public_key: None,
            comment: Some(comment.clone()),
            key_type: identity.pubkey.algorithm().into(),
            fingerprint_sha256: compute_sha256_fingerprint(&identity.pubkey),
            fingerprint_md5: compute_md5_fingerprint(&identity.pubkey),
            has_saved_password: false,
            is_managed: false,
            agent: BTreeSet::new(),
        }
    }
}

impl From<SystemSshKey> for SshKeyEntry {
    fn from(system_key: SystemSshKey) -> Self {
        SshKeyEntry {
            name: system_key.name,
            location: SshKeyLocation::SshDir,
            path: Some(system_key.path.to_string_lossy().to_string()),
            public_key: system_key
                .public_key_path
                .as_ref()
                .map(|p| format!("{}", p.display())),
            comment: Some(system_key.comment),
            key_type: system_key.key_type,
            fingerprint_sha256: system_key.fingerprint_sha256.clone(),
            fingerprint_md5: system_key.fingerprint_md5.clone(),
            // note: we could do system_key.has_saved_password()
            // but it makes a system call so we leave it to the caller
            has_saved_password: false,
            is_managed: false,
            agent: BTreeSet::new(),
        }
    }
}

impl From<ManagedSshKey> for SshKeyEntry {
    fn from(managed_key: ManagedSshKey) -> Self {
        SshKeyEntry {
            name: managed_key.name(),
            location: SshKeyLocation::Vault,
            path: None,
            key_type: SshKeyType::Ecdsa, // Managed keys are always ECDSA
            public_key: managed_key
                .pubkey_path()
                .ok()
                .filter(|p| p.exists())
                .map(|p| format!("{}", p.display())),
            comment: None,
            fingerprint_sha256: managed_key.fingerprint_sha256().to_string(),
            fingerprint_md5: managed_key.fingerprint_md5().to_string(),
            has_saved_password: false,
            is_managed: true,
            agent: BTreeSet::new(),
        }
    }
}
