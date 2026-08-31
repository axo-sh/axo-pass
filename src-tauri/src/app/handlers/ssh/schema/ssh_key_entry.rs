use std::collections::BTreeSet;

use axo_pass_core::ssh::key_overview::{
    SshKeyAgentKind as CoreSshKeyAgent, SshKeyLocation as CoreSshKeyLocation, SshKeyOverview,
};
use axo_pass_core::ssh::ssh_keys::SshKeyType;
use serde::Serialize;
use typeshare::typeshare;

#[derive(Debug, Clone, Serialize)]
#[typeshare]
pub enum SshKeyLocation {
    Vault,
    Transient,
    SshDir,
}

impl From<CoreSshKeyLocation> for SshKeyLocation {
    fn from(l: CoreSshKeyLocation) -> Self {
        match l {
            CoreSshKeyLocation::Vault => SshKeyLocation::Vault,
            CoreSshKeyLocation::Transient => SshKeyLocation::Transient,
            CoreSshKeyLocation::SshDir => SshKeyLocation::SshDir,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub enum SshKeyAgent {
    SystemAgent,
    AxoPassAgent,
}

impl From<CoreSshKeyAgent> for SshKeyAgent {
    fn from(a: CoreSshKeyAgent) -> Self {
        match a {
            CoreSshKeyAgent::SystemAgent => SshKeyAgent::SystemAgent,
            CoreSshKeyAgent::AxoPassAgent => SshKeyAgent::AxoPassAgent,
        }
    }
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

impl From<SshKeyOverview> for SshKeyEntry {
    fn from(overview: SshKeyOverview) -> Self {
        SshKeyEntry {
            name: overview.name,
            location: overview.location.into(),
            path: overview.path,
            public_key: overview.public_key,
            comment: overview.comment,
            key_type: overview.key_type,
            fingerprint_sha256: overview.fingerprint_sha256,
            fingerprint_md5: overview.fingerprint_md5,
            has_saved_password: overview.has_saved_password,
            is_managed: overview.is_managed,
            agent: overview.agents.into_iter().map(SshKeyAgent::from).collect(),
        }
    }
}
