use std::collections::{BTreeSet, HashMap};

use serde::Serialize;
use ssh_key::HashAlg;
use typeshare::typeshare;

use crate::cli::commands::ssh_agent::{
    AgentStatus, get_agent_status, list_axo_agent_identities, list_system_agent_identities,
};

#[derive(Debug, Clone, Serialize)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub enum SshAgentStatus {
    Running,
    NotRunning,
    StaleSocket,
}

impl From<AgentStatus> for SshAgentStatus {
    fn from(status: AgentStatus) -> Self {
        match status {
            AgentStatus::Running => SshAgentStatus::Running,
            AgentStatus::NotRunning => SshAgentStatus::NotRunning,
            AgentStatus::StaleSocket => SshAgentStatus::StaleSocket,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub enum SshKeyTag {
    Transient,
    SystemAgent,
    AxoPassAgent,
}

#[derive(Debug, Clone, Serialize)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub struct SshAgentIdentity {
    pub fingerprint: String,
    pub comment: String,
    pub tags: BTreeSet<SshKeyTag>,
}

#[derive(Debug, Clone, Serialize)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub struct SshAgentStatusResponse {
    pub status: SshAgentStatus,
    pub identities: Vec<SshAgentIdentity>,
}

#[tauri::command]
pub async fn get_ssh_agent_status() -> Result<SshAgentStatusResponse, String> {
    let status = get_agent_status().await;
    let mut identities: HashMap<String, SshAgentIdentity> = HashMap::new();

    // Query system agent (SSH_AUTH_SOCK)
    if let Ok(agent_identities) = list_system_agent_identities().await {
        for identity in agent_identities {
            let fingerprint = identity.pubkey.fingerprint(HashAlg::Sha256).to_string();
            identities
                .entry(fingerprint.clone())
                .and_modify(|e| {
                    e.tags.insert(SshKeyTag::SystemAgent);
                })
                .or_insert(SshAgentIdentity {
                    fingerprint,
                    comment: identity.comment.to_string(),
                    tags: BTreeSet::from([SshKeyTag::SystemAgent]),
                });
        }
    }

    // Query our agent if it's running
    if matches!(status, AgentStatus::Running)
        && let Ok(agent_identities) = list_axo_agent_identities().await
    {
        for identity in agent_identities {
            let fingerprint = identity.pubkey.fingerprint(HashAlg::Sha256).to_string();
            identities
                .entry(fingerprint.clone())
                .and_modify(|e| {
                    e.tags.insert(SshKeyTag::AxoPassAgent);
                })
                .or_insert(SshAgentIdentity {
                    fingerprint,
                    comment: identity.comment.to_string(),
                    tags: BTreeSet::from([SshKeyTag::AxoPassAgent]),
                });
        }
    }

    Ok(SshAgentStatusResponse {
        status: status.into(),
        identities: identities.into_values().collect(),
    })
}
