use axo_pass_core::audit;
use axo_pass_core::secrets::keychain::managed_key::ManagedSshKey;
use serde::Serialize;
use typeshare::typeshare;

use crate::app::handlers::app_errors::AppError;
use crate::app::handlers::ssh::schema::ssh_key_entry::SshKeyEntry;

#[derive(Debug, Clone, Serialize)]
#[typeshare]
pub struct AddManagedSshKeyResponse {
    pub key: SshKeyEntry,
}

#[tauri::command]
pub async fn add_managed_ssh_key() -> Result<AddManagedSshKeyResponse, AppError> {
    // todo: support managed ssh key aliases
    let result = ManagedSshKey::create().await;

    let mut event = audit::AuditEvent::new(
        audit::process_source(),
        audit::Action::SshManagedKeyCreate,
        match &result {
            Ok(_) => audit::Outcome::Succeeded,
            Err(_) => audit::Outcome::Failed,
        },
    );
    match &result {
        Ok(key) => {
            let fingerprint = format!("SHA256:{}", key.fingerprint_sha256());
            event = event.subject(
                audit::Subject::new(audit::SubjectKind::SshKey, fingerprint.clone())
                    .label(key.label())
                    .fingerprint(fingerprint),
            );
        },
        Err(e) => event = event.message(e.to_string()),
    }
    audit::record(event);

    let managed_key = result?;
    let overview: axo_pass_core::ssh::key_overview::SshKeyOverview = managed_key.into();
    Ok(AddManagedSshKeyResponse {
        key: overview.into(),
    })
}
