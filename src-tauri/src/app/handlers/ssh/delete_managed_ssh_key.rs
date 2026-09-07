use axo_pass_core::audit;
use axo_pass_core::secrets::keychain::managed_key::ManagedSshKey;
use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::app::handlers::app_errors::{AppError, ErrorContext};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[typeshare]
#[serde(rename_all = "snake_case")]
pub struct DeleteManagedSshKeyRequest {
    label: String,
}

#[tauri::command]
pub async fn delete_managed_ssh_key(request: DeleteManagedSshKeyRequest) -> Result<(), AppError> {
    let key = ManagedSshKey::find(&request.label)?
        .ok_or_else(|| AppError::not_found(&format!("SSH key {} not found", request.label)))?;
    let fingerprint = format!("SHA256:{}", key.fingerprint_sha256());
    let label = key.label();
    let result = key
        .delete()
        .error_context(format!("Failed to delete SSH key {}", request.label));

    let mut event = audit::AuditEvent::new(
        audit::process_source(),
        audit::Action::SshManagedKeyDelete,
        match &result {
            Ok(_) => audit::Outcome::Succeeded,
            Err(_) => audit::Outcome::Failed,
        },
    )
    .subject(
        audit::Subject::new(audit::SubjectKind::SshKey, fingerprint.clone())
            .label(label)
            .fingerprint(fingerprint),
    );
    if let Err(e) = &result {
        event = event.message(e.to_string());
    }
    audit::record(event);

    result
}
