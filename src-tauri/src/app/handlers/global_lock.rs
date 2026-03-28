use crate::app::handlers::app_errors::AppError;
use crate::core::auth::{AuthContext, AuthMethod, invalidate_auth, run_on_auth_thread};

#[tauri::command]
pub async fn unlock_axo() -> Result<(), AppError> {
    log::debug!("command: unlock_axo");
    run_on_auth_thread(
        AuthContext::SharedThreadLocal,
        AuthMethod::Policy {
            reason: "unlock".to_string(),
        },
        |_| {},
    )
    .map_err(|e| e.into())
}

#[tauri::command]
pub async fn lock_axo() -> Result<(), AppError> {
    log::debug!("command: lock_axo");
    invalidate_auth();
    Ok(())
}
