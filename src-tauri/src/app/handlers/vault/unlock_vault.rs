use crate::core::auth::{AuthContext, AuthMethod, invalidate_auth, run_on_auth_thread};

#[tauri::command]
pub async fn unlock_axo() -> Result<(), String> {
    log::debug!("command: unlock_axo");
    run_on_auth_thread(
        AuthContext::SharedThreadLocal,
        AuthMethod::Policy {
            reason: "unlock Axo".to_string(),
        },
        |_| {},
    )
    .map_err(|e| format!("Failed to authenticate: {e}"))
}

#[tauri::command]
pub async fn lock_axo() -> Result<(), String> {
    log::debug!("command: lock_axo");
    invalidate_auth();
    Ok(())
}
