use std::sync::Mutex;

use crate::app::AppState;
use crate::secrets::vault_wrapper::VaultWrapper;

pub mod add_credential;
pub mod add_item;
pub mod delete_credential;
pub mod delete_item;
pub mod delete_vault;
pub mod get_decrypted_credential;
pub mod get_vault;
pub mod new_vault;
pub mod schemas;
pub mod update_item;
pub mod update_vault;

pub fn with_unlocked_vault<F, R>(
    state: &tauri::State<'_, Mutex<AppState>>,
    vault_key: &str,
    f: F,
) -> Result<R, String>
where
    F: FnOnce(&mut VaultWrapper) -> Result<R, String>,
{
    let mut guard = state
        .lock()
        .map_err(|e| format!("Failed to lock app state: {e}"))?;

    let vw = guard
        .vaults
        .get_vault_mut(vault_key)
        .map_err(|e| format!("Failed to get vault: {e}"))?;

    vw.unlock().map_err(|e| match e {
        // Error::VaultLocked => "Vault is locked".to_string(),
        other => {
            log::debug!("Failed to unlock vault: {:?}", other);
            "Failed to unlock vault.".to_string()
        },
    })?;

    let result = f(vw)?;
    vw.save()
        .map_err(|e| format!("Failed to save vault: {e}"))?;
    Ok(result)
}
