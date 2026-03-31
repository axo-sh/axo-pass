use std::sync::Mutex;

use crate::app::AppState;
use crate::app::handlers::app_errors::{AppError, ErrorContext};
use crate::core::auth::check_auth_still_valid;
use crate::secrets::vaults::VaultWrapper;

pub mod add_or_update_credential;
pub mod add_or_update_item;
pub mod add_vault;
pub mod delete_credential;
pub mod delete_item;
pub mod delete_vault;
pub mod get_decrypted_credential;
pub mod get_vault;
pub mod schemas;
pub mod update_vault;

pub fn with_unlocked_vault<F, R>(
    state: &tauri::State<'_, Mutex<AppState>>,
    vault_key: &str,
    f: F,
) -> Result<R, AppError>
where
    F: FnOnce(&mut VaultWrapper) -> Result<R, AppError>,
{
    // check the LAContext is still valid
    check_auth_still_valid()?;

    // get the vault wrapper
    let mut guard = state.lock()?;
    let vw = guard
        .vaults
        .get_or_create_vault_mut(vault_key)
        .error_context("Failed to get vault")?;

    // unlock the vault
    vw.unlock()?;

    // run the provided function
    let result = f(vw)?;

    // save the vault
    vw.save().error_context("Failed to save vault")?;
    Ok(result)
}
