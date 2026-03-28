use crate::app::handlers::app_errors::{AppError, ErrorContext};
use crate::secrets::keychain::generic_password::PasswordEntry;

#[cfg(debug_assertions)]
#[tauri::command]
pub async fn list_passwords() -> Result<Vec<PasswordEntry>, AppError> {
    use crate::secrets::keychain::generic_password::PasswordEntryType;
    // no keychain in debug mode because it's not codesigned
    let passwords = vec![
        PasswordEntry {
            password_type: PasswordEntryType::GPGKey,
            key_id: "test-key-1".to_string(),
        },
        PasswordEntry {
            password_type: PasswordEntryType::GPGKey,
            key_id: "test-key-2".to_string(),
        },
        PasswordEntry {
            password_type: PasswordEntryType::GPGKey,
            key_id: "test-key-3".to_string(),
        },
    ];
    Ok(passwords)
}

#[cfg(not(debug_assertions))]
#[tauri::command]
pub async fn list_passwords() -> Result<Vec<PasswordEntry>, AppError> {
    let passwords = PasswordEntry::list()?.error_context("Failed to list password entries.")?;
    Ok(passwords)
}

#[tauri::command]
pub async fn delete_password(entry: PasswordEntry) -> Result<(), AppError> {
    log::debug!("Deleting password entry: {:?}", entry);
    entry
        .delete()
        .error_context("Failed to delete password entry.")
}
