use crate::secrets::keychain::generic_password::PasswordEntry;

#[cfg(debug_assertions)]
#[tauri::command]
pub async fn list_passwords() -> Result<Vec<PasswordEntry>, String> {
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
pub async fn list_passwords() -> Result<Vec<PasswordEntry>, String> {
    let passwords = PasswordEntry::list().map_err(|e| format!("Failed to list passwords: {e}"))?;
    Ok(passwords)
}

#[tauri::command]
pub async fn delete_password(entry: PasswordEntry) -> Result<(), String> {
    log::debug!("Deleting password entry: {:?}", entry);
    entry
        .delete()
        .map_err(|e| format!("Failed to delete password entry: {e}"))
}
