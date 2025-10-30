use tauri::Manager;

use crate::secrets::vault::{DEFAULT_VAULT, read_vault};

pub fn cmd_get_item(app_handle: tauri::AppHandle, get_item_url: String) -> Result<(), String> {
    let u =
        url::Url::parse(&get_item_url).map_err(|e| format!("Invalid URL '{get_item_url}': {e}"))?;
    if u.scheme() != "axo" {
        panic!("Unsupported URL scheme: {}", u.scheme())
    }
    let vault_name = u
        .host_str()
        .ok_or_else(|| format!("URL missing host: {}", get_item_url))?;
    let Ok(app_data_dir) = &app_handle.path().app_data_dir() else {
        return Err("Failed to get app data directory".to_string());
    };
    let mut vault = read_vault(app_data_dir, Some(vault_name)).expect("Failed to read vault");
    vault.unlock().expect("Failed to unlock vault");
    let res = vault
        .get_secret_by_url(u)
        .expect("Failed to get item by URL");
    println!("{}", res.unwrap_or_else(|| "<not found>".to_string()));
    Ok(())
}

pub fn cmd_list_items(app_handle: tauri::AppHandle) -> Result<(), String> {
    let Ok(app_data_dir) = &app_handle.path().app_data_dir() else {
        return Err("Failed to get app data directory".to_string());
    };

    let vault = read_vault(app_data_dir, None).expect("Failed to read vault");
    println!("Vault ID: {} (default vault)", vault.id);
    if vault.data.is_empty() {
        println!("No items found in vault.");
        return Ok(());
    }
    for (item_key, item_value) in vault.data.iter() {
        for (cred_key, _cred_value) in item_value.credentials.iter() {
            println!("axo://{}/{}/{}", DEFAULT_VAULT, item_key, cred_key);
        }
    }

    Ok(())
}
