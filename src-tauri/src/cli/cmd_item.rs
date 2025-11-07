use std::io::{IsTerminal, Read};

use inquire::Password;
use secrecy::SecretString;
use tauri::Manager;

use crate::secrets::vault_wrapper::{DEFAULT_VAULT, VaultWrapper};

fn load_vault(
    app_handle: tauri::AppHandle,
    vault_name: Option<&str>,
) -> Result<VaultWrapper, String> {
    let Ok(app_data_dir) = app_handle.path().app_data_dir() else {
        return Err("Failed to get app data directory".to_string());
    };
    let vaults_dir = app_data_dir.join("vaults");
    let mut vw = VaultWrapper::load(&vaults_dir, Some(vault_name.unwrap_or(DEFAULT_VAULT)))
        .map_err(|e| format!("Failed to load vault: {e}"))?;
    vw.unlock()
        .map_err(|e| format!("Failed to unlock vault: {e}"))?;
    Ok(vw)
}

pub fn cmd_get_item(app_handle: tauri::AppHandle, get_item_url: String) -> Result<(), String> {
    let u =
        url::Url::parse(&get_item_url).map_err(|e| format!("Invalid URL '{get_item_url}': {e}"))?;
    if u.scheme() != "axo" {
        panic!("Unsupported URL scheme: {}", u.scheme())
    }
    let vault_name = u
        .host_str()
        .ok_or_else(|| format!("URL missing host: {}", get_item_url))?;

    let vw = load_vault(app_handle.clone(), Some(vault_name))?;
    let res = vw.get_secret_by_url(u).expect("Failed to get item by URL");
    println!("{}", res.unwrap_or_else(|| "<not found>".to_string()));
    Ok(())
}

pub fn cmd_list_items(app_handle: tauri::AppHandle) -> Result<(), String> {
    let vw = load_vault(app_handle.clone(), None)?;

    println!("Vault: {} (default vault)", vw.key);
    let items = vw.list_items();
    let mut has_items = false;
    for (item_key, item_value) in items {
        for (cred_key, _cred_value) in item_value.credentials.iter() {
            println!("axo://{}/{}/{}", DEFAULT_VAULT, item_key, cred_key);
        }
        has_items = true;
    }
    if !has_items {
        println!("<no items>");
    }

    Ok(())
}

pub fn cmd_set_item(
    app_handle: tauri::AppHandle,
    vault_key: &str,
    item_key: &str,
    credential_key: &str,
    secret_value: Option<SecretString>,
) -> Result<(), String> {
    let mut vw = load_vault(app_handle.clone(), Some(vault_key))?;

    let secret = match secret_value {
        Some(value) => value,
        None if std::io::stdin().is_terminal() => Password::new("Enter secret value:")
            .prompt()
            .map_err(|e| format!("Failed to read secret value: {e}"))?
            .trim()
            .into(),

        None => {
            let mut buffer = String::new();
            std::io::stdin()
                .read_to_string(&mut buffer)
                .map_err(|e| format!("Failed to read from stdin: {e}"))?;
            buffer.trim().to_string().into()
        },
    };

    vw.add_secret(
        item_key,
        Some(item_key),
        credential_key,
        credential_key,
        secret,
    )
    .expect("Failed to add secret");

    vw.save().expect("Failed to save vault");

    println!(
        "Added item: axo://{}/{}/{}",
        vault_key, item_key, credential_key
    );

    Ok(())
}
