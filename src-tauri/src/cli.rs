pub mod cmd_generic_password;
mod cmd_item;
pub mod cmd_managed_keys;
use anyhow::bail;
use tauri::AppHandle;
use tauri_plugin_cli::SubcommandMatches;

pub fn get_optional_arg(
    subcommand: &SubcommandMatches,
    arg_name: &str,
) -> anyhow::Result<Option<String>> {
    let Some(arg) = subcommand.matches.args.get(arg_name).cloned() else {
        return Ok(None);
    };
    if arg.value.is_null() {
        return Ok(None);
    }
    let Some(value) = arg.value.as_str() else {
        bail!("Invalid argument type for {arg_name}: {:?}", arg.value);
    };
    Ok(Some(value.to_string()))
}

pub fn get_arg(subcommand: &SubcommandMatches, arg_name: &str) -> anyhow::Result<String> {
    get_optional_arg(subcommand, arg_name)?.ok_or_else(|| {
        log::debug!("subcommands: {:?}", subcommand.matches.args);
        anyhow::anyhow!("Missing required argument: {arg_name}")
    })
}

pub fn get_subcommand(subcommand: &SubcommandMatches) -> Option<SubcommandMatches> {
    subcommand
        .matches
        .subcommand
        .as_ref()
        .map(|s| (**s).clone())
}

pub fn run_cli_command(app_handle: AppHandle, subcommand: &SubcommandMatches, command: &str) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let res = rt.block_on(async {
        let h = app_handle.clone();
        match command {
            "get" => {
                let get_item_url = get_arg(subcommand, "item_url")?;
                cmd_item::cmd_get_item(h, get_item_url).map_err(|e| anyhow::anyhow!(e))?;
            },
            "items" => match get_subcommand(subcommand) {
                Some(ref sc) if sc.name == "list" => {
                    cmd_item::cmd_list_items(h).map_err(|e| anyhow::anyhow!(e))?;
                },
                Some(ref sc) if sc.name == "set" || sc.name == "add" => {
                    let vault_key = get_arg(sc, "vault_key")?;
                    let item_key = get_arg(sc, "item_key")?;
                    let credential_key = get_arg(sc, "credential_key")?;
                    let secret_value = get_optional_arg(sc, "secret_value")?.map(|s| s.into());
                    cmd_item::cmd_set_item(h, &vault_key, &item_key, &credential_key, secret_value)
                        .map_err(|e| anyhow::anyhow!(e))?;
                },
                _ => {
                    bail!("Unknown items subcommand");
                },
            },
            "managed-keys" => match get_subcommand(subcommand) {
                Some(ref sc) if sc.name == "list" => {
                    cmd_managed_keys::cmd_list_managed_keys().await;
                },
                _ => {
                    bail!("Unknown managed-keys subcommand");
                },
            },
            "generic-password" => match get_subcommand(subcommand) {
                Some(ref sc) if sc.name == "list" => {
                    cmd_generic_password::cmd_list_generic_passwords().await;
                },
                _ => {
                    bail!("Unknown generic-password subcommand");
                },
            },
            _ => {
                bail!("Unknown command: {}", command);
            },
        }
        Ok(())
    });

    match res {
        Ok(_) => {
            app_handle.exit(0);
        },
        Err(e) => {
            eprintln!("Error: {e}");
            app_handle.exit(1);
        },
    }
}
