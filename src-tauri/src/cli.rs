mod cmd_generic_password;
mod cmd_item;
mod cmd_managed_keys;
use anyhow::bail;
use tauri::AppHandle;
use tauri_plugin_cli::SubcommandMatches;

pub fn get_arg(subcommand: &SubcommandMatches, arg_name: &str) -> anyhow::Result<String> {
    let Some(arg) = subcommand.matches.args.get(arg_name).cloned() else {
        bail!("Missing required argument: {arg_name}");
    };
    let Some(value) = arg.value.as_str() else {
        bail!("Invalid argument type for {arg_name}: {:?}", arg.value);
    };
    Ok(value.to_string())
}

pub fn get_subcommand(subcommand: &SubcommandMatches) -> Option<String> {
    subcommand
        .matches
        .subcommand
        .as_ref()
        .map(|sc| sc.name.clone())
}

pub fn run_cli_command(app_handle: AppHandle, subcommand: &SubcommandMatches, command: &str) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let res = rt.block_on(async {
        match command {
            "get" => {
                let get_item_url = get_arg(subcommand, "item_url")?;
                cmd_item::cmd_get_item(app_handle.clone(), get_item_url)
                    .map_err(|e| anyhow::anyhow!(e))?;
            },
            "items" => match get_subcommand(subcommand) {
                Some(ref sc) if sc == "list" => {
                    cmd_item::cmd_list_items(app_handle.clone()).map_err(|e| anyhow::anyhow!(e))?;
                },
                _ => {
                    bail!("Unknown items subcommand");
                },
            },
            "managed-keys" => match get_subcommand(subcommand) {
                Some(ref sc) if sc == "list" => {
                    cmd_managed_keys::cmd_list_managed_keys().await;
                },
                _ => {
                    bail!("Unknown managed-keys subcommand");
                },
            },
            "generic-password" => match get_subcommand(subcommand) {
                Some(ref sc) if sc == "list" => {
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
