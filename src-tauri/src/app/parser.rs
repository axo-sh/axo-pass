use anyhow::bail;
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
