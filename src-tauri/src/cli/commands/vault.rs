use std::path::PathBuf;

use clap::{Parser, Subcommand};
use color_print::cprintln;

use crate::core::config::APP_CONFIG;
use crate::secrets::vaults::{VaultWrapper, VaultsManager};

#[derive(Parser, Debug)]
#[command(flatten_help = true, help_template = "{usage-heading} {usage}")]
pub struct VaultCommand {
    #[command(subcommand)]
    subcommand: VaultSubcommand,
}

#[derive(Subcommand, Debug)]
enum VaultSubcommand {
    /// List vaults
    List,

    /// Add an external vault by path
    Add { vault_path: String },
}

impl VaultCommand {
    pub async fn execute(&self) {
        match &self.subcommand {
            VaultSubcommand::List => self.cmd_list_vaults(),
            VaultSubcommand::Add { vault_path } => {
                if let Err(e) = self.cmd_add_vault(vault_path) {
                    cprintln!("<red>Error:</red> {e}");
                    std::process::exit(1);
                }
            },
        }
    }

    fn cmd_list_vaults(&self) {
        let vm = VaultsManager::new();
        cprintln!("<green>Vaults:</green>");
        if vm.iter_vault_keys().next().is_none() {
            println!("<no vaults>");
            return;
        }
        for (vault_key, vw) in vm.iter_vaults() {
            let vault_name = vw.vault.name.as_deref().unwrap_or("<unnamed>");
            cprintln!("  <blue>{vault_name}</blue> {vault_key}");
        }
    }

    fn cmd_add_vault(&self, vault_path: &str) -> Result<(), String> {
        let path = PathBuf::from(vault_path)
            .canonicalize()
            .map_err(|e| format!("Could not resolve path {vault_path}: {e}"))?;

        // Validate the vault file before adding it to the config: must be a valid vault
        // file and must be unlockable.
        let vw = match VaultWrapper::load_from_path(None, &path) {
            Ok(mut vw) => {
                vw.unlock()
                    .map_err(|e| format!("Failed to unlock vault: {e}"))?;
                vw
            },
            Err(e) => Err(format!("Not a valid vault file: {e}"))?,
        };

        let mut app_config = APP_CONFIG
            .lock()
            .map_err(|e| format!("Failed to unlock config: {e}"))?;

        app_config
            .add_external_vault(&vw.key, path.clone())
            .map_err(|e| format!("Failed to add vault: {e}"))?;

        cprintln!("Added vault: <blue>{}</blue>", path.display());
        Ok(())
    }
}
