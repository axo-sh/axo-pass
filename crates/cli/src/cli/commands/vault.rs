mod export;
mod import;
mod parse_1password;
mod utils;

use std::path::PathBuf;

use axo_pass_core::core::app_broker;
use axo_pass_core::core::provenance::Provenance;
use axo_pass_core::secrets::vaults::VaultCatalog;
use clap::{Parser, Subcommand};
use clml::cprintln;

use crate::cli::commands::vault::export::VaultExportCommand;
use crate::cli::commands::vault::import::VaultImportCommand;
use crate::cli::commands::vault::parse_1password::VaultParse1passwordCommand;

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

    /// Export one or more vaults to a portable bundle file
    Export(VaultExportCommand),

    /// Import vaults from an export bundle
    Import(VaultImportCommand),

    /// Parse a 1Password .1pif export and print its contents
    OnePasswordImport(VaultParse1passwordCommand),
}

impl VaultCommand {
    pub async fn execute(&self) -> ! {
        match &self.subcommand {
            VaultSubcommand::List => self.cmd_list_vaults(),
            VaultSubcommand::Add { vault_path } => {
                if let Err(e) = self.cmd_add_vault(vault_path) {
                    cprintln!("<red>Error:</red> {e}");
                    std::process::exit(1);
                }
            },
            VaultSubcommand::Export(vault_export_cmd) => {
                if let Err(e) = vault_export_cmd.execute() {
                    cprintln!("<red>Error:</red> {e}");
                    std::process::exit(1);
                }
            },
            VaultSubcommand::Import(vault_import_cmd) => {
                if let Err(e) = vault_import_cmd.execute() {
                    cprintln!("<red>Error:</red> {e}");
                    std::process::exit(1);
                }
            },
            VaultSubcommand::OnePasswordImport(cmd) => {
                if let Err(e) = cmd.execute() {
                    cprintln!("<red>Error:</red> {e}");
                    std::process::exit(1);
                }
            },
        }
        std::process::exit(0);
    }

    fn cmd_list_vaults(&self) -> ! {
        let vaults = VaultCatalog::app().list();
        cprintln!("<green>Vaults:</green>");
        if vaults.is_empty() {
            println!("<no vaults>");
        }
        for (vault_key, vw) in &vaults {
            let vault_name = vw.vault_name().unwrap_or("<unnamed>");
            cprintln!("  <blue>{vault_name}</blue> {vault_key}");
        }
        std::process::exit(0);
    }

    /// Register an external vault through the app broker. `ap` holds no
    /// keychain entitlements, so the app unlocks the vault to validate it
    /// and writes the config entry. A build that is not staged in an app
    /// bundle has no broker to reach and fails.
    fn cmd_add_vault(&self, vault_path: &str) -> Result<(), String> {
        let path = PathBuf::from(vault_path)
            .canonicalize()
            .map_err(|e| format!("Could not resolve path {vault_path}: {e}"))?;
        let path_str = path.to_string_lossy().to_string();

        let caller = Provenance::resolve_current_parent().and_then(|p| p.caller());

        match app_broker::request_add_external_vault(&path_str, caller.as_deref()) {
            Ok(_) => {},
            Err(e) => return Err(format!("Failed to add vault: {e}")),
        }

        cprintln!("Added vault: <blue>{}</blue>", path.display());
        Ok(())
    }
}
