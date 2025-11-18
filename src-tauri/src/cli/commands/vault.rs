use clap::{Parser, Subcommand};
use color_print::cprintln;

use crate::secrets::vaults_manager::VaultsManager;

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
}

impl VaultCommand {
    pub async fn execute(&self) {
        match &self.subcommand {
            VaultSubcommand::List => {
                self.cmd_list_vaults();
            },
        }
    }

    fn cmd_list_vaults(&self) {
        let vm = VaultsManager::new();
        for (vault_key, vw) in vm.iter_vaults() {
            let vault_name = vw.vault.name.as_deref().unwrap_or("<unnamed>");
            cprintln!("{vault_name} <dim>{vault_key}</dim>");
        }
    }
}
