pub mod commands;

use clap::{Parser, Subcommand, command};

use crate::cli::commands::keychain::KeychainCommand;
use crate::cli::commands::vault::VaultCommand;

#[derive(Parser, Debug)]
struct AxoPassCli {
    #[command(subcommand)]
    command: AxoPassCommand,
}

#[derive(Subcommand, Debug)]
enum AxoPassCommand {
    Keychain(KeychainCommand),
    Vault(VaultCommand),
}

pub async fn run() {
    let cli = AxoPassCli::parse();
    match cli.command {
        AxoPassCommand::Keychain(keychain) => keychain.execute().await,
        AxoPassCommand::Vault(vault) => vault.execute().await,
    }
}
