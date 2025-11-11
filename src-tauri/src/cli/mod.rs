pub mod commands;

use std::io::Write;

use clap::{Parser, Subcommand, command};
use color_print::cwriteln;
use log::LevelFilter;

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
    if std::env::var("FRITTATA_DEBUG").is_ok() || cfg!(debug_assertions) {
        env_logger::builder()
            .filter_level(LevelFilter::Debug)
            .format(|buf, record| cwriteln!(buf, "<dim>{}</dim>", record.args()))
            .init();
    }

    let cli = AxoPassCli::parse();
    match cli.command {
        AxoPassCommand::Keychain(keychain) => keychain.execute().await,
        AxoPassCommand::Vault(vault) => vault.execute().await,
    }
}
