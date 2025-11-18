pub mod commands;

use std::io::Write;

use clap::{Parser, Subcommand, command};
use color_print::cwriteln;
use log::LevelFilter;

use crate::cli::commands::inject::InjectCommand;
use crate::cli::commands::item::{ItemCommand, ItemReference};
use crate::cli::commands::keychain::KeychainCommand;
use crate::cli::commands::vault::VaultCommand;
use crate::core::build_sha;

#[derive(Parser, Debug)]
struct AxoPassCli {
    #[command(subcommand)]
    command: AxoPassCommand,
}

#[derive(Subcommand, Debug)]
enum AxoPassCommand {
    /// Commands for managing vaults
    Vault(VaultCommand),
    /// Commands for managing items and credentials
    Item(ItemCommand),
    /// Get a item credential's secret
    Read { item_reference: ItemReference },
    /// Inject secrets into a file
    Inject(InjectCommand),

    Keychain(KeychainCommand),
    Info,
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
        AxoPassCommand::Item(item) => item.execute().await,
        AxoPassCommand::Read { item_reference } => {
            ItemCommand::cmd_read(&item_reference, None).unwrap();
        },
        AxoPassCommand::Inject(inject) => inject.execute().await,
        AxoPassCommand::Info => {
            println!("Built at: {}", build_sha::BUILT_AT);
            println!("Build: {}", build_sha::BUILD_SHA);
        },
    }
}
