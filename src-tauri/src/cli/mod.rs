pub mod commands;

use std::io::Write;

use clap::{Parser, Subcommand, command};
use color_print::cwriteln;
use log::LevelFilter;

use crate::cli::commands::age::AgeCommand;
use crate::cli::commands::inject::InjectCommand;
use crate::cli::commands::item::{ItemCommand, ItemReference};
use crate::cli::commands::keychain::KeychainCommand;
use crate::cli::commands::vault::VaultCommand;
use crate::core::build_sha;
use crate::core::dirs::vaults_dir;

#[derive(Parser, Debug)]
pub struct AxoPassCli {
    #[command(subcommand)]
    pub command: Option<AxoPassCommand>,
}

#[derive(Subcommand, Debug)]
pub enum AxoPassCommand {
    /// Commands for managing vaults
    Vault(VaultCommand),

    /// Commands for managing items and credentials
    Item(ItemCommand),

    /// Get a item credential's secret
    Read { item_reference: ItemReference },

    /// Inject secrets into a file
    Inject(InjectCommand),

    /// Commands for managing items stored in keychain
    Keychain(KeychainCommand),

    /// Commands for age encryption
    Age(AgeCommand),

    /// Show version and build
    Info,
}

impl AxoPassCommand {
    pub async fn execute(&self) {
        if std::env::var("FRITTATA_DEBUG").is_ok() || cfg!(debug_assertions) {
            env_logger::builder()
                .filter_level(LevelFilter::Debug)
                .format(|buf, record| cwriteln!(buf, "<dim>{}</dim>", record.args()))
                .init();
        }

        match self {
            AxoPassCommand::Keychain(keychain) => keychain.execute().await,
            AxoPassCommand::Vault(vault) => vault.execute().await,
            AxoPassCommand::Item(item) => item.execute().await,
            AxoPassCommand::Read { item_reference } => {
                ItemCommand::cmd_read(item_reference, None).unwrap();
            },
            AxoPassCommand::Inject(inject) => inject.execute().await,
            AxoPassCommand::Age(age) => age.execute().await,
            AxoPassCommand::Info => {
                println!("ap {}", env!("CARGO_PKG_VERSION"));
                println!("Built at: {}", build_sha::BUILT_AT.unwrap_or("not set"));
                println!("Build: {}", build_sha::BUILD_SHA.unwrap_or("not set"));
                println!("Vault dir: {}", vaults_dir().display());
            },
        }
    }
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
        Some(command) => command.execute().await,
        None => {
            eprintln!("No command provided. Use --help for usage information.");
            std::process::exit(1);
        },
    }
}
