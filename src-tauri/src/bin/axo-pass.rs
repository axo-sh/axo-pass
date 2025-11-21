// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use clap::builder::styling;
use clap::{Parser, Subcommand};
use frittata_lib::app::AxoAppCommand;
use frittata_lib::cli::AxoPassCommand;

const STYLES: styling::Styles = styling::Styles::styled()
    .header(styling::AnsiColor::Green.on_default().bold())
    .usage(styling::AnsiColor::Green.on_default().bold())
    .literal(styling::AnsiColor::Blue.on_default().bold())
    .placeholder(styling::AnsiColor::Cyan.on_default());

#[derive(Parser, Debug)]
#[command(
    name = "Axo Pass",
    bin_name = "ap",
    version = env!("CARGO_PKG_VERSION"),
    styles = STYLES,
)]
pub struct AxoPass {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    #[command(flatten)]
    Cli(AxoPassCommand),

    #[command(flatten)]
    App(AxoAppCommand),
}

impl AxoPass {
    fn execute(&self) {
        match &self.command {
            Some(Command::Cli(cmd)) => tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    cmd.execute().await;
                }),
            Some(Command::App(cmd)) => {
                frittata_lib::app::run(Some(cmd.clone()));
            },
            None => {
                frittata_lib::app::run(None);
            },
        }
    }
}

fn main() {
    AxoPass::parse().execute();
}
