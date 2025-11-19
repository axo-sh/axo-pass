// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use clap::{Parser, Subcommand};
use frittata_lib::app::AxoAppCommand;
use frittata_lib::cli::AxoPassCommand;

#[derive(Parser, Debug)]
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
