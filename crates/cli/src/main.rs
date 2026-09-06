// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use axo_pass_cli::cli::AxoPassCommand;
use clap::Parser;
use clap::builder::styling;

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
    arg_required_else_help = true,
)]
pub struct AxoPass {
    #[command(subcommand)]
    command: Option<AxoPassCommand>,
}

impl AxoPass {
    fn execute(&self) {
        if let Some(cmd) = &self.command {
            cmd.execute();
        }
    }
}

fn main() {
    axo_pass_core::audit::set_process_source(axo_pass_core::audit::Source::Cli);
    AxoPass::parse().execute();
}
