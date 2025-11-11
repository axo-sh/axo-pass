use std::os::unix::process::CommandExt;
use std::process::Command;

use clap::{Parser, Subcommand, command};
use frittata_lib::cli::commands::{keychain_generic_password, keychain_managed_keys};

#[derive(Parser, Debug)]
#[command(name = "ap")]
struct AxoPassCli {
    #[command(subcommand)]
    command: AxoPassCommand,
}

#[derive(Subcommand, Debug)]
enum AxoPassCommand {
    Keychain(Keychain),
    Pinentry,
    SshAskpass,
}

#[derive(Parser, Debug)]
pub struct Keychain {
    #[command(subcommand)]
    subcommand: KeychainSubcommand,
}

#[derive(Subcommand, Debug)]
enum KeychainSubcommand {
    ManagedKeys,
    GenericPassword,
}

#[tokio::main]
async fn main() {
    let cli = AxoPassCli::parse();
    match cli.command {
        AxoPassCommand::Pinentry => run_axo("pinentry"),
        AxoPassCommand::SshAskpass => run_axo("ssh-askpass"),
        AxoPassCommand::Keychain(keychain) => match keychain.subcommand {
            KeychainSubcommand::ManagedKeys => {
                keychain_managed_keys::cmd_list_managed_keys().await;
            },
            KeychainSubcommand::GenericPassword => {
                keychain_generic_password::cmd_list_generic_passwords().await;
            },
        },
    }
}

pub fn run_axo(arg: &str) {
    let Some(exe_path) = std::env::current_exe().ok() else {
        println!("Could not get path");
        return;
    };
    let Some(exe_dir) = exe_path.parent().map(|p| p.to_path_buf()) else {
        println!("exe path: {}", exe_path.display());
        return;
    };
    println!("dir: {}", exe_dir.display());
    let axo_pass = exe_dir.join("axo-pass");
    let err = Command::new(axo_pass).arg(arg).exec();
    // only reached if exec failed
    println!("Error executing pinentry: {}", err);
}
