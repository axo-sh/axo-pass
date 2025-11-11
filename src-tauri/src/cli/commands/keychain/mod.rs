use clap::{Parser, Subcommand};

pub mod generic_password;
pub mod managed_keys;

#[derive(Parser, Debug)]
pub struct KeychainCommand {
    #[command(subcommand)]
    subcommand: KeychainSubcommand,
}

#[derive(Subcommand, Debug)]
enum KeychainSubcommand {
    ManagedKeys,
    GenericPassword,
}

impl KeychainCommand {
    pub async fn execute(&self) {
        match &self.subcommand {
            KeychainSubcommand::ManagedKeys => {
                managed_keys::cmd_list_managed_keys().await;
            },
            KeychainSubcommand::GenericPassword => {
                generic_password::cmd_list_generic_passwords().await;
            },
        }
    }
}
