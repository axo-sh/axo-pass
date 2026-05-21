use clap::{Parser, Subcommand};

pub mod generic_password;
pub mod managed_keys;

#[derive(Parser, Debug)]
#[command(flatten_help = true, help_template = "{usage-heading} {usage}")]
pub struct KeychainCommand {
    #[command(subcommand)]
    subcommand: KeychainSubcommand,
}

#[derive(Subcommand, Debug)]
enum KeychainSubcommand {
    /// List Secure Enclave managed keys
    ManagedKeys {
        #[command(subcommand)]
        action: Option<ManagedKeysAction>,
    },

    /// List Secure Enclave generic passwords
    GenericPassword,
}

#[derive(Subcommand, Debug)]
enum ManagedKeysAction {
    /// List all managed keys (default)
    List,

    /// Delete a managed key by label
    Delete { label: String },
}

impl KeychainCommand {
    pub async fn execute(&self) {
        match &self.subcommand {
            KeychainSubcommand::ManagedKeys { action } => match action {
                Some(ManagedKeysAction::List) | None => {
                    managed_keys::cmd_list_managed_keys().await;
                },
                Some(ManagedKeysAction::Delete { label }) => {
                    managed_keys::cmd_delete_managed_key(label).await;
                },
            },
            KeychainSubcommand::GenericPassword => {
                generic_password::cmd_list_generic_passwords().await;
            },
        }
    }
}
