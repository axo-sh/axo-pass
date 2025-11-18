use clap::{Parser, Subcommand};

use crate::age::crypto::{age_decrypt, age_encrypt};
use crate::age::recipients::{age_keygen, delete_recipient, list_recipients};

#[derive(Parser, Debug)]
#[command(flatten_help = true, help_template = "{usage-heading} {usage}")]
pub struct AgeCommand {
    #[command(subcommand)]
    subcommand: AgeSubcommand,
}

#[derive(Subcommand, Debug)]
enum AgeSubcommand {
    /// Encrypt a file
    Encrypt {
        #[arg(short, long, required = true)]
        recipient: Vec<String>,
        file_path: Option<String>,
    },

    /// Decrypt a file
    Decrypt {
        #[arg(short, long, required = true)]
        recipient: Option<String>,
        file_path: Option<String>,
    },

    /// Generate a new recipient
    Keygen {
        /// name of the key to generate
        name: String,

        /// whether to show the generated secret
        show: Option<bool>,
    },

    /// List all saved recipients
    ListRecipients,

    /// Delete a recipient by name
    Delete { recipient: String },
}

impl AgeCommand {
    pub async fn execute(&self) {
        match &self.subcommand {
            AgeSubcommand::Decrypt {
                recipient,
                file_path,
            } => {
                let Some(recipient) = recipient else {
                    log::error!("Recipient is required for decryption");
                    std::process::exit(1);
                };
                if let Err(err) = age_decrypt(recipient, file_path.as_deref()).await {
                    log::error!("{err}");
                    std::process::exit(1);
                }
            },
            AgeSubcommand::Encrypt {
                recipient,
                file_path,
            } => {
                if let Err(err) = age_encrypt(recipient, file_path.as_deref()).await {
                    log::error!("{err}");
                    std::process::exit(1);
                }
            },
            AgeSubcommand::Keygen { name, show } => {
                age_keygen(name, show).await;
            },
            AgeSubcommand::ListRecipients => {
                list_recipients().await;
            },
            AgeSubcommand::Delete { recipient } => {
                if let Err(err) = delete_recipient(recipient) {
                    log::error!("{err}");
                    std::process::exit(1);
                }
            },
        }
    }
}
