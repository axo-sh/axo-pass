use std::str::FromStr;

use axo_pass_core::age::audit::{record_decrypt, record_encrypt};
use axo_pass_core::age::crypto::{age_decrypt, age_encrypt};
use axo_pass_core::age::errors::AgeError;
use axo_pass_core::core::app_broker::{self, BrokerError};
use axo_pass_core::core::provenance::Provenance;
use clap::{Parser, Subcommand};
use color_print::cprintln;
use secrecy::ExposeSecret;

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
    Recipients,

    /// Delete a recipient by name
    Delete { recipient: String },
}

/// Who asked, resolved from this process's parent chain. Delegated to the
/// broker the same way `ap ssh-askpass` and `ap read` do it.
fn caller() -> Option<String> {
    Provenance::resolve_current_parent().and_then(|provenance| provenance.caller())
}

fn map_broker(e: BrokerError) -> AgeError {
    match e {
        BrokerError::Unavailable => AgeError::BrokerUnavailable,
        BrokerError::Cancelled => AgeError::Cancelled,
        e => AgeError::Broker(e.to_string()),
    }
}

/// Unlock a named age key through the app, mapping a missing key back to
/// `RecipientNotFound` so the message does not degrade to a raw broker string.
fn request_identity(name: &str, caller: Option<&str>) -> Result<age::x25519::Identity, AgeError> {
    let secret = app_broker::request_age_identity(name, caller).map_err(|e| match e {
        BrokerError::Failed(m) if m.starts_with("No age key named") => {
            AgeError::RecipientNotFound(name.to_string())
        },
        e => map_broker(e),
    })?;
    age::x25519::Identity::from_str(secret.expose_secret())
        .map_err(|e| AgeError::FailedToParseIdentity(name.to_string(), e))
}

/// Resolve one `-r` value to an age recipient. A bare `age1...` parses locally;
/// a name is unlocked through the app.
fn resolve_recipient(
    value: &str,
    caller: Option<&str>,
) -> Result<age::x25519::Recipient, AgeError> {
    if value.starts_with("age1") {
        return value
            .parse::<age::x25519::Recipient>()
            .map_err(|e| AgeError::FailedToParseRecipient(value.to_string(), e));
    }
    Ok(request_identity(value, caller)?.to_public())
}

async fn run_encrypt(recipients: &[String], file_path: Option<&str>) -> Result<(), AgeError> {
    let caller = caller();
    let mut resolved = Vec::with_capacity(recipients.len());
    for r in recipients {
        resolved.push(resolve_recipient(r, caller.as_deref())?);
    }
    age_encrypt(&resolved, file_path).await
}

async fn run_decrypt(recipient: &str, file_path: Option<&str>) -> Result<(), AgeError> {
    if recipient.starts_with("age1") {
        return Err(AgeError::Broker(
            "Decrypt needs a key name, not a bare recipient. Use -r <name>.".to_string(),
        ));
    }
    let identity = request_identity(recipient, caller().as_deref())?;
    age_decrypt(&identity, file_path).await
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
                let result = run_decrypt(recipient, file_path.as_deref()).await;
                record_decrypt(recipient, file_path.as_deref(), &result);
                exit_on_err(result);
            },
            AgeSubcommand::Encrypt {
                recipient,
                file_path,
            } => {
                let result = run_encrypt(recipient, file_path.as_deref()).await;
                record_encrypt(recipient.len(), file_path.as_deref(), &result);
                exit_on_err(result);
            },
            AgeSubcommand::Keygen { name, show } => {
                let key = match app_broker::request_create_age_key(name, caller().as_deref()) {
                    Ok(key) => key,
                    Err(e) => {
                        log::error!("{}", map_broker(e));
                        std::process::exit(1);
                    },
                };
                cprintln!("<green>Recipient</green>: {}", key.recipient);
                if show.unwrap_or(false) {
                    match app_broker::request_age_identity(name, caller().as_deref()) {
                        Ok(secret) => println!("Secret: {}", secret.expose_secret()),
                        Err(e) => log::error!("Error reading back the generated secret: {e}"),
                    }
                }
            },
            AgeSubcommand::Recipients => match app_broker::request_age_keys(caller().as_deref()) {
                Ok(keys) if keys.is_empty() => println!("No age recipients found"),
                Ok(keys) => {
                    cprintln!("<green>Age recipients:</green>");
                    for key in keys {
                        cprintln!("  {} <dim>{}</dim>", key.name, key.recipient);
                    }
                },
                Err(e) => {
                    log::error!("{}", map_broker(e));
                    std::process::exit(1);
                },
            },
            AgeSubcommand::Delete { recipient } => {
                if let Err(e) = app_broker::request_delete_age_key(recipient, caller().as_deref()) {
                    log::error!("{}", map_broker(e));
                    std::process::exit(1);
                }
            },
        }
    }
}

fn exit_on_err(result: Result<(), AgeError>) {
    if let Err(err) = result {
        log::error!("{err}");
        std::process::exit(1);
    }
}
