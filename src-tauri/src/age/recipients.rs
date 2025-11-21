use std::str::FromStr;

use color_print::cprintln;
use secrecy::ExposeSecret;

use crate::age::errors::AgeError;
use crate::secrets::keychain::generic_password::{PasswordEntry, PasswordEntryType};

pub async fn age_keygen(name: &str, show: &Option<bool>) {
    let identity = age::x25519::Identity::generate();
    let identity_str = identity.to_string();
    let password_entry = PasswordEntry::age(name);
    if let Err(e) = password_entry.save_password(identity_str.clone()) {
        eprintln!("Error saving key to keychain: {e}");
        std::process::exit(1);
    }
    cprintln!("<green>Recipient</green>: {}", identity.to_public());
    if show.unwrap_or(false) {
        println!("<green>Secret</green>: {}", identity_str.expose_secret());
    }
}

pub async fn list_recipients() {
    match PasswordEntry::list() {
        Ok(entries) => {
            let age_entries: Vec<_> = entries
                .into_iter()
                .filter(|e| matches!(e.password_type, PasswordEntryType::AgeKey))
                .collect();

            if age_entries.is_empty() {
                println!("No age recipients found in keychain");
            } else {
                cprintln!("<green>Age recipients:</green>");
                for entry in age_entries {
                    let entry_name = entry.key_id.clone();
                    match entry.get_password() {
                        Err(err) => {
                            cprintln!("  {entry_name}: <red>{err}</red>");
                        },
                        Ok(None) => {
                            cprintln!("  {entry_name}: <red>not found</red>");
                        },
                        Ok(Some(pwd)) => {
                            match age::x25519::Identity::from_str(pwd.expose_secret()) {
                                Ok(identity) => {
                                    cprintln!(
                                        "  {} <dim>{}</dim>",
                                        entry.key_id,
                                        identity.to_public().to_string()
                                    );
                                },
                                Err(err) => {
                                    cprintln!("  {entry_name}: <red>{err}</red>");
                                },
                            }
                        },
                    }
                }
            }
        },
        Err(e) => {
            eprintln!("Error listing recipients: {e}");
            std::process::exit(1);
        },
    }
}

pub fn delete_recipient(recipient: &str) -> Result<(), AgeError> {
    PasswordEntry::age(recipient)
        .delete()
        .map_err(|e| AgeError::FailedToDeleteRecipient(recipient.to_owned(), e))
}

fn resolve_recipient(recipient: &str) -> Result<age::x25519::Recipient, AgeError> {
    let recipient = recipient.to_owned();
    if recipient.starts_with("age1") {
        recipient
            .parse::<age::x25519::Recipient>()
            .map_err(|e| AgeError::FailedToParseRecipient(recipient, e))
    } else {
        let password_entry = PasswordEntry::age(&recipient);
        match password_entry.get_password() {
            Ok(Some(pwd)) => match age::x25519::Identity::from_str(pwd.expose_secret()) {
                Ok(identity) => Ok(identity.to_public()),
                Err(e) => Err(AgeError::FailedToParseIdentity(recipient, e)),
            },
            Ok(None) => Err(AgeError::RecipientNotFound(recipient)),
            Err(e) => Err(AgeError::FailedToRetrieveRecipient(recipient, e)),
        }
    }
}

pub fn resolve_recipients(
    recipients: &[String],
) -> Result<Vec<Box<dyn age::Recipient + '_>>, AgeError> {
    let mut age_recipients: Vec<Box<dyn age::Recipient>> = Vec::new();
    for recipient in recipients {
        let recipient = resolve_recipient(recipient)?;
        age_recipients.push(Box::new(recipient));
    }
    Ok(age_recipients)
}

pub fn resolve_identity(recipient: &str) -> Result<age::x25519::Identity, AgeError> {
    let recipient = recipient.to_owned();
    if recipient.starts_with("age1") {
        for entry in PasswordEntry::list()
            .map_err(|e| AgeError::FailedToRetrieveRecipient(recipient.clone(), e))?
            .into_iter()
            .filter(|e| matches!(e.password_type, PasswordEntryType::AgeKey))
        {
            if let Ok(Some(pwd)) = entry.get_password()
                && let Ok(identity) = age::x25519::Identity::from_str(pwd.expose_secret())
                && identity.to_public().to_string() == recipient
            {
                return Ok(identity);
            }
        }
        Err(AgeError::RecipientNotFound(recipient))
    } else {
        let password_entry = PasswordEntry::age(&recipient);
        match password_entry.get_password() {
            Ok(Some(pwd)) => match age::x25519::Identity::from_str(pwd.expose_secret()) {
                Ok(identity) => Ok(identity),
                Err(e) => Err(AgeError::FailedToParseIdentity(recipient, e)),
            },
            Ok(None) => Err(AgeError::RecipientNotFound(recipient)),
            Err(e) => Err(AgeError::FailedToRetrieveRecipient(recipient, e)),
        }
    }
}
