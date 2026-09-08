use std::str::FromStr;

use color_print::cprintln;
use secrecy::ExposeSecret;

use crate::age::errors::AgeError;
use crate::age::key_overview::AgeKeyOverview;
use crate::audit::{self, Action, Actor, AuditEvent, Outcome, Subject, SubjectKind};
use crate::secrets::keychain::generic_password::{PasswordEntry, PasswordEntryType};

/// Record an age key lifecycle event. `recipient` is the public half, safe to
/// log; the secret is never passed here. `actor` names the requester when the
/// event is served over the app broker in the app process; the app's own pane
/// passes `None`.
fn record_key_event(
    action: Action,
    name: &str,
    recipient: Option<&str>,
    error: Option<String>,
    actor: Option<Actor>,
) {
    let outcome = if error.is_some() {
        Outcome::Failed
    } else {
        Outcome::Succeeded
    };
    let mut subject = Subject::new(SubjectKind::AgeIdentity, name);
    if let Some(recipient) = recipient {
        subject = subject.label(recipient);
    }
    let mut event = AuditEvent::new(audit::process_source(), action, outcome)
        .subject(subject)
        .maybe_actor(actor);
    if let Some(error) = error {
        event = event.message(error);
    }
    audit::record(event);
}

/// Generate a new x25519 identity, save it to the keychain under `name`, and
/// record an `age.key_create` audit event. Errors if a key of that name exists.
pub fn generate_age_key(name: &str, actor: Option<Actor>) -> Result<AgeKeyOverview, AgeError> {
    let entry = PasswordEntry::age(name);
    let exists = entry
        .exists()
        .map_err(|e| AgeError::FailedToRetrieveRecipient(name.to_owned(), e))?;
    if exists {
        let err = AgeError::KeyAlreadyExists(name.to_owned());
        record_key_event(
            Action::AgeKeyCreate,
            name,
            None,
            Some(err.to_string()),
            actor,
        );
        return Err(err);
    }

    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public().to_string();
    let identity_str = identity.to_string();

    match entry.save_password(identity_str) {
        Ok(()) => {
            record_key_event(Action::AgeKeyCreate, name, Some(&recipient), None, actor);
            Ok(AgeKeyOverview {
                name: name.to_owned(),
                recipient,
            })
        },
        Err(e) => {
            let err = AgeError::FailedToSaveKey(name.to_owned(), e);
            record_key_event(
                Action::AgeKeyCreate,
                name,
                None,
                Some(err.to_string()),
                actor,
            );
            Err(err)
        },
    }
}

pub async fn age_keygen(name: &str, show: &Option<bool>) {
    let overview = match generate_age_key(name, None) {
        Ok(overview) => overview,
        Err(e) => {
            eprintln!("Error saving key to keychain: {e}");
            std::process::exit(1);
        },
    };
    cprintln!("<green>Recipient</green>: {}", overview.recipient);
    if show.unwrap_or(false) {
        match PasswordEntry::age(name).get_password() {
            Ok(Some(secret)) => println!("Secret: {}", secret.expose_secret()),
            _ => eprintln!("Error reading back the generated secret"),
        }
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

pub fn delete_recipient(recipient: &str, actor: Option<Actor>) -> Result<(), AgeError> {
    let result = PasswordEntry::age(recipient)
        .delete()
        .map_err(|e| AgeError::FailedToDeleteRecipient(recipient.to_owned(), e));
    let error = result.as_ref().err().map(|e| e.to_string());
    record_key_event(Action::AgeKeyDelete, recipient, None, error, actor);
    result
}

pub fn resolve_recipient(recipient: &str) -> Result<age::x25519::Recipient, AgeError> {
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
