use crate::age::errors::AgeError;
use crate::age::key_overview::AgeKeyOverview;
use crate::audit::{self, Action, Actor, AuditEvent, Outcome, Subject, SubjectKind};
use crate::secrets::keychain::generic_password::PasswordEntry;

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

pub fn delete_recipient(recipient: &str, actor: Option<Actor>) -> Result<(), AgeError> {
    let result = PasswordEntry::age(recipient)
        .delete()
        .map_err(|e| AgeError::FailedToDeleteRecipient(recipient.to_owned(), e));
    let error = result.as_ref().err().map(|e| e.to_string());
    record_key_event(Action::AgeKeyDelete, recipient, None, error, actor);
    result
}
