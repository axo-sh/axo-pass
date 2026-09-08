//! Recording for `ap age encrypt` / `ap age decrypt`.
//!
//! The encryption itself is pure (see [`crate::age::crypto`]); the CLI resolves
//! keys through the app broker and calls these once per operation, with
//! `Source::Cli` and the resolved caller. Kept in core so the audit types and
//! their tests stay together.

use crate::age::errors::AgeError;
use crate::audit::{self, Action, AuditEvent, Outcome, Subject, SubjectKind};

fn outcome(result: &Result<(), AgeError>) -> Outcome {
    match result {
        Ok(()) => Outcome::Succeeded,
        Err(AgeError::Cancelled) => Outcome::Cancelled,
        Err(_) => Outcome::Failed,
    }
}

/// Record one `age.encrypt`. The recipients are named only by their count.
pub fn record_encrypt(
    recipient_count: usize,
    file_path: Option<&str>,
    result: &Result<(), AgeError>,
) {
    let mut event = AuditEvent::new(audit::process_source(), Action::AgeEncrypt, outcome(result))
        .detail("recipients", recipient_count.to_string());
    if let Some(path) = file_path {
        event = event.detail("file", path);
    }
    if let Err(e) = result {
        event = event.message(e.to_string());
    }
    audit::record(event);
}

/// Record one `age.decrypt`. `recipient` is the key name or `age1...` the user
/// passed.
pub fn record_decrypt(recipient: &str, file_path: Option<&str>, result: &Result<(), AgeError>) {
    let mut event = AuditEvent::new(audit::process_source(), Action::AgeDecrypt, outcome(result))
        .subject(Subject::new(SubjectKind::AgeIdentity, recipient));
    if let Some(path) = file_path {
        event = event.detail("file", path);
    }
    if let Err(e) = result {
        event = event.message(e.to_string());
    }
    audit::record(event);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::test_support::test_dir;
    use crate::audit::{AuditFilter, read};

    fn events(action: Action) -> Vec<crate::audit::AuditEvent> {
        read(&AuditFilter {
            actions: vec![action],
            ..Default::default()
        })
        .events
    }

    #[test]
    fn encrypt_records_a_succeeded_event() {
        let _t = test_dir();
        record_encrypt(2, Some("/tmp/x"), &Ok(()));

        let events = events(Action::AgeEncrypt);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, Outcome::Succeeded);
        assert_eq!(
            events[0].detail.get("recipients").map(String::as_str),
            Some("2")
        );
    }

    #[test]
    fn decrypt_records_a_cancelled_event() {
        let _t = test_dir();
        record_decrypt("demo", None, &Err(AgeError::Cancelled));

        let events = events(Action::AgeDecrypt);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, Outcome::Cancelled);
    }

    #[test]
    fn decrypt_records_a_failed_event() {
        let _t = test_dir();
        record_decrypt(
            "demo",
            None,
            &Err(AgeError::RecipientNotFound("demo".to_owned())),
        );

        let events = events(Action::AgeDecrypt);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, Outcome::Failed);
    }
}
