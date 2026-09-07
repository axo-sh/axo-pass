use std::io::{self, Read};
use std::path::PathBuf;

use age::armor::Format;

use crate::age::errors::AgeError;
use crate::age::recipients::{resolve_identity, resolve_recipients};
use crate::audit::{self, Action, AuditEvent, Outcome, Subject, SubjectKind};
use crate::core::read_input::read_file_or_stdin;

pub async fn age_encrypt(recipients: &[String], file_path: Option<&str>) -> Result<(), AgeError> {
    let result = age_encrypt_inner(recipients, file_path).await;

    let outcome = match &result {
        Ok(()) => Outcome::Succeeded,
        Err(_) => Outcome::Failed,
    };
    let mut event = AuditEvent::new(audit::process_source(), Action::AgeEncrypt, outcome)
        .detail("recipients", recipients.len().to_string());
    if let Some(path) = file_path {
        event = event.detail("file", path);
    }
    if let Err(e) = &result {
        event = event.message(e.to_string());
    }
    audit::record(event);

    result
}

async fn age_encrypt_inner(recipients: &[String], file_path: Option<&str>) -> Result<(), AgeError> {
    let age_recipients = resolve_recipients(recipients)?;
    let input_data = read_file_or_stdin(&file_path.map(PathBuf::from))?;
    let encryptor = age::Encryptor::with_recipients(age_recipients.iter().map(|r| r.as_ref()))?;

    let mut stdout = io::stdout();
    let armor_writer = age::armor::ArmoredWriter::wrap_output(&mut stdout, Format::AsciiArmor)
        .map_err(AgeError::WriteError)?;
    let mut writer = encryptor
        .wrap_output(armor_writer)
        .map_err(AgeError::WriteError)?;

    io::Write::write_all(&mut writer, &input_data).map_err(AgeError::WriteError)?;
    writer
        .finish()
        .and_then(|armor| armor.finish())
        .map_err(AgeError::WriteError)?;

    Ok(())
}

pub async fn age_decrypt(recipient: &str, file_path: Option<&str>) -> Result<(), AgeError> {
    let result = age_decrypt_inner(recipient, file_path).await;

    let outcome = match &result {
        Ok(()) => Outcome::Succeeded,
        Err(_) => Outcome::Failed,
    };
    let mut event = AuditEvent::new(audit::process_source(), Action::AgeDecrypt, outcome)
        .subject(Subject::new(SubjectKind::AgeIdentity, recipient));
    if let Some(path) = file_path {
        event = event.detail("file", path);
    }
    if let Err(e) = &result {
        event = event.message(e.to_string());
    }
    audit::record(event);

    result
}

async fn age_decrypt_inner(recipient: &str, file_path: Option<&str>) -> Result<(), AgeError> {
    let age_identity = resolve_identity(recipient)?;
    let input_data = read_file_or_stdin(&file_path.map(PathBuf::from))?;

    let armor_reader = age::armor::ArmoredReader::new(&input_data[..]);
    let decryptor = age::Decryptor::new(armor_reader)?;

    let mut reader = decryptor.decrypt(std::iter::once(&age_identity as &dyn age::Identity))?;

    let mut output = Vec::new();
    reader
        .read_to_end(&mut output)
        .map_err(AgeError::WriteError)?;

    let mut stdout = io::stdout();
    io::Write::write_all(&mut stdout, &output).map_err(AgeError::WriteError)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

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

    #[tokio::test]
    async fn encrypt_records_a_succeeded_event() {
        let _t = test_dir();
        let recipient = age::x25519::Identity::generate().to_public().to_string();

        let mut input = tempfile::NamedTempFile::new().unwrap();
        input.write_all(b"hello").unwrap();
        let path = input.path().to_str().unwrap().to_owned();

        age_encrypt(&[recipient], Some(&path)).await.unwrap();

        let events = events(Action::AgeEncrypt);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, Outcome::Succeeded);
        assert_eq!(
            events[0].detail.get("recipients").map(String::as_str),
            Some("1")
        );
    }

    #[tokio::test]
    async fn encrypt_records_a_failed_event_for_a_bad_recipient() {
        let _t = test_dir();
        let result = age_encrypt(&["age1notarealrecipient".to_owned()], None).await;
        assert!(result.is_err());

        let events = events(Action::AgeEncrypt);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, Outcome::Failed);
    }
}
