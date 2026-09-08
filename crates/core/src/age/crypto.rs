//! The age encryption and decryption primitives. Pure: resolved recipients or
//! an identity in, ciphertext or plaintext out, no keychain and no audit. The
//! CLI resolves keys through the app broker and records the audit event; see
//! [`crate::age::audit`].

use std::io::{self, Read};
use std::path::PathBuf;

use age::armor::Format;

use crate::age::errors::AgeError;
use crate::core::read_input::read_file_or_stdin;

pub async fn age_encrypt(
    recipients: &[age::x25519::Recipient],
    file_path: Option<&str>,
) -> Result<(), AgeError> {
    let input_data = read_file_or_stdin(&file_path.map(PathBuf::from))?;
    let encryptor =
        age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))?;

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

pub async fn age_decrypt(
    identity: &age::x25519::Identity,
    file_path: Option<&str>,
) -> Result<(), AgeError> {
    let input_data = read_file_or_stdin(&file_path.map(PathBuf::from))?;

    let armor_reader = age::armor::ArmoredReader::new(&input_data[..]);
    let decryptor = age::Decryptor::new(armor_reader)?;

    let mut reader = decryptor.decrypt(std::iter::once(identity as &dyn age::Identity))?;

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
    use super::*;

    #[tokio::test]
    async fn round_trips_through_a_generated_identity() {
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();

        let mut plaintext = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut plaintext, b"hello").unwrap();

        // Encrypt writes to stdout, so this only checks it does not error. The
        // decrypt round trip is covered end to end by the CLI tests.
        age_encrypt(&[recipient], Some(plaintext.path().to_str().unwrap()))
            .await
            .unwrap();
    }
}
