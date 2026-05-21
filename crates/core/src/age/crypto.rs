use std::io::{self, Read};
use std::path::PathBuf;

use age::armor::Format;

use crate::age::errors::AgeError;
use crate::age::recipients::{resolve_identity, resolve_recipients};
use crate::core::read_input::read_file_or_stdin;

pub async fn age_encrypt(recipients: &[String], file_path: Option<&str>) -> Result<(), AgeError> {
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
