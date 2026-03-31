use std::io::Write;
use std::iter::once;

use age::armor::Format;
use secrecy::SecretString;

use crate::secrets::vaults::errors::Error;

pub enum ExportMode {
    /// Encrypt the file key with a passphrase (age scrypt)
    Passphrase(SecretString),

    /// Encrypt the file key to an age public key (age x25519)
    Recipient(String),
}

impl ExportMode {
    pub fn wrap_file_key(&self, raw_key: &[u8]) -> Result<String, Error> {
        let recipient: Box<dyn age::Recipient> = match self {
            ExportMode::Passphrase(passphrase) => {
                Box::new(age::scrypt::Recipient::new(passphrase.clone()))
            },
            ExportMode::Recipient(pubkey) => {
                let r: age::x25519::Recipient = pubkey.parse().map_err(|e: &str| {
                    Error::VaultExportError(format!("Invalid age public key: {e}"))
                })?;
                Box::new(r)
            },
        };

        let encryptor = age::Encryptor::with_recipients(once(&*recipient))
            .map_err(|e| Error::VaultExportError(format!("Failed to create encryptor: {e}")))?;

        let mut output = Vec::new();
        let armor_writer = age::armor::ArmoredWriter::wrap_output(&mut output, Format::AsciiArmor)
            .map_err(|e| Error::VaultExportError(format!("Failed to create armor writer: {e}")))?;
        let mut writer = encryptor
            .wrap_output(armor_writer)
            .map_err(|e| Error::VaultExportError(format!("Failed to wrap output: {e}")))?;

        writer
            .write_all(raw_key)
            .map_err(|e| Error::VaultExportError(format!("Failed to write key data: {e}")))?;
        writer
            .finish()
            .and_then(|armor| armor.finish())
            .map_err(|e| Error::VaultExportError(format!("Failed to finalize encryption: {e}")))?;

        String::from_utf8(output)
            .map_err(|e| Error::VaultExportError(format!("Failed to encode armored output: {e}")))
    }
}
