use std::io::Read;
use std::iter::once;

use secrecy::SecretString;

use crate::secrets::vaults::errors::Error;

pub enum ImportIdentity {
    Passphrase(SecretString),

    /// age secret key in armored format (age x25519 identity)
    Identity(age::x25519::Identity),
}

impl ImportIdentity {
    pub fn unwrap_file_key(&self, age_ciphertext: &str) -> Result<Vec<u8>, Error> {
        let identity: Box<dyn age::Identity> = match self {
            ImportIdentity::Passphrase(passphrase) => {
                Box::new(age::scrypt::Identity::new(passphrase.clone()))
            },
            ImportIdentity::Identity(identity) => Box::new(identity.clone()),
        };

        let armor_reader = age::armor::ArmoredReader::new(age_ciphertext.as_bytes());
        let decryptor = age::Decryptor::new(armor_reader)
            .map_err(|e| Error::VaultImportError(format!("Failed to read export file: {e}")))?;
        let mut reader = decryptor
            .decrypt(once(&*identity))
            .map_err(|e| Error::VaultImportError(format!("Failed to decrypt file key: {e}")))?;

        let mut raw_key = Vec::new();
        reader
            .read_to_end(&mut raw_key)
            .map_err(|e| Error::VaultImportError(format!("Failed to read decrypted key: {e}")))?;
        if raw_key.len() != 32 {
            return Err(Error::VaultImportError(format!(
                "Invalid file key length: expected 32 bytes, got {}",
                raw_key.len()
            )));
        }
        Ok(raw_key)
    }
}
