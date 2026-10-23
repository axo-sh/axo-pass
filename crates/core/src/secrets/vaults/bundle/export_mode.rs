use std::io::Write;
use std::iter::once;

use age::armor::Format;
use secrecy::SecretString;

use crate::secrets::vaults::errors::Error;

/// Lowest scrypt log_n the export accepts. Below this a passphrase export is
/// weak against an offline attack on a human-chosen passphrase.
pub const MIN_WORK_FACTOR: u8 = 18;

/// Highest scrypt log_n the export accepts. A log_n of 24 needs about 16 GB of
/// memory.
pub const MAX_WORK_FACTOR: u8 = 24;

/// Highest scrypt log_n import will process. Set above [`MAX_WORK_FACTOR`] to
/// leave headroom for bundles written elsewhere, but bounded so a hostile file
/// cannot force an unbounded allocation.
#[cfg(not(test))]
pub const MAX_IMPORT_WORK_FACTOR: u8 = 25;
#[cfg(test)]
pub const MAX_IMPORT_WORK_FACTOR: u8 = 11;

/// Named scrypt work factors offered to the user, plus a numeric override.
///
/// scrypt memory is `N * 2r * 64` bytes, and age's default `r` is 8, so each
/// step up in `log_n` doubles both memory and time. Derivation time varies
/// widely with the machine, so only memory is quoted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum WorkFactor {
    /// log_n 19, about 512 MB.
    Fast,
    /// log_n 20, about 1 GB.
    Balanced,
    /// log_n 21, about 2 GB.
    #[default]
    Secure,
    /// log_n 23, about 8 GB.
    Paranoid,
    /// An explicit log_n, clamped to [`MIN_WORK_FACTOR`]..=[`MAX_WORK_FACTOR`].
    Custom(u8),
}

impl WorkFactor {
    /// The scrypt `log_n` for this setting. Under test every setting is capped
    /// low so the round-trip tests do not take minutes.
    pub fn log_n(self) -> u8 {
        let n = match self {
            WorkFactor::Fast => 19,
            WorkFactor::Balanced => 20,
            WorkFactor::Secure => 21,
            WorkFactor::Paranoid => 23,
            WorkFactor::Custom(n) => n.clamp(MIN_WORK_FACTOR, MAX_WORK_FACTOR),
        };
        #[cfg(test)]
        let n = n.min(10);
        n
    }

    /// Parse a preset name or a bare number.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_lowercase().as_str() {
            "fast" => Ok(WorkFactor::Fast),
            "balanced" => Ok(WorkFactor::Balanced),
            "secure" => Ok(WorkFactor::Secure),
            "paranoid" => Ok(WorkFactor::Paranoid),
            other => {
                let n: u8 = other
                    .parse()
                    .map_err(|_| format!("Unknown work factor '{s}'"))?;
                if !(MIN_WORK_FACTOR..=MAX_WORK_FACTOR).contains(&n) {
                    return Err(format!(
                        "Work factor {n} is out of range {MIN_WORK_FACTOR}..={MAX_WORK_FACTOR}"
                    ));
                }
                Ok(WorkFactor::Custom(n))
            },
        }
    }

    /// A short human note about the memory cost of this setting.
    pub fn cost_hint(self) -> &'static str {
        match self.log_n() {
            0..=19 => "about 512 MB of memory",
            20 => "about 1 GB of memory",
            21 => "about 2 GB of memory",
            22 => "about 4 GB of memory",
            23 => "about 8 GB of memory",
            _ => "16 GB of memory or more",
        }
    }
}

#[derive(Clone)]
pub enum ExportMode {
    /// Encrypt the file key with a passphrase (age scrypt).
    Passphrase {
        passphrase: SecretString,
        work_factor: WorkFactor,
    },

    /// Encrypt the file key to an age public key (age x25519).
    Recipient(String),
}

impl ExportMode {
    /// A passphrase export at the default work factor.
    pub fn passphrase(passphrase: impl Into<SecretString>) -> Self {
        ExportMode::Passphrase {
            passphrase: passphrase.into(),
            work_factor: WorkFactor::default(),
        }
    }

    /// Encrypt arbitrary bytes to an age recipient (passphrase or x25519) and
    /// return the ASCII-armored ciphertext.
    pub fn encrypt(&self, raw_key: &[u8]) -> Result<String, Error> {
        let recipient: Box<dyn age::Recipient> = match self {
            ExportMode::Passphrase {
                passphrase,
                work_factor,
            } => {
                let mut r = age::scrypt::Recipient::new(passphrase.clone());
                // https://words.filippo.io/the-scrypt-parameters/
                r.set_work_factor(work_factor.log_n());
                Box::new(r)
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
