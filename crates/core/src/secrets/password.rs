//! Random password generation.

use aes_gcm::aead::OsRng;
use aes_gcm::aead::rand_core::RngCore;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?";

pub const DEFAULT_LENGTH: usize = 20;
const MIN_LENGTH: usize = 4;
const MAX_LENGTH: usize = 256;

/// Fields left out of a serialized policy take their default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PasswordPolicy {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            length: DEFAULT_LENGTH,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PasswordError {
    #[error("password length must be between {MIN_LENGTH} and {MAX_LENGTH}")]
    InvalidLength,

    #[error("at least one character class must be enabled")]
    NoCharacterClasses,
}

impl PasswordPolicy {
    fn classes(&self) -> Vec<&'static [u8]> {
        [
            (self.lowercase, LOWER),
            (self.uppercase, UPPER),
            (self.digits, DIGITS),
            (self.symbols, SYMBOLS),
        ]
        .into_iter()
        .filter_map(|(enabled, set)| enabled.then_some(set))
        .collect()
    }

    /// Generate a password that contains at least one character from every
    /// enabled class.
    pub fn generate(&self) -> Result<SecretString, PasswordError> {
        if !(MIN_LENGTH..=MAX_LENGTH).contains(&self.length) {
            return Err(PasswordError::InvalidLength);
        }
        let classes = self.classes();
        if classes.is_empty() {
            return Err(PasswordError::NoCharacterClasses);
        }

        let pool: Vec<u8> = classes.iter().flat_map(|set| set.iter().copied()).collect();

        // One character from each class first, then the rest from the full
        // pool, then shuffle so the guaranteed characters are not up front.
        let mut chars: Vec<u8> = classes.iter().map(|set| pick(set)).collect();
        while chars.len() < self.length {
            chars.push(pick(&pool));
        }
        for i in (1..chars.len()).rev() {
            let j = below(i + 1);
            chars.swap(i, j);
        }

        // Every byte comes from an ASCII set.
        Ok(SecretString::from(
            String::from_utf8(chars).expect("ascii password"),
        ))
    }
}

fn pick(set: &[u8]) -> u8 {
    set[below(set.len())]
}

/// A uniform random integer in `0..n`, by rejection sampling.
fn below(n: usize) -> usize {
    debug_assert!(n > 0 && n <= u32::MAX as usize);
    let n = n as u32;
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let value = OsRng.next_u32();
        if value < zone {
            return (value % n) as usize;
        }
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn default_policy_makes_a_twenty_character_password() {
        let password = PasswordPolicy::default().generate().unwrap();
        assert_eq!(password.expose_secret().len(), DEFAULT_LENGTH);
    }

    #[test]
    fn every_enabled_class_is_present() {
        let policy = PasswordPolicy {
            length: 8,
            ..Default::default()
        };
        for _ in 0..200 {
            let password = policy.generate().unwrap();
            let password = password.expose_secret().as_bytes();
            for set in [LOWER, UPPER, DIGITS, SYMBOLS] {
                assert!(password.iter().any(|b| set.contains(b)));
            }
        }
    }

    #[test]
    fn disabled_classes_are_absent() {
        let policy = PasswordPolicy {
            length: 64,
            symbols: false,
            digits: false,
            uppercase: false,
            ..Default::default()
        };
        let password = policy.generate().unwrap();
        assert!(password.expose_secret().bytes().all(|b| LOWER.contains(&b)));
    }

    #[test]
    fn rejects_bad_policies() {
        let short = PasswordPolicy {
            length: 2,
            ..Default::default()
        };
        assert_eq!(short.generate().unwrap_err(), PasswordError::InvalidLength);

        let none = PasswordPolicy {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..Default::default()
        };
        assert_eq!(
            none.generate().unwrap_err(),
            PasswordError::NoCharacterClasses
        );
    }

    #[test]
    fn passwords_differ() {
        let policy = PasswordPolicy::default();
        let a = policy.generate().unwrap();
        let b = policy.generate().unwrap();
        assert_ne!(a.expose_secret(), b.expose_secret());
    }
}
