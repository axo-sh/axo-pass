//! Crockford base32, the shown form of the pairing code and the printed form
//! of the key fingerprint.
//!
//! The alphabet is `0123456789ABCDEFGHJKMNPQRSTVWXYZ`. Output is uppercase
//! with no padding. Input is read case-insensitively. Hyphens and spaces are
//! dropped. `O` reads as `0`, and `I` and `L` read as `1`.

use ::base32::Alphabet;

/// Crockford base32 encoding and decoding.
pub struct Crockford;

impl Crockford {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    /// Crockford base32 of `bytes`, uppercase, with no padding.
    pub fn encode(bytes: &[u8]) -> String {
        ::base32::encode(Alphabet::Crockford, bytes)
    }

    /// Crockford base32 of `bytes` in groups of `group` characters, joined by
    /// hyphens. The last group can be shorter.
    pub fn encode_grouped(bytes: &[u8], group: usize) -> String {
        let text = Self::encode(bytes);
        text.as_bytes()
            .chunks(group)
            .map(|chunk| str::from_utf8(chunk).expect("base32 output is ASCII"))
            .collect::<Vec<_>>()
            .join("-")
    }

    /// Bytes of the Crockford base32 text `text`. Fails if a character other
    /// than a hyphen or a space is outside the alphabet and its read forms.
    pub fn decode(text: &str) -> Option<Vec<u8>> {
        let normalized = text
            .chars()
            .filter(|c| !matches!(c, '-' | ' '))
            .map(Self::normalize)
            .collect::<Option<String>>()?;
        ::base32::decode(Alphabet::Crockford, &normalized)
    }

    /// Alphabet character that `c` reads as.
    fn normalize(c: char) -> Option<char> {
        let c = match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        };
        (c.is_ascii() && Self::ALPHABET.contains(&(c as u8))).then_some(c)
    }
}
