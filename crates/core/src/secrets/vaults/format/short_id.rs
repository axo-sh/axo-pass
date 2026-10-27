//! Short text form of vault ids.
//!
//! A short id is a UUID written as a flickrBase58 number of 22 characters,
//! padded on the left with `1`. It matches the default output of the
//! JavaScript `short-uuid` package. Reading also accepts the 32 and 36
//! character hex forms. Blob AADs use the hyphenated form, not this one.

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{DeserializeAs, SerializeAs};
use uuid::Uuid;

/// flickrBase58 digits in value order.
const ALPHABET: &[u8; 58] = b"123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";

/// Length of every encoded id. 58^22 is above 2^128.
pub const SHORT_ID_LEN: usize = 22;

/// Text that is not a short id or a 32 or 36 character hex UUID.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid id {0:?}")]
pub struct ParseShortIdError(String);

/// UUID read and written in the short form.
///
/// Also a `serde_with` adapter for `Uuid` fields, as in
/// `#[serde_as(as = "ShortId")]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShortId(Uuid);

impl ShortId {
    pub fn new(id: Uuid) -> Self {
        Self(id)
    }

    pub fn uuid(self) -> Uuid {
        self.0
    }

    /// Short form of this id.
    pub fn encode(self) -> String {
        let mut value = self.0.as_u128();
        let mut digits = [ALPHABET[0]; SHORT_ID_LEN];
        for digit in digits.iter_mut().rev() {
            *digit = ALPHABET[(value % 58) as usize];
            value /= 58;
        }
        digits.iter().map(|&b| b as char).collect()
    }

    /// Short form of `id`.
    pub fn encode_uuid(id: Uuid) -> String {
        Self(id).encode()
    }

    /// Read a short id, or a 32 or 36 character hex UUID in either letter
    /// case. Any other text is refused.
    pub fn decode(text: &str) -> Result<Self, ParseShortIdError> {
        let invalid = || ParseShortIdError(text.to_string());
        match text.len() {
            SHORT_ID_LEN => Self::decode_base58(text).ok_or_else(invalid),
            32 | 36 => Uuid::try_parse(text).map(Self).map_err(|_| invalid()),
            _ => Err(invalid()),
        }
    }

    /// Read `text` with [`Self::decode`] and return the UUID.
    pub fn parse_uuid(text: &str) -> Result<Uuid, ParseShortIdError> {
        Self::decode(text).map(Self::uuid)
    }

    /// Short form of `id` in lower case. Two ids with one folded form name
    /// one file on a file system that ignores case.
    pub fn folded(id: Uuid) -> String {
        Self::encode_uuid(id).to_ascii_lowercase()
    }

    /// Value of a 22 digit flickrBase58 number. `None` for a digit outside the
    /// alphabet or a value above 128 bits.
    fn decode_base58(text: &str) -> Option<Self> {
        let mut value: u128 = 0;
        for byte in text.bytes() {
            let digit = ALPHABET.iter().position(|&b| b == byte)? as u128;
            value = value.checked_mul(58)?.checked_add(digit)?;
        }
        Some(Self(Uuid::from_u128(value)))
    }
}

impl From<Uuid> for ShortId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<ShortId> for Uuid {
    fn from(id: ShortId) -> Self {
        id.0
    }
}

impl fmt::Display for ShortId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encode())
    }
}

impl FromStr for ShortId {
    type Err = ParseShortIdError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::decode(text)
    }
}

impl Serialize for ShortId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.encode())
    }
}

impl<'de> Deserialize<'de> for ShortId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ShortIdVisitor;

        impl Visitor<'_> for ShortIdVisitor {
            type Value = ShortId;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a short id or a hex UUID")
            }

            fn visit_str<E: de::Error>(self, text: &str) -> Result<ShortId, E> {
                ShortId::decode(text).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(ShortIdVisitor)
    }
}

impl SerializeAs<Uuid> for ShortId {
    fn serialize_as<S: Serializer>(id: &Uuid, serializer: S) -> Result<S::Ok, S::Error> {
        Self(*id).serialize(serializer)
    }
}

impl<'de> DeserializeAs<'de, Uuid> for ShortId {
    fn deserialize_as<D: Deserializer<'de>>(deserializer: D) -> Result<Uuid, D::Error> {
        Self::deserialize(deserializer).map(Self::uuid)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;
    use serde_with::serde_as;

    use super::*;

    /// UUIDs and their short forms as printed by the JavaScript `short-uuid`
    /// package 6.0.3, `createTranslator().fromUUID`.
    const REFERENCE: [(&str, &str); 6] = [
        (
            "00000000-0000-0000-0000-000000000000",
            "1111111111111111111111",
        ),
        (
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
            "xBuEXKpA6iqZQK5Kf2TnkV",
        ),
        (
            "00000000-0000-0000-0000-000000000001",
            "1111111111111111111112",
        ),
        (
            "00000001-0000-4000-8000-000000000000",
            "111115Qcm4aLLYniL2oXNq",
        ),
        (
            "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
            "wD22tEXs3RXBjieaEk5373",
        ),
        (
            "5355e6aa-868d-43ce-824e-7b7002baddd2",
            "bhRFe93MKwHktZwXKG599A",
        ),
    ];

    #[test]
    fn reference_ids_match_short_uuid_package() {
        for (hyphenated, short) in REFERENCE {
            let id = Uuid::parse_str(hyphenated).unwrap();
            assert_eq!(ShortId::encode_uuid(id), short, "{hyphenated}");
            assert_eq!(ShortId::parse_uuid(short).unwrap(), id, "{short}");
        }
    }

    #[test]
    fn nil_and_max_ids_round_trip() {
        for id in [Uuid::nil(), Uuid::max()] {
            let short = ShortId::new(id).to_string();
            assert_eq!(short.parse::<ShortId>().unwrap().uuid(), id);
        }
    }

    #[test]
    fn every_encoded_id_is_22_characters() {
        let mut ids = vec![Uuid::nil(), Uuid::max()];
        for zero_bytes in 1..16 {
            let mut bytes = *Uuid::max().as_bytes();
            bytes[..zero_bytes].fill(0);
            ids.push(Uuid::from_bytes(bytes));
        }
        ids.extend((0..1000).map(|_| Uuid::new_v4()));
        for id in ids {
            let short = ShortId::encode_uuid(id);
            assert_eq!(short.len(), SHORT_ID_LEN, "{id}");
            assert_eq!(ShortId::parse_uuid(&short).unwrap(), id);
        }
    }

    #[test]
    fn hex_forms_decode_to_one_id() {
        let id = Uuid::parse_str("f81d4fae-7dec-11d0-a765-00a0c91e6bf6").unwrap();
        let forms = [
            "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
            "F81D4FAE-7DEC-11D0-A765-00A0C91E6BF6",
            "f81d4fae7dec11d0a76500a0c91e6bf6",
            "F81D4FAE7DEC11D0A76500A0C91E6BF6",
            "wD22tEXs3RXBjieaEk5373",
        ];
        for form in forms {
            assert_eq!(ShortId::parse_uuid(form).unwrap(), id, "{form}");
        }
    }

    #[test]
    fn malformed_ids_are_refused() {
        let inputs = [
            "",
            "1",
            // 21 and 23 digits.
            "111111111111111111111",
            "11111111111111111111111",
            // Characters outside the alphabet: 0, O, I, and l.
            "0111111111111111111111",
            "O111111111111111111111",
            "I111111111111111111111",
            "l111111111111111111111",
            "111111111111111111111-",
            // Above 128 bits.
            "zzzzzzzzzzzzzzzzzzzzzz",
            "xBuEXKpA6iqZQK5Kf2TnkW",
            // Hex forms that are not 32 or 36 characters, or not hex.
            "{f81d4fae-7dec-11d0-a765-00a0c91e6bf6}",
            "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
            "f81d4fae-7dec-11d0-a765-00a0c91e6bfg",
            "f81d4fae7dec11d0a76500a0c91e6bfg",
            "f81d4fae7dec-11d0-a765-00a0c91e6bf6-",
        ];
        for input in inputs {
            assert!(ShortId::decode(input).is_err(), "{input:?} was accepted");
        }
    }

    #[test]
    fn serde_adapter_writes_short_ids_and_reads_hex_ids() {
        #[serde_as]
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct Ids {
            #[serde_as(as = "ShortId")]
            id: Uuid,
            #[serde_as(as = "Option<ShortId>")]
            other: Option<Uuid>,
            #[serde_as(as = "BTreeMap<ShortId, _>")]
            map: BTreeMap<Uuid, u32>,
        }

        let id = Uuid::parse_str("5355e6aa-868d-43ce-824e-7b7002baddd2").unwrap();
        let ids = Ids {
            id,
            other: Some(id),
            map: BTreeMap::from([(id, 1)]),
        };
        let short = "bhRFe93MKwHktZwXKG599A";
        assert_eq!(
            serde_json::to_value(&ids).unwrap(),
            json!({ "id": short, "other": short, "map": { short: 1 } })
        );

        let hyphenated = id.to_string();
        let read: Ids = serde_json::from_value(json!({
            "id": hyphenated,
            "other": hyphenated,
            "map": { hyphenated.clone(): 1 },
        }))
        .unwrap();
        assert_eq!(read, ids);
    }
}
