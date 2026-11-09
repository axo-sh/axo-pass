use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroize;

#[derive(Serialize, Deserialize, Zeroize, Default, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct TextField {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multiline: Option<bool>,
}

/// Semantic type of a credential. This tier is closed: adding a preset means
/// adding code to handle its value and UI. `Text` is the freeform single-value
/// case and carries its own open subtype.
///
/// Serialized as an internally tagged object, `{"type": "..."}`. A known
/// variant is read only if it serializes back to the same JSON. Any other
/// object deserializes to `Unknown`, which keeps the raw object so a
/// round-trip through an older client preserves it unchanged. This covers an
/// unrecognized `type`, a known `type` with an unexpected shape, and a known
/// `type` with an extra field.
///
/// `remote = "Self"` makes the derives generate the inherent functions
/// `FieldKind::serialize` and `FieldKind::deserialize` instead of trait impls.
/// The trait impls below call them.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(tag = "type", rename_all = "kebab-case", remote = "Self")]
pub enum FieldKind {
    Text(TextField),
    Confidential(TextField),
    Email,
    Url,
    Phone,
    Date,
    Totp,
    /// A WebAuthn passkey. The credential's value is a JSON `Passkey` record
    /// (see `passkey.rs`), holding the private key, so it is confidential in
    /// the same way a password is. It is never editable as text.
    Passkey,
    /// Unknown or newer kind written by another client. Rendered read-only.
    #[serde(untagged)]
    Unknown(Value),
}

impl Serialize for FieldKind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Derived function, not this trait method.
        FieldKind::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for FieldKind {
    /// Known variant if it serializes back to the same JSON, and `Unknown`
    /// holding the object otherwise. Unit variants of an internally tagged
    /// enum ignore extra fields, so the derived function alone would drop
    /// them.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        // Derived function, not this trait method.
        let kind = FieldKind::deserialize(&value).map_err(serde::de::Error::custom)?;
        let same = serde_json::to_value(&kind).is_ok_and(|json| json == value);
        Ok(if same { kind } else { Self::Unknown(value) })
    }
}

impl Default for FieldKind {
    fn default() -> Self {
        Self::Confidential(TextField {
            multiline: Some(false),
        })
    }
}

impl FieldKind {
    pub fn is_default(&self) -> bool {
        matches!(
            self,
            Self::Confidential(TextField {
                multiline: Some(false),
            })
        )
    }
}

impl Zeroize for FieldKind {
    fn zeroize(&mut self) {
        match self {
            Self::Text(TextField { multiline }) => {
                multiline.zeroize();
            },
            Self::Confidential(TextField { multiline }) => {
                multiline.zeroize();
            },
            _ => {},
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_kind_is_default() {
        assert!(FieldKind::default().is_default());
        assert!(!FieldKind::Totp.is_default());
    }

    #[test]
    fn text_subtype_and_concealed_roundtrip() {
        let kind = FieldKind::Text(TextField {
            multiline: Some(true),
        });
        let json = serde_json::to_value(&kind).unwrap();
        assert_eq!(json["type"], "text");
        assert_eq!(json["multiline"], true);
        assert_eq!(serde_json::from_value::<FieldKind>(json).unwrap(), kind);
    }

    #[test]
    fn totp_kind_roundtrips() {
        let json = serde_json::to_value(FieldKind::Totp).unwrap();
        assert_eq!(json["type"], "totp");
        assert_eq!(
            serde_json::from_value::<FieldKind>(json).unwrap(),
            FieldKind::Totp
        );
    }

    #[test]
    fn unknown_kind_preserves_raw_object() {
        let src = r#"{"type":"wifi","ssid":"home","password":"hunter2"}"#;
        let kind: FieldKind = serde_json::from_str(src).unwrap();
        assert!(matches!(kind, FieldKind::Unknown(_)));

        // A round-trip, as happens when an older client rebuilds this
        // credential's metadata, leaves the object untouched.
        let back = serde_json::to_value(&kind).unwrap();
        assert_eq!(
            back,
            serde_json::from_str::<serde_json::Value>(src).unwrap()
        );
    }

    #[test]
    fn malformed_known_kind_falls_through_to_unknown() {
        // A `text` object that does not fit the schema (here `concealed` is not
        // a string) is preserved as `Unknown` rather than failing the load.
        let kind: FieldKind = serde_json::from_str(r#"{"type":"text","multiline":"yes"}"#).unwrap();
        assert!(matches!(kind, FieldKind::Unknown(_)));
    }

    #[test]
    fn known_kind_with_extra_field_kept_as_unknown() {
        for src in [
            r#"{"type":"email","x":1}"#,
            r#"{"type":"passkey","x":1}"#,
            r#"{"multiline":true,"type":"text","x":1}"#,
            r#"{"type":"confidential","x":{"y":[1,2]}}"#,
        ] {
            let kind: FieldKind = serde_json::from_str(src).unwrap();
            assert!(matches!(kind, FieldKind::Unknown(_)), "{src}");
            assert_eq!(serde_json::to_string(&kind).unwrap(), src);
        }
    }

    #[test]
    fn every_known_kind_reads_as_itself() {
        let kinds = [
            FieldKind::Text(TextField { multiline: None }),
            FieldKind::Text(TextField {
                multiline: Some(true),
            }),
            FieldKind::Confidential(TextField {
                multiline: Some(false),
            }),
            FieldKind::Email,
            FieldKind::Url,
            FieldKind::Phone,
            FieldKind::Date,
            FieldKind::Totp,
            FieldKind::Passkey,
        ];
        for kind in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            assert_eq!(
                serde_json::from_str::<FieldKind>(&json).unwrap(),
                kind,
                "{json}"
            );
        }
    }
}
