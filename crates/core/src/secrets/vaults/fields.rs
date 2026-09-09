use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Semantic type of a credential. This tier is closed: adding a preset means
/// adding code to handle its value and UI. `Text` is the freeform single-value
/// case and carries its own open subtype.
///
/// Serialized as an internally tagged object, `{"type": "..."}`. Any object
/// this build cannot parse as a known variant (an unrecognized `type`, or a
/// known `type` with an unexpected shape) deserializes to `Unknown`, which
/// keeps the raw object so a round-trip through an older client preserves it
/// unchanged.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum FieldKind {
    Text {
        #[serde(default, skip_serializing_if = "TextSubtype::is_plain")]
        subtype: TextSubtype,
        /// None: derive from the subtype (password defaults concealed).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        concealed: Option<bool>,
    },
    Totp,
    /// Unknown or newer kind written by another client. Rendered read-only.
    #[serde(untagged)]
    Unknown(serde_json::Value),
}

impl Default for FieldKind {
    fn default() -> Self {
        Self::Text {
            subtype: TextSubtype::Plain,
            concealed: None,
        }
    }
}

impl FieldKind {
    pub fn is_default(&self) -> bool {
        matches!(
            self,
            Self::Text {
                subtype: TextSubtype::Plain,
                concealed: None,
            }
        )
    }

    /// Whether the value should be masked in the UI by default.
    pub fn concealed(&self) -> bool {
        match self {
            Self::Text { subtype, concealed } => {
                concealed.unwrap_or(matches!(subtype, TextSubtype::Password))
            },
            Self::Totp => true,
            Self::Unknown(_) => false,
        }
    }

    /// Whether the text editor should be multiline.
    pub fn multiline(&self) -> bool {
        matches!(
            self,
            Self::Text {
                subtype: TextSubtype::Multiline,
                ..
            }
        )
    }
}

impl Zeroize for FieldKind {
    fn zeroize(&mut self) {
        if let Self::Text { subtype, concealed } = self {
            subtype.zeroize();
            concealed.zeroize();
        }
    }
}

/// Rendering and validation profile for a `Text` field. Open: an unknown
/// subtype from another client behaves as `Plain`.
#[derive(Zeroize, Clone, PartialEq, Eq, Default, Debug)]
pub enum TextSubtype {
    #[default]
    Plain,
    Multiline,
    Email,
    Url,
    Phone,
    Date,
    Password,
    Other(String),
}

impl TextSubtype {
    fn is_plain(&self) -> bool {
        matches!(self, Self::Plain)
    }

    fn as_str(&self) -> &str {
        match self {
            Self::Plain => "plain",
            Self::Multiline => "multiline",
            Self::Email => "email",
            Self::Url => "url",
            Self::Phone => "phone",
            Self::Date => "date",
            Self::Password => "password",
            Self::Other(s) => s,
        }
    }
}

impl From<&str> for TextSubtype {
    fn from(s: &str) -> Self {
        match s {
            "plain" => Self::Plain,
            "multiline" => Self::Multiline,
            "email" => Self::Email,
            "url" => Self::Url,
            "phone" => Self::Phone,
            "date" => Self::Date,
            "password" => Self::Password,
            other => Self::Other(other.to_string()),
        }
    }
}

impl Serialize for TextSubtype {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for TextSubtype {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::from(String::deserialize(deserializer)?.as_str()))
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
        let kind = FieldKind::Text {
            subtype: TextSubtype::Multiline,
            concealed: Some(true),
        };
        let json = serde_json::to_value(&kind).unwrap();
        assert_eq!(json["type"], "text");
        assert_eq!(json["subtype"], "multiline");
        assert_eq!(json["concealed"], true);
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
        assert!(!kind.concealed());

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
        // a bool) is preserved as `Unknown` rather than failing the load.
        let kind: FieldKind = serde_json::from_str(r#"{"type":"text","concealed":"yes"}"#).unwrap();
        assert!(matches!(kind, FieldKind::Unknown(_)));
    }

    #[test]
    fn unknown_text_subtype_preserved() {
        let kind: FieldKind = serde_json::from_str(r#"{"type":"text","subtype":"color"}"#).unwrap();
        assert_eq!(
            kind,
            FieldKind::Text {
                subtype: TextSubtype::Other("color".to_string()),
                concealed: None,
            }
        );
        let json = serde_json::to_value(&kind).unwrap();
        assert_eq!(json["subtype"], "color");
    }

    #[test]
    fn concealed_defaults() {
        assert!(!FieldKind::default().concealed());
        assert!(FieldKind::Totp.concealed());
        assert!(
            FieldKind::Text {
                subtype: TextSubtype::Password,
                concealed: None,
            }
            .concealed()
        );
        assert!(
            !FieldKind::Text {
                subtype: TextSubtype::Password,
                concealed: Some(false),
            }
            .concealed()
        );
    }
}
