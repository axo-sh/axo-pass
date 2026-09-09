use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize, Zeroize, Default, Clone, PartialEq, Eq, Debug)]
pub struct TextField {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multiline: Option<bool>,
}

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
    Text(TextField),
    Confidential(TextField),
    Email,
    Url,
    Phone,
    Date,
    Totp,
    /// Unknown or newer kind written by another client. Rendered read-only.
    #[serde(untagged)]
    Unknown(serde_json::Value),
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
}
