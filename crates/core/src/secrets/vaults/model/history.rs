use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroize;

/// Change recorded by a credential history entry. This tier is closed: adding
/// a kind means adding code to record and show it.
///
/// Serialized as an internally tagged object, `{"type": "..."}`, with the
/// round-trip rule of `FieldKind`. A known variant is read only if it
/// serializes back to the same JSON. Any other object deserializes to
/// `Unknown`, which keeps the raw object so a round-trip through an older
/// client preserves it unchanged.
///
/// `remote = "Self"` makes the derives generate the inherent functions
/// `HistoryKind::serialize` and `HistoryKind::deserialize` instead of trait
/// impls. The trait impls below call them.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Default)]
#[serde(tag = "type", rename_all = "kebab-case", remote = "Self")]
pub enum HistoryKind {
    /// First value of a credential, set over no value or an empty value. The
    /// entry holds no value.
    ValueCreated,
    /// Value replaced by another. The entry holds the replaced value.
    #[default]
    ValueUpdated,
    /// Unknown or newer kind written by another client. The entry may hold a
    /// value.
    #[serde(untagged)]
    Unknown(Value),
}

impl Serialize for HistoryKind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Derived function, not this trait method.
        HistoryKind::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for HistoryKind {
    /// Known variant if it serializes back to the same JSON, and `Unknown`
    /// holding the object otherwise. Unit variants of an internally tagged
    /// enum ignore extra fields, so the derived function alone would drop
    /// them.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        // Derived function, not this trait method.
        let kind = HistoryKind::deserialize(&value).map_err(serde::de::Error::custom)?;
        let same = serde_json::to_value(&kind).is_ok_and(|json| json == value);
        Ok(if same { kind } else { Self::Unknown(value) })
    }
}

impl HistoryKind {
    /// Whether an entry of this kind holds a value. `None` for an unknown
    /// kind, which may hold one or not.
    pub fn has_value(&self) -> Option<bool> {
        match self {
            Self::ValueCreated => Some(false),
            Self::ValueUpdated => Some(true),
            Self::Unknown(_) => None,
        }
    }
}

impl Zeroize for HistoryKind {
    fn zeroize(&mut self) {}
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn known_kinds_roundtrip() {
        for (kind, json) in [
            (HistoryKind::ValueCreated, json!({"type": "value-created"})),
            (HistoryKind::ValueUpdated, json!({"type": "value-updated"})),
        ] {
            assert_eq!(serde_json::to_value(&kind).unwrap(), json);
            assert_eq!(serde_json::from_value::<HistoryKind>(json).unwrap(), kind);
        }
    }

    #[test]
    fn unknown_kind_kept_as_written() {
        for json in [
            json!({"type": "renamed", "from": "Old title"}),
            json!({"type": "value-updated", "extra": 1}),
            json!({"other": true}),
        ] {
            let kind: HistoryKind = serde_json::from_value(json.clone()).unwrap();
            assert_eq!(kind, HistoryKind::Unknown(json.clone()));
            assert_eq!(serde_json::to_value(&kind).unwrap(), json);
        }
    }
}
