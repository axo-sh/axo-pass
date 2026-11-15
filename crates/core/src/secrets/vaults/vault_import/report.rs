use std::fmt;

use super::map::{FOLDER_TYPE, FOLDER_TYPE_PREFIX, has_password_slot, is_web_url};
use super::onepif::{ParsedItem, json_value_to_string};

/// Top-level keys that hold 1Password bookkeeping. They are not reported.
const BOOKKEEPING_KEYS: [&str; 4] = [
    "contentsHash",
    "locationKey",
    "securityLevel",
    "txTimestamp",
];
/// Top-level key that holds the favorite position.
const FAVORITE_KEY: &str = "faveIndex";

/// Data of one record that the import does not keep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dropped {
    /// Short name of the kind of data, such as `tags`. Items share kinds, so a
    /// report can count them.
    pub kind: &'static str,
    /// Details, such as the tag names. Empty if there are none to show.
    pub detail: String,
    /// Secret values of the dropped data, such as previous passwords. A caller
    /// shows them only on request.
    pub concealed: Option<String>,
}

impl Dropped {
    fn new(kind: &'static str, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
            concealed: None,
        }
    }
}

impl fmt::Display for Dropped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.detail.is_empty() {
            f.write_str(self.kind)
        } else {
            write!(f, "{}: {}", self.kind, self.detail)
        }
    }
}

/// Data of `item` that the mapper and writer do not keep. It applies the same
/// rules as the mapper.
pub fn dropped_data(item: &ParsedItem) -> Vec<Dropped> {
    let mut dropped = Vec::new();

    if let Some(value) = item.unread.get(FAVORITE_KEY) {
        dropped.push(Dropped::new("favorite", text(value)));
    }
    let unread = pairs(
        item.unread
            .iter()
            .filter(|(k, _)| *k != FAVORITE_KEY && !BOOKKEEPING_KEYS.contains(&k.as_str())),
    );
    if !unread.is_empty() {
        dropped.push(Dropped::new("unread keys", unread));
    }

    if !item.tags.is_empty() {
        dropped.push(Dropped::new("tags", item.tags.join(", ")));
    }
    if let Some(at) = item.updated_at {
        dropped.push(Dropped::new("modified time", at.to_string()));
    }

    if !item.password_history.is_empty() && !has_password_slot(item) {
        let mut entry = Dropped::new(
            "password history",
            format!("{} entries, no password field", item.password_history.len()),
        );
        entry.concealed = Some(
            item.password_history
                .iter()
                .map(|e| e.value.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        );
        dropped.push(entry);
    }
    for note in &item.parse_notes {
        dropped.push(Dropped::new("parse note", note.clone()));
    }

    if !item.blank_fields.is_empty() {
        let names: Vec<&str> = item
            .blank_fields
            .iter()
            .map(|n| {
                if n.is_empty() {
                    "(no label)"
                } else {
                    n.as_str()
                }
            })
            .collect();
        dropped.push(Dropped::new("blank fields", names.join(", ")));
    }

    let web_form = item.fields.iter().map(|f| (f.name.as_str(), &f.extra));
    let section = item
        .sections
        .iter()
        .flat_map(|s| &s.fields)
        .map(|f| (f.label.as_str(), &f.extra));
    let field_keys: Vec<String> = web_form
        .chain(section)
        .filter(|(_, extra)| !extra.is_empty())
        .map(|(name, extra)| {
            let name = if name.is_empty() { "(no label)" } else { name };
            format!("{name} ({})", pairs(extra.iter()))
        })
        .collect();
    if !field_keys.is_empty() {
        dropped.push(Dropped::new("field keys", field_keys.join("; ")));
    }

    if let Some(location) = item.location.as_deref()
        && !is_web_url(location)
        && !item.type_name.starts_with(FOLDER_TYPE_PREFIX)
    {
        dropped.push(Dropped::new("location, not a URL", location));
    }

    if item.type_name == FOLDER_TYPE {
        if let Some(parent) = &item.folder_uuid {
            dropped.push(Dropped::new("folder nesting", format!("parent {parent}")));
        }
    } else if item.type_name.starts_with(FOLDER_TYPE_PREFIX) {
        dropped.push(Dropped::new("folder not imported", item.type_name.clone()));
    }

    dropped
}

/// Value as text. A string has no quotes.
fn text(value: &serde_json::Value) -> String {
    json_value_to_string(value.clone())
}

/// `key=value` pairs, separated by commas.
fn pairs<'a>(entries: impl Iterator<Item = (&'a String, &'a serde_json::Value)>) -> String {
    entries
        .map(|(key, value)| format!("{key}={}", text(value)))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use std::fs;

    use indoc::indoc;

    use super::*;
    use crate::secrets::vaults::vault_import::parse_1pif;

    fn entries_of(record: &str) -> Vec<Dropped> {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("data.1pif"), record).unwrap();
        let items = parse_1pif(dir.path()).unwrap();
        dropped_data(&items[0])
    }

    fn dropped_of(record: &str) -> Vec<String> {
        entries_of(record).iter().map(Dropped::to_string).collect()
    }

    #[test]
    fn record_with_nothing_dropped_reports_nothing() {
        let dropped = dropped_of(indoc! {r#"
            {"uuid":"A1","typeName":"securenotes.SecureNote","title":"N","contentsHash":"h","securityLevel":"SL5","txTimestamp":1,"secureContents":{"notesPlain":"x"}}
        "#});

        assert!(dropped.is_empty(), "{dropped:?}");
    }

    #[test]
    fn favorite_and_modified_time_reported() {
        let dropped = dropped_of(indoc! {r#"
            {"uuid":"A2","typeName":"securenotes.SecureNote","title":"N","faveIndex":3,"updatedAt":1500000000,"secureContents":{}}
        "#});

        assert_eq!(dropped, ["favorite: 3", "modified time: 1500000000"]);
    }

    #[test]
    fn tags_reported_with_names() {
        let dropped = dropped_of(indoc! {r#"
            {"uuid":"A3","typeName":"securenotes.SecureNote","title":"N","openContents":{"tags":["work","bank"]},"secureContents":{}}
        "#});

        assert_eq!(dropped, ["tags: work, bank"]);
    }

    #[test]
    fn unknown_top_level_key_reported() {
        let dropped = dropped_of(indoc! {r#"
            {"uuid":"A4","typeName":"securenotes.SecureNote","title":"N","newThing":1,"secureContents":{}}
        "#});

        assert_eq!(dropped, ["unread keys: newThing=1"]);
    }

    #[test]
    fn history_without_password_field_reported_concealed() {
        let entries = entries_of(indoc! {r#"
            {"uuid":"A5","typeName":"webforms.WebForm","title":"N","secureContents":{"passwordHistory":[{"value":"old1","time":1},{"value":"old2","time":2}]}}
        "#});

        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].to_string(),
            "password history: 2 entries, no password field"
        );
        assert_eq!(entries[0].concealed.as_deref(), Some("old1, old2"));
    }

    #[test]
    fn history_with_password_field_not_reported() {
        let dropped = dropped_of(indoc! {r#"
            {"uuid":"A5","typeName":"webforms.WebForm","title":"N","secureContents":{"fields":[{"name":"pass","designation":"password","value":"now","type":"P"}],"passwordHistory":[{"value":"old1","time":1}]}}
        "#});

        assert!(dropped.is_empty(), "{dropped:?}");
    }

    #[test]
    fn malformed_history_entry_reported_without_value() {
        let entries = entries_of(indoc! {r#"
            {"uuid":"A5","typeName":"webforms.WebForm","title":"N","secureContents":{"fields":[{"name":"pass","designation":"password","value":"now","type":"P"}],"passwordHistory":[{"value":"secret-old"}]}}
        "#});

        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].to_string(),
            "parse note: password history entry 1 has no time"
        );
        assert_eq!(entries[0].concealed, None);
    }

    #[test]
    fn empty_password_history_not_reported() {
        let dropped = dropped_of(indoc! {r#"
            {"uuid":"A6","typeName":"webforms.WebForm","title":"N","secureContents":{"passwordHistory":[]}}
        "#});

        assert!(dropped.is_empty(), "{dropped:?}");
    }

    #[test]
    fn blank_fields_counted_across_web_form_and_sections() {
        let dropped = dropped_of(indoc! {r#"
            {"uuid":"A7","typeName":"webforms.WebForm","title":"N","secureContents":{"fields":[{"name":"login","designation":"username","value":"","type":"T"}],"sections":[{"title":"S","fields":[{"k":"string","t":"a","v":""},{"k":"string","t":"b","v":null},{"k":"string","t":"c","v":"x"}]}]}}
        "#});

        assert_eq!(dropped, ["blank fields: login, a, b"]);
    }

    #[test]
    fn field_keys_not_imported_reported_once() {
        let dropped = dropped_of(indoc! {r#"
            {"uuid":"A8","typeName":"webforms.WebForm","title":"N","secureContents":{"fields":[{"name":"x","id":"i1","value":"v","type":"T"}],"sections":[{"title":"S","fields":[{"k":"string","n":"f1","t":"a","v":"x"},{"k":"string","n":"f2","t":"b","v":"y"}]}]}}
        "#});

        assert_eq!(dropped, ["field keys: x (id=i1); a (n=f1); b (n=f2)"]);
    }

    #[test]
    fn location_that_is_not_a_url_reported() {
        let dropped = dropped_of(indoc! {r#"
            {"uuid":"A9","typeName":"wallet.computer.Router","title":"R","location":"192.168.1.1","secureContents":{}}
        "#});

        assert_eq!(dropped, ["location, not a URL: 192.168.1.1"]);
    }

    #[test]
    fn web_location_not_reported() {
        let dropped = dropped_of(indoc! {r#"
            {"uuid":"B1","typeName":"webforms.WebForm","title":"S","location":"https://a.example","secureContents":{}}
        "#});

        assert!(dropped.is_empty(), "{dropped:?}");
    }

    #[test]
    fn nested_folder_and_smart_folder_reported() {
        let nested = dropped_of(indoc! {r#"
            {"uuid":"F1","typeName":"system.folder.Regular","title":"Child","folderUuid":"F0","secureContents":{}}
        "#});
        let smart = dropped_of(indoc! {r#"
            {"uuid":"F2","typeName":"system.folder.SmartFolder","title":"Smart","secureContents":{}}
        "#});

        assert_eq!(nested, ["folder nesting: parent F0"]);
        assert_eq!(smart, ["folder not imported: system.folder.SmartFolder"]);
    }
}
