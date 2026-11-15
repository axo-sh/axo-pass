use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

/// Record separator that 1Password writes between JSON objects in a `.1pif`
/// export.
const RECORD_SEPARATOR: &str = "***5642bee8-a5ff-11dc-8314-0800200c9a66***";

/// Key of `secureContents` that holds previous passwords.
const HISTORY_KEY: &str = "passwordHistory";

#[derive(Debug, Error)]
pub enum OnePifError {
    #[error("1pif path not found: {0}")]
    NotFound(String),

    #[error("failed to read 1pif data: {0}")]
    Read(#[source] std::io::Error),

    #[error("failed to parse 1pif record {record}: {source}")]
    Parse {
        record: usize,
        #[source]
        source: serde_json::Error,
    },
}

/// A single parsed entry from a 1Password 1pif export, normalized into the
/// fields this app cares about.
#[derive(Debug, Clone)]
pub struct ParsedItem {
    pub uuid: String,
    pub type_name: String,
    pub title: String,
    pub location: Option<String>,
    pub trashed: bool,
    pub notes: Option<String>,
    /// Web-form fields (login / password designations live here).
    pub fields: Vec<ParsedField>,
    /// Custom sections, each with its own labelled fields.
    pub sections: Vec<ParsedSection>,
    /// Website links from `secureContents.URLs`.
    pub urls: Vec<ParsedUrl>,
    /// Folder reference from `folderUuid`.
    pub folder_uuid: Option<String>,
    /// Tags from `openContents.tags`. Only used for the import report.
    pub tags: Vec<String>,
    /// Creation time from `createdAt`, in Unix seconds. 1Password writes
    /// seconds, but this has not been checked against a real export.
    pub created_at: Option<i64>,
    /// Modification time from `updatedAt`, in Unix seconds. Only used for the
    /// import report.
    pub updated_at: Option<i64>,
    /// Keys of `secureContents` that the parser does not read into another
    /// field, with their values. Keys are in sorted order.
    pub extra: serde_json::Map<String, serde_json::Value>,
    /// Files in `attachments/<uuid>/` next to the data file, sorted by path.
    pub attachments: Vec<PathBuf>,
    /// Top-level keys of the record that the parser does not read, with their
    /// values. Keys are in sorted order.
    pub unread: serde_json::Map<String, serde_json::Value>,
    /// Names of web-form fields and labels of section fields with a blank
    /// value. The parser drops blank section fields and the mapper skips
    /// blank web-form fields.
    pub blank_fields: Vec<String>,
    /// Previous passwords from `passwordHistory`, in export order. A malformed
    /// entry is left out and noted in `parse_notes`.
    pub password_history: Vec<ParsedHistoryEntry>,
    /// Problems found while reading the record. A note holds no secret value.
    pub parse_notes: Vec<String>,
}

/// A previous password from `secureContents.passwordHistory`.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedHistoryEntry {
    pub value: String,
    /// Unix seconds.
    pub time: i64,
}

#[derive(Debug, Clone)]
pub struct ParsedUrl {
    pub label: String,
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct ParsedField {
    pub name: String,
    pub designation: Option<String>,
    /// Field value as written in the export. Usually a string.
    pub value: serde_json::Value,
    pub field_type: Option<String>,
    /// Other keys of the field, with their values.
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl ParsedField {
    /// Value as text. Non-string values use their JSON form.
    pub fn text(&self) -> String {
        json_value_to_string(self.value.clone())
    }
}

#[derive(Debug, Clone)]
pub struct ParsedSection {
    pub title: String,
    pub fields: Vec<ParsedSectionField>,
}

#[derive(Debug, Clone)]
pub struct ParsedSectionField {
    pub label: String,
    /// Field value as written in the export. A string, number, boolean,
    /// object, or array.
    pub value: serde_json::Value,
    /// 1Password field kind, e.g. `concealed`, `string`, `email`.
    pub kind: Option<String>,
    /// Other keys of the field, such as `n`, with their values.
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl ParsedSectionField {
    /// Value as text. Non-string values use their JSON form.
    pub fn text(&self) -> String {
        json_value_to_string(self.value.clone())
    }
}

impl ParsedItem {
    /// Value text of the first web-form field with the given `designation`.
    pub fn designated(&self, designation: &str) -> Option<String> {
        self.fields
            .iter()
            .find(|f| f.designation.as_deref() == Some(designation))
            .map(ParsedField::text)
    }
}

/// Parse a 1Password `.1pif` export. `path` may point at the `.1pif` directory,
/// at the `data.1pif` file inside it, or at any file containing the record
/// stream.
pub fn parse_1pif<P: AsRef<Path>>(path: P) -> Result<Vec<ParsedItem>, OnePifError> {
    let data_path = resolve_data_path(path.as_ref())?;
    let contents = fs::read_to_string(&data_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            OnePifError::NotFound(data_path.display().to_string())
        } else {
            OnePifError::Read(e)
        }
    })?;

    let mut items = Vec::new();
    for (idx, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line == RECORD_SEPARATOR {
            continue;
        }

        let raw: RawItem = serde_json::from_str(line).map_err(|source| OnePifError::Parse {
            record: idx + 1,
            source,
        })?;
        items.push(raw.into_parsed());
    }

    if let Some(root) = data_path.parent() {
        for item in &mut items {
            item.attachments = find_attachments(root, &item.uuid)?;
        }
    }
    Ok(items)
}

fn resolve_data_path(path: &Path) -> Result<PathBuf, OnePifError> {
    if path.is_dir() {
        for candidate in ["data.1pif", "1PIF.txt"] {
            let p = path.join(candidate);
            if p.is_file() {
                return Ok(p);
            }
        }
        return Err(OnePifError::NotFound(
            path.join("data.1pif").display().to_string(),
        ));
    }
    Ok(path.to_path_buf())
}

#[derive(Debug, Deserialize)]
struct RawItem {
    #[serde(default)]
    uuid: String,
    #[serde(rename = "typeName", default)]
    type_name: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    trashed: bool,
    #[serde(rename = "folderUuid", default)]
    folder_uuid: Option<String>,
    #[serde(rename = "createdAt", default)]
    created_at: Option<i64>,
    #[serde(rename = "updatedAt", default)]
    updated_at: Option<i64>,
    #[serde(rename = "openContents", default)]
    open_contents: RawOpenContents,
    #[serde(rename = "secureContents", default)]
    secure_contents: RawSecureContents,
    /// Every key not listed above.
    #[serde(flatten)]
    other: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Default, Deserialize)]
struct RawOpenContents {
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawUrl {
    #[serde(default)]
    label: String,
    #[serde(default)]
    url: String,
}

#[derive(Debug, Default, Deserialize)]
struct RawSecureContents {
    #[serde(default)]
    fields: Vec<RawField>,
    #[serde(default)]
    sections: Vec<RawSection>,
    #[serde(rename = "notesPlain", default)]
    notes_plain: Option<String>,
    /// Present on `passwords.Password` items.
    #[serde(default)]
    password: Option<String>,
    #[serde(rename = "URLs", default)]
    urls: Vec<RawUrl>,
    /// Every key not listed above.
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct RawField {
    #[serde(default)]
    name: String,
    #[serde(default)]
    designation: Option<String>,
    #[serde(default)]
    value: serde_json::Value,
    #[serde(rename = "type", default)]
    field_type: Option<String>,
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct RawSection {
    #[serde(default)]
    title: String,
    #[serde(default)]
    fields: Vec<RawSectionField>,
}

#[derive(Debug, Deserialize)]
struct RawSectionField {
    #[serde(rename = "t", default)]
    label: String,
    #[serde(rename = "v", default)]
    value: serde_json::Value,
    #[serde(rename = "k", default)]
    kind: Option<String>,
    #[serde(flatten)]
    extra: serde_json::Map<String, serde_json::Value>,
}

impl RawItem {
    fn into_parsed(self) -> ParsedItem {
        let sc = self.secure_contents;

        let mut fields: Vec<ParsedField> = sc
            .fields
            .into_iter()
            .map(|f| ParsedField {
                name: f.name,
                designation: f.designation,
                value: f.value,
                field_type: f.field_type,
                extra: f.extra,
            })
            .collect();

        let blank_fields: Vec<String> = fields
            .iter()
            .filter(|f| is_blank(&f.value))
            .map(|f| f.name.clone())
            .chain(
                sc.sections
                    .iter()
                    .flat_map(|s| &s.fields)
                    .filter(|f| is_blank(&f.value))
                    .map(|f| f.label.clone()),
            )
            .collect();

        // `passwords.Password` items keep the secret in `secureContents.password`
        // rather than a web-form field.
        if let Some(password) = sc.password
            && !password.is_empty()
        {
            fields.push(ParsedField {
                name: "password".to_string(),
                designation: Some("password".to_string()),
                value: serde_json::Value::String(password),
                field_type: Some("P".to_string()),
                extra: serde_json::Map::new(),
            });
        }

        let sections = sc
            .sections
            .into_iter()
            .filter_map(|s| {
                let fields: Vec<ParsedSectionField> = s
                    .fields
                    .into_iter()
                    .filter_map(|f| {
                        if is_blank(&f.value) {
                            return None;
                        }
                        Some(ParsedSectionField {
                            label: f.label,
                            value: f.value,
                            kind: f.kind,
                            extra: f.extra,
                        })
                    })
                    .collect();
                if fields.is_empty() {
                    None
                } else {
                    Some(ParsedSection {
                        title: s.title,
                        fields,
                    })
                }
            })
            .collect();

        let mut extra = sc.extra;
        let (password_history, parse_notes) = read_history(extra.remove(HISTORY_KEY));

        ParsedItem {
            uuid: self.uuid,
            type_name: self.type_name,
            title: self.title,
            location: self.location.filter(|l| !l.is_empty()),
            trashed: self.trashed,
            notes: sc.notes_plain.filter(|n| !n.is_empty()),
            fields,
            sections,
            urls: sc
                .urls
                .into_iter()
                .filter(|u| !u.url.is_empty())
                .map(|u| ParsedUrl {
                    label: u.label,
                    url: u.url,
                })
                .collect(),
            folder_uuid: self.folder_uuid.filter(|f| !f.is_empty()),
            tags: self.open_contents.tags,
            created_at: self.created_at,
            updated_at: self.updated_at,
            extra,
            attachments: Vec::new(),
            unread: self.other,
            blank_fields,
            password_history,
            parse_notes,
        }
    }
}

/// Entries of a `passwordHistory` value, and a note for each entry that has
/// no string value or no integer time.
fn read_history(value: Option<serde_json::Value>) -> (Vec<ParsedHistoryEntry>, Vec<String>) {
    let mut entries = Vec::new();
    let mut notes = Vec::new();
    match value {
        None | Some(serde_json::Value::Null) => {},
        Some(serde_json::Value::Array(list)) => {
            for (index, raw) in list.iter().enumerate() {
                let number = index + 1;
                let value = raw
                    .get("value")
                    .and_then(serde_json::Value::as_str)
                    .filter(|v| !v.is_empty());
                let time = raw.get("time").and_then(serde_json::Value::as_i64);
                match (value, time) {
                    (Some(value), Some(time)) => entries.push(ParsedHistoryEntry {
                        value: value.to_string(),
                        time,
                    }),
                    (None, _) => {
                        notes.push(format!("password history entry {number} has no value"))
                    },
                    (_, None) => notes.push(format!("password history entry {number} has no time")),
                }
            }
        },
        Some(_) => notes.push("password history is not a list".to_string()),
    }
    (entries, notes)
}

/// Files in `attachments/<uuid>/` of the export folder `root`, sorted by path.
/// The folder name is the item uuid, compared without regard to case. Hidden
/// files and subfolders are left out. Empty if the item has no folder.
fn find_attachments(root: &Path, uuid: &str) -> Result<Vec<PathBuf>, OnePifError> {
    let attachments = root.join("attachments");
    if uuid.is_empty() || !attachments.is_dir() {
        return Ok(Vec::new());
    }
    let mut folder = None;
    for entry in fs::read_dir(&attachments).map_err(OnePifError::Read)? {
        let entry = entry.map_err(OnePifError::Read)?;
        if entry
            .file_name()
            .to_string_lossy()
            .eq_ignore_ascii_case(uuid)
            && entry.path().is_dir()
        {
            folder = Some(entry.path());
            break;
        }
    }
    let Some(folder) = folder else {
        return Ok(Vec::new());
    };

    let mut files = Vec::new();
    for entry in fs::read_dir(&folder).map_err(OnePifError::Read)? {
        let entry = entry.map_err(OnePifError::Read)?;
        let hidden = entry.file_name().to_string_lossy().starts_with('.');
        if !hidden && entry.path().is_file() {
            files.push(entry.path());
        }
    }
    files.sort();
    Ok(files)
}

/// True for a null or empty string value.
pub(super) fn is_blank(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => true,
        serde_json::Value::String(s) => s.is_empty(),
        _ => false,
    }
}

pub(super) fn json_value_to_string(value: serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => String::new(),
        serde_json::Value::String(s) => s,
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::*;

    fn write_fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let data = indoc! {r#"
            {"uuid":"AAA1","typeName":"webforms.WebForm","title":"GitHub","location":"https://github.com","secureContents":{"fields":[{"name":"login","designation":"username","value":"me@example.com","type":"T"},{"name":"password","designation":"password","value":"hunter2","type":"P"}],"sections":[{"title":"Recovery","fields":[{"k":"concealed","n":"otp","t":"one-time password","v":"otpauth://totp/x"},{"k":"string","n":"blank","t":"empty","v":""}]}]}}
            ***5642bee8-a5ff-11dc-8314-0800200c9a66***
            {"uuid":"BBB2","typeName":"passwords.Password","title":"WiFi","secureContents":{"password":"correcthorse","notesPlain":"home network"}}
            ***5642bee8-a5ff-11dc-8314-0800200c9a66***
            {"uuid":"CCC3","typeName":"securenotes.SecureNote","title":"Old","trashed":true,"secureContents":{"notesPlain":"gone"}}
        "#};
        fs::write(dir.path().join("data.1pif"), data).unwrap();
        dir
    }

    #[test]
    fn parses_records_from_directory() {
        let dir = write_fixture();
        let items = parse_1pif(dir.path()).unwrap();

        assert_eq!(items.len(), 3);

        let github = &items[0];
        assert_eq!(github.title, "GitHub");
        assert_eq!(
            github.designated("username").as_deref(),
            Some("me@example.com")
        );
        assert_eq!(github.designated("password").as_deref(), Some("hunter2"));
        assert_eq!(github.location.as_deref(), Some("https://github.com"));
        assert_eq!(github.sections.len(), 1);
        // The empty-value field is dropped.
        assert_eq!(github.sections[0].fields.len(), 1);
        assert_eq!(
            github.sections[0].fields[0].kind.as_deref(),
            Some("concealed")
        );

        let wifi = &items[1];
        assert_eq!(wifi.designated("password").as_deref(), Some("correcthorse"));
        assert_eq!(wifi.notes.as_deref(), Some("home network"));

        assert!(items[2].trashed);
    }

    /// Parse one record given as JSON.
    fn parse_one(record: &str) -> ParsedItem {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("data.1pif"), record).unwrap();
        parse_1pif(dir.path()).unwrap().remove(0)
    }

    #[test]
    fn reads_urls() {
        let item = parse_one(indoc! {r#"
            {"uuid":"U1","typeName":"webforms.WebForm","title":"Site","secureContents":{"URLs":[{"label":"website","url":"https://a.example"},{"label":"","url":""},{"label":"login","url":"https://b.example"}]}}
        "#});

        assert_eq!(item.urls.len(), 2);
        assert_eq!(item.urls[0].label, "website");
        assert_eq!(item.urls[0].url, "https://a.example");
        assert_eq!(item.urls[1].label, "login");
        assert!(!item.extra.contains_key("URLs"));
    }

    #[test]
    fn reads_folder_uuid() {
        let item = parse_one(
            r#"{"uuid":"F1","typeName":"securenotes.SecureNote","title":"N","folderUuid":"FOLDER1","secureContents":{}}"#,
        );
        assert_eq!(item.folder_uuid.as_deref(), Some("FOLDER1"));

        let item = parse_one(
            r#"{"uuid":"F2","typeName":"securenotes.SecureNote","title":"N","folderUuid":"","secureContents":{}}"#,
        );
        assert_eq!(item.folder_uuid, None);
    }

    #[test]
    fn reads_tags() {
        let item = parse_one(
            r#"{"uuid":"T1","typeName":"securenotes.SecureNote","title":"N","openContents":{"tags":["work","bank"]},"secureContents":{}}"#,
        );
        assert_eq!(item.tags, ["work", "bank"]);
    }

    #[test]
    fn reads_created_and_updated_times() {
        let item = parse_one(
            r#"{"uuid":"D1","typeName":"securenotes.SecureNote","title":"N","createdAt":1400000000,"updatedAt":1500000000,"secureContents":{}}"#,
        );
        assert_eq!(item.created_at, Some(1_400_000_000));
        assert_eq!(item.updated_at, Some(1_500_000_000));

        let item = parse_one(
            r#"{"uuid":"D2","typeName":"securenotes.SecureNote","title":"N","secureContents":{}}"#,
        );
        assert_eq!(item.created_at, None);
        assert_eq!(item.updated_at, None);
    }

    #[test]
    fn reads_attachment_files() {
        let dir = tempfile::tempdir().unwrap();
        let data = indoc! {r#"
            {"uuid":"5930154CFAB244FB920D5189DA0FAB9C","typeName":"webforms.WebForm","title":"With files","secureContents":{}}
            {"uuid":"AAAA0000AAAA0000AAAA0000AAAA0000","typeName":"securenotes.SecureNote","title":"No files","secureContents":{}}
        "#};
        fs::write(dir.path().join("data.1pif"), data).unwrap();
        let folder = dir
            .path()
            .join("attachments")
            .join("5930154cfab244fb920d5189da0fab9c");
        fs::create_dir_all(folder.join("nested")).unwrap();
        fs::write(folder.join("b.png"), "b").unwrap();
        fs::write(folder.join("a.pdf"), "a").unwrap();
        fs::write(folder.join(".DS_Store"), "x").unwrap();

        let items = parse_1pif(dir.path()).unwrap();

        let names: Vec<_> = items[0]
            .attachments
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, ["a.pdf", "b.png"]);
        assert!(items[1].attachments.is_empty());
    }

    #[test]
    fn no_attachments_folder_gives_no_attachments() {
        let item = parse_one(
            r#"{"uuid":"Z1","typeName":"securenotes.SecureNote","title":"N","secureContents":{}}"#,
        );
        assert!(item.attachments.is_empty());
    }

    #[test]
    fn keeps_type_name() {
        let item = parse_one(
            r#"{"uuid":"Y1","typeName":"wallet.financial.CreditCard","title":"Card","secureContents":{}}"#,
        );
        assert_eq!(item.type_name, "wallet.financial.CreditCard");
    }

    #[test]
    fn keeps_unread_secure_contents_keys() {
        let item = parse_one(indoc! {r#"
            {"uuid":"X1","typeName":"wallet.financial.CreditCard","title":"Card","secureContents":{"ccnum":"4111","expiry_yy":2030,"cardholder":"Me","notesPlain":"n","sections":[],"fields":[]}}
        "#});

        assert_eq!(item.extra.len(), 3);
        assert_eq!(item.extra["ccnum"], "4111");
        assert_eq!(item.extra["expiry_yy"], 2030);
        assert_eq!(item.extra["cardholder"], "Me");
    }

    #[test]
    fn keeps_unread_section_field_keys() {
        let item = parse_one(indoc! {r#"
            {"uuid":"S1","typeName":"securenotes.SecureNote","title":"N","secureContents":{"sections":[{"title":"S","fields":[{"k":"string","n":"field1","t":"Label","v":"value","inputTraits":{"autocapitalization":"None"}}]}]}}
        "#});

        let field = &item.sections[0].fields[0];
        assert_eq!(field.extra.len(), 2);
        assert_eq!(field.extra["n"], "field1");
        assert_eq!(field.extra["inputTraits"]["autocapitalization"], "None");
    }

    #[test]
    fn keeps_unread_web_form_field_keys() {
        let item = parse_one(indoc! {r#"
            {"uuid":"W1","typeName":"webforms.WebForm","title":"Site","secureContents":{"fields":[{"name":"login","id":"user_id","designation":"username","value":"me","type":"T"}]}}
        "#});

        assert_eq!(item.fields[0].extra.len(), 1);
        assert_eq!(item.fields[0].extra["id"], "user_id");
    }

    #[test]
    fn section_field_number_value() {
        let item = parse_one(indoc! {r#"
            {"uuid":"V1","typeName":"securenotes.SecureNote","title":"N","secureContents":{"sections":[{"title":"S","fields":[{"k":"monthYear","t":"expires","v":203012}]}]}}
        "#});

        let field = &item.sections[0].fields[0];
        assert_eq!(field.value, serde_json::json!(203012));
        assert_eq!(field.text(), "203012");
    }

    #[test]
    fn section_field_boolean_value() {
        let item = parse_one(indoc! {r#"
            {"uuid":"V2","typeName":"securenotes.SecureNote","title":"N","secureContents":{"sections":[{"title":"S","fields":[{"k":"string","t":"flag","v":false}]}]}}
        "#});

        let field = &item.sections[0].fields[0];
        assert_eq!(field.value, serde_json::json!(false));
        assert_eq!(field.text(), "false");
    }

    #[test]
    fn section_field_object_value() {
        let item = parse_one(indoc! {r#"
            {"uuid":"V3","typeName":"securenotes.SecureNote","title":"N","secureContents":{"sections":[{"title":"S","fields":[{"k":"address","t":"home","v":{"street":"1 Main","city":"Town"}}]}]}}
        "#});

        let field = &item.sections[0].fields[0];
        assert_eq!(field.value["street"], "1 Main");
        assert_eq!(field.value["city"], "Town");
    }

    #[test]
    fn section_field_array_value() {
        let item = parse_one(indoc! {r#"
            {"uuid":"V4","typeName":"securenotes.SecureNote","title":"N","secureContents":{"sections":[{"title":"S","fields":[{"k":"string","t":"list","v":["a","b"]}]}]}}
        "#});

        let field = &item.sections[0].fields[0];
        assert_eq!(field.value, serde_json::json!(["a", "b"]));
        assert_eq!(field.text(), r#"["a","b"]"#);
    }

    #[test]
    fn section_field_null_dropped_empty_array_kept() {
        let item = parse_one(indoc! {r#"
            {"uuid":"V5","typeName":"securenotes.SecureNote","title":"N","secureContents":{"sections":[{"title":"S","fields":[{"k":"string","t":"nothing","v":null},{"k":"string","t":"list","v":[]}]}]}}
        "#});

        assert_eq!(item.sections[0].fields.len(), 1);
        assert_eq!(item.sections[0].fields[0].label, "list");
    }

    #[test]
    fn web_form_number_value() {
        let item = parse_one(indoc! {r#"
            {"uuid":"P1","typeName":"webforms.WebForm","title":"Site","secureContents":{"fields":[{"name":"pin","designation":"password","value":1234,"type":"P"}]}}
        "#});

        assert_eq!(item.fields[0].value, serde_json::json!(1234));
        assert_eq!(item.designated("password").as_deref(), Some("1234"));
    }

    #[test]
    fn web_form_boolean_value() {
        let item = parse_one(indoc! {r#"
            {"uuid":"P2","typeName":"webforms.WebForm","title":"Site","secureContents":{"fields":[{"name":"remember","value":true,"type":"C"}]}}
        "#});

        assert_eq!(item.fields[0].value, serde_json::json!(true));
        assert_eq!(item.fields[0].text(), "true");
    }

    #[test]
    fn web_form_object_value() {
        let item = parse_one(indoc! {r#"
            {"uuid":"P3","typeName":"webforms.WebForm","title":"Site","secureContents":{"fields":[{"name":"opts","value":{"a":1},"type":"T"}]}}
        "#});

        assert_eq!(item.fields[0].value, serde_json::json!({"a": 1}));
    }

    #[test]
    fn reads_password_history() {
        let item = parse_one(indoc! {r#"
            {"uuid":"H1","typeName":"webforms.WebForm","title":"Site","secureContents":{"passwordHistory":[{"value":"old1","time":1634666640},{"value":"old2","time":1634666650}]}}
        "#});

        assert_eq!(
            item.password_history,
            [
                ParsedHistoryEntry {
                    value: "old1".to_string(),
                    time: 1_634_666_640,
                },
                ParsedHistoryEntry {
                    value: "old2".to_string(),
                    time: 1_634_666_650,
                },
            ]
        );
        assert!(item.parse_notes.is_empty());
        assert!(!item.extra.contains_key("passwordHistory"));
    }

    #[test]
    fn malformed_history_entries_noted_without_values() {
        let item = parse_one(indoc! {r#"
            {"uuid":"H2","typeName":"webforms.WebForm","title":"Site","secureContents":{"passwordHistory":[{"value":"good","time":5},{"time":6},{"value":"secret-no-time"},{"value":"secret-float-time","time":1.5},{"value":"","time":7},"text"]}}
        "#});

        assert_eq!(item.password_history.len(), 1);
        assert_eq!(item.password_history[0].value, "good");
        assert_eq!(
            item.parse_notes,
            [
                "password history entry 2 has no value",
                "password history entry 3 has no time",
                "password history entry 4 has no time",
                "password history entry 5 has no value",
                "password history entry 6 has no value",
            ]
        );
        assert!(item.parse_notes.iter().all(|n| !n.contains("secret")));
    }

    #[test]
    fn history_that_is_not_a_list_noted() {
        let item = parse_one(indoc! {r#"
            {"uuid":"H3","typeName":"webforms.WebForm","title":"Site","secureContents":{"passwordHistory":"oops"}}
        "#});

        assert!(item.password_history.is_empty());
        assert_eq!(item.parse_notes, ["password history is not a list"]);
        assert!(!item.extra.contains_key("passwordHistory"));
    }

    #[test]
    fn web_form_array_value() {
        let item = parse_one(indoc! {r#"
            {"uuid":"P4","typeName":"webforms.WebForm","title":"Site","secureContents":{"fields":[{"name":"choices","value":["x","y"],"type":"T"}]}}
        "#});

        assert_eq!(item.fields[0].value, serde_json::json!(["x", "y"]));
        assert_eq!(item.fields[0].text(), r#"["x","y"]"#);
    }
}
