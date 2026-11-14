use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

/// Record separator that 1Password writes between JSON objects in a `.1pif`
/// export.
const RECORD_SEPARATOR: &str = "***5642bee8-a5ff-11dc-8314-0800200c9a66***";

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
}

#[derive(Debug, Clone)]
pub struct ParsedField {
    pub name: String,
    pub designation: Option<String>,
    pub value: String,
    pub field_type: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedSection {
    pub title: String,
    pub fields: Vec<ParsedSectionField>,
}

#[derive(Debug, Clone)]
pub struct ParsedSectionField {
    pub label: String,
    pub value: String,
    /// 1Password field kind, e.g. `concealed`, `string`, `email`.
    pub kind: Option<String>,
}

impl ParsedItem {
    /// Value of the first web-form field with the given `designation`.
    pub fn designated(&self, designation: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|f| f.designation.as_deref() == Some(designation))
            .map(|f| f.value.as_str())
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
    #[serde(rename = "secureContents", default)]
    secure_contents: RawSecureContents,
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
}

#[derive(Debug, Deserialize)]
struct RawField {
    #[serde(default)]
    name: String,
    #[serde(default)]
    designation: Option<String>,
    #[serde(default)]
    value: String,
    #[serde(rename = "type", default)]
    field_type: Option<String>,
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
            })
            .collect();

        // `passwords.Password` items keep the secret in `secureContents.password`
        // rather than a web-form field.
        if let Some(password) = sc.password
            && !password.is_empty()
        {
            fields.push(ParsedField {
                name: "password".to_string(),
                designation: Some("password".to_string()),
                value: password,
                field_type: Some("P".to_string()),
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
                        let value = json_value_to_string(f.value);
                        if value.is_empty() {
                            return None;
                        }
                        Some(ParsedSectionField {
                            label: f.label,
                            value,
                            kind: f.kind,
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

        ParsedItem {
            uuid: self.uuid,
            type_name: self.type_name,
            title: self.title,
            location: self.location.filter(|l| !l.is_empty()),
            trashed: self.trashed,
            notes: sc.notes_plain.filter(|n| !n.is_empty()),
            fields,
            sections,
        }
    }
}

fn json_value_to_string(value: serde_json::Value) -> String {
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
        assert_eq!(github.designated("username"), Some("me@example.com"));
        assert_eq!(github.designated("password"), Some("hunter2"));
        assert_eq!(github.location.as_deref(), Some("https://github.com"));
        assert_eq!(github.sections.len(), 1);
        // The empty-value field is dropped.
        assert_eq!(github.sections[0].fields.len(), 1);
        assert_eq!(
            github.sections[0].fields[0].kind.as_deref(),
            Some("concealed")
        );

        let wifi = &items[1];
        assert_eq!(wifi.designated("password"), Some("correcthorse"));
        assert_eq!(wifi.notes.as_deref(), Some("home network"));

        assert!(items[2].trashed);
    }
}
