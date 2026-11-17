use std::fs;
use std::path::Path;

use thiserror::Error;

use super::onepif::{ParsedField, ParsedItem, ParsedUrl};

/// Title of the one-time password field of an imported item.
const OTP_TITLE: &str = "One-time password";

#[derive(Debug, Error)]
pub enum AppleCsvError {
    #[error("CSV path not found: {0}")]
    NotFound(String),

    #[error("failed to read CSV data: {0}")]
    Read(#[source] std::io::Error),

    #[error("the CSV file is not valid UTF-8")]
    NotUtf8,

    #[error("the CSV file is empty")]
    Empty,

    #[error("the CSV header has no {0} column, so this is not an Apple Passwords export")]
    MissingColumn(&'static str),

    #[error("a quoted value in the CSV file is not closed")]
    UnterminatedQuote,
}

/// Parse an Apple Passwords CSV export. The header row names the columns, in
/// any order and case. `Title` and `Password` are required. `URL`, `Username`,
/// `Notes`, and `OTPAuth` are optional. Other columns are ignored.
///
/// The export has no record ids, so items have an empty uuid and no type.
pub fn parse_apple_csv<P: AsRef<Path>>(path: P) -> Result<Vec<ParsedItem>, AppleCsvError> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            AppleCsvError::NotFound(path.display().to_string())
        } else {
            AppleCsvError::Read(e)
        }
    })?;
    let text = String::from_utf8(bytes).map_err(|_| AppleCsvError::NotUtf8)?;
    parse_apple_csv_str(&text)
}

fn parse_apple_csv_str(text: &str) -> Result<Vec<ParsedItem>, AppleCsvError> {
    let mut records = read_records(text.strip_prefix('\u{feff}').unwrap_or(text))?.into_iter();
    let header = records.next().ok_or(AppleCsvError::Empty)?;
    let columns = Columns::from_header(&header)?;
    Ok(records.filter_map(|row| columns.item(&row)).collect())
}

/// Column positions of the header row.
struct Columns {
    title: usize,
    password: usize,
    url: Option<usize>,
    username: Option<usize>,
    notes: Option<usize>,
    otp: Option<usize>,
}

impl Columns {
    fn from_header(header: &[String]) -> Result<Self, AppleCsvError> {
        let find = |name: &str| {
            header
                .iter()
                .position(|h| h.trim().eq_ignore_ascii_case(name))
        };
        Ok(Self {
            title: find("Title").ok_or(AppleCsvError::MissingColumn("Title"))?,
            password: find("Password").ok_or(AppleCsvError::MissingColumn("Password"))?,
            url: find("URL"),
            username: find("Username"),
            notes: find("Notes"),
            otp: find("OTPAuth"),
        })
    }

    /// Item of a data row, or `None` if every cell is blank.
    fn item(&self, row: &[String]) -> Option<ParsedItem> {
        let cell = |index: Option<usize>| {
            index
                .and_then(|i| row.get(i))
                .map(String::as_str)
                .filter(|v| !v.is_empty())
        };
        let title = cell(Some(self.title));
        let url = cell(self.url);
        let username = cell(self.username);
        let password = cell(Some(self.password));
        let notes = cell(self.notes);
        let otp = cell(self.otp);
        if [title, url, username, password, notes, otp]
            .iter()
            .all(Option::is_none)
        {
            return None;
        }

        let mut fields = Vec::new();
        if let Some(username) = username {
            fields.push(field("Username", Some("username"), username, None));
        }
        if let Some(password) = password {
            fields.push(field("Password", Some("password"), password, Some("P")));
        }
        if let Some(otp) = otp {
            fields.push(field(OTP_TITLE, None, otp, None));
        }

        Some(ParsedItem {
            uuid: String::new(),
            type_name: String::new(),
            title: title.or(url).unwrap_or_default().to_string(),
            location: None,
            trashed: false,
            notes: notes.map(str::to_string),
            fields,
            sections: Vec::new(),
            urls: url
                .map(|url| ParsedUrl {
                    label: "website".to_string(),
                    url: url.to_string(),
                })
                .into_iter()
                .collect(),
            folder_uuid: None,
            tags: Vec::new(),
            created_at: None,
            updated_at: None,
            extra: serde_json::Map::new(),
            attachments: Vec::new(),
            unread: serde_json::Map::new(),
            blank_fields: Vec::new(),
            password_history: Vec::new(),
            parse_notes: Vec::new(),
        })
    }
}

fn field(
    name: &str,
    designation: Option<&str>,
    value: &str,
    field_type: Option<&str>,
) -> ParsedField {
    ParsedField {
        name: name.to_string(),
        designation: designation.map(str::to_string),
        value: serde_json::Value::String(value.to_string()),
        field_type: field_type.map(str::to_string),
        extra: serde_json::Map::new(),
    }
}

/// Records of RFC 4180 CSV text. Quoted values may hold commas, line breaks,
/// and doubled quotes. Both `\n` and `\r\n` end a record. Records that hold a
/// single empty value, such as blank lines, are left out.
fn read_records(text: &str) -> Result<Vec<Vec<String>>, AppleCsvError> {
    let mut records = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut value = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') => {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    value.push('"');
                } else {
                    quoted = false;
                }
            },
            (true, c) => value.push(c),
            (false, '"') if value.is_empty() => quoted = true,
            (false, ',') => row.push(std::mem::take(&mut value)),
            (false, '\r') if chars.peek() == Some(&'\n') => {},
            (false, '\r' | '\n') => {
                row.push(std::mem::take(&mut value));
                push_record(&mut records, std::mem::take(&mut row));
            },
            (false, c) => value.push(c),
        }
    }
    if quoted {
        return Err(AppleCsvError::UnterminatedQuote);
    }
    if !value.is_empty() || !row.is_empty() {
        row.push(value);
        push_record(&mut records, row);
    }
    Ok(records)
}

fn push_record(records: &mut Vec<Vec<String>>, row: Vec<String>) {
    if row.len() == 1 && row[0].is_empty() {
        return;
    }
    records.push(row);
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "Title,URL,Username,Password,Notes,OTPAuth\n";

    fn parse(rows: &str) -> Vec<ParsedItem> {
        parse_apple_csv_str(&format!("{HEADER}{rows}")).unwrap()
    }

    #[test]
    fn row_becomes_login() {
        let items = parse("GitHub,https://github.com,me,hunter2,,\n");
        let item = &items[0];
        assert_eq!(item.title, "GitHub");
        assert_eq!(item.urls[0].url, "https://github.com");
        assert_eq!(item.designated("username").as_deref(), Some("me"));
        assert_eq!(item.designated("password").as_deref(), Some("hunter2"));
        assert_eq!(item.fields.len(), 2);
        assert!(item.notes.is_none());
    }

    #[test]
    fn otp_uri_becomes_field() {
        let items = parse("Site,,me,pw,,otpauth://totp/x?secret=abc\n");
        let otp = items[0]
            .fields
            .iter()
            .find(|f| f.name == OTP_TITLE)
            .unwrap();
        assert_eq!(otp.text(), "otpauth://totp/x?secret=abc");
    }

    #[test]
    fn quoted_values_keep_commas_quotes_and_line_breaks() {
        let items = parse("\"A, \"\"B\"\"\",,me,pw,\"line 1\r\nline 2\",\n");
        assert_eq!(items[0].title, "A, \"B\"");
        assert_eq!(items[0].notes.as_deref(), Some("line 1\r\nline 2"));
    }

    #[test]
    fn crlf_and_bom_accepted() {
        let text = format!(
            "\u{feff}{}",
            "Title,URL,Username,Password,Notes,OTPAuth\r\nA,,u,p,,\r\nB,,u,p,,\r\n"
        );
        let items = parse_apple_csv_str(&text).unwrap();
        let titles: Vec<&str> = items.iter().map(|i| i.title.as_str()).collect();
        assert_eq!(titles, ["A", "B"]);
    }

    #[test]
    fn export_without_notes_column_parses() {
        let text = "Title,URL,Username,Password,OTPAuth\nA,,u,p,otpauth://totp/x?secret=abc\n";
        let items = parse_apple_csv_str(text).unwrap();
        assert!(items[0].notes.is_none());
        assert_eq!(items[0].fields.len(), 3);
    }

    #[test]
    fn columns_matched_by_name() {
        let text = "password,TITLE,Username\npw,A,u\n";
        let items = parse_apple_csv_str(text).unwrap();
        assert_eq!(items[0].title, "A");
        assert_eq!(items[0].designated("password").as_deref(), Some("pw"));
    }

    #[test]
    fn blank_rows_skipped() {
        let items = parse("\n,,,,,\nA,,u,p,,\n");
        assert_eq!(items.len(), 1);
    }

    #[test]
    fn short_row_fills_missing_cells() {
        let items = parse("A,https://a.example\n");
        assert_eq!(items[0].urls.len(), 1);
        assert!(items[0].fields.is_empty());
    }

    #[test]
    fn title_falls_back_to_url() {
        let items = parse(",https://a.example,u,p,,\n");
        assert_eq!(items[0].title, "https://a.example");
    }

    #[test]
    fn missing_password_column_refused() {
        let err = parse_apple_csv_str("Title,URL\nA,b\n").unwrap_err();
        assert!(matches!(err, AppleCsvError::MissingColumn("Password")));
    }

    #[test]
    fn empty_file_refused() {
        assert!(matches!(
            parse_apple_csv_str("").unwrap_err(),
            AppleCsvError::Empty
        ));
    }

    #[test]
    fn unterminated_quote_refused() {
        let err = parse_apple_csv_str(&format!("{HEADER}\"A,,u,p,,\n")).unwrap_err();
        assert!(matches!(err, AppleCsvError::UnterminatedQuote));
    }
}
