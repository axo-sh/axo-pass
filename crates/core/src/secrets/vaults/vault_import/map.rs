use std::collections::HashSet;
use std::path::PathBuf;

use serde_json::Value;
use uuid::Uuid;

use super::onepif::{ParsedItem, is_blank, json_value_to_string};
use crate::secrets::vaults::{CATEGORY_LOGIN, FieldKind, MatchKind, TextField, Website};

/// Title of the section that holds the import bookkeeping credentials.
pub const IMPORT_SECTION: &str = "Imported from 1Password";
/// Key of the credential that holds the original `typeName`.
pub const TYPE_KEY: &str = "onepassword-type";

/// Title of a section that has none in the export.
const UNTITLED_SECTION: &str = "Section";
const NOTES_KEY: &str = "notes";
const USERNAME_KEY: &str = "username";
const PASSWORD_KEY: &str = "password";
pub(super) const FOLDER_TYPE: &str = "system.folder.Regular";
pub(super) const FOLDER_TYPE_PREFIX: &str = "system.folder.";
const OTP_PREFIX: &str = "otpauth://";

#[derive(Debug, Clone, Copy, Default)]
pub struct MapOptions {
    /// Plan trashed items. They are added and then deleted by the writer.
    pub include_trashed: bool,
}

/// Result of mapping parsed items. The writer applies it to a vault.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportPlan {
    pub items: Vec<PlannedItem>,
    pub folders: Vec<PlannedFolder>,
    /// Trashed items left out because `include_trashed` is unset.
    pub skipped_trashed: usize,
    /// Record uuids that an earlier record of the export already has. The
    /// repeated item gets a new id, so a re-import does not recognize it.
    pub repeated_uuids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PlannedFolder {
    /// 1Password folder uuid, which items refer to.
    pub uuid: String,
    pub title: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PlannedItem {
    /// Item key. Unique among the planned items. A collision with an item
    /// that is already in the vault is not checked here.
    pub key: String,
    pub title: String,
    /// Record uuid as written in the export.
    pub uuid: String,
    /// Vault item id, the record uuid. `None` if the uuid is not a uuid or an
    /// earlier record has it. The vault then gives the item a new id.
    pub id: Option<Uuid>,
    pub category: Option<&'static str>,
    /// Unix seconds.
    pub created_at: Option<i64>,
    /// Uuid of a planned folder.
    pub folder_uuid: Option<String>,
    pub trashed: bool,
    /// Tags from the export. Only used for the import report.
    pub tags: Vec<String>,
    /// Unix seconds. Only used for the import report.
    pub updated_at: Option<i64>,
    /// Credentials outside any section.
    pub credentials: Vec<PlannedCredential>,
    pub sections: Vec<PlannedSection>,
    /// Attachments, written as file credentials outside any section.
    pub files: Vec<PlannedFile>,
    pub autofill: PlannedAutofill,
}

/// An attachment to add to an item as a file credential. The MIME type is not
/// set, since readers fall back to the file name extension.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedFile {
    /// Credential key. Unique within the item.
    pub key: String,
    /// Credential title, the file name.
    pub title: String,
    /// File name stored in the file record.
    pub name: String,
    /// Path of the file in the export.
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PlannedSection {
    pub title: String,
    pub credentials: Vec<PlannedCredential>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PlannedCredential {
    /// Credential key. Unique within the item.
    pub key: String,
    pub title: String,
    pub kind: FieldKind,
    pub value: String,
    /// Previous values, oldest first. Only the autofill password credential
    /// has any. None equals `value`.
    pub history: Vec<PlannedHistory>,
}

/// A previous value of a credential.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedHistory {
    pub value: String,
    /// Unix seconds.
    pub time: i64,
}

/// Autofill data. Slots hold credential keys.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PlannedAutofill {
    pub websites: Vec<Website>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
}

/// Map parsed 1Password items to an import plan. Folder records become
/// folders. Every other record becomes an item.
pub fn map_items(items: &[ParsedItem], options: MapOptions) -> ImportPlan {
    let folders: Vec<PlannedFolder> = items
        .iter()
        .filter(|i| i.type_name == FOLDER_TYPE && !i.trashed && !i.title.is_empty())
        .map(|i| PlannedFolder {
            uuid: i.uuid.clone(),
            title: i.title.clone(),
        })
        .collect();

    let mut item_keys = KeyAllocator::default();
    let mut planned = Vec::new();
    let mut skipped_trashed = 0;
    let mut seen_ids = HashSet::new();
    let mut repeated_uuids = Vec::new();
    for item in items {
        if item.type_name.starts_with(FOLDER_TYPE_PREFIX) {
            continue;
        }
        if item.trashed && !options.include_trashed {
            skipped_trashed += 1;
            continue;
        }
        let title = if item.title.is_empty() {
            "Untitled"
        } else {
            item.title.as_str()
        };
        let key = item_keys.allocate(title);
        let folder_uuid = item
            .folder_uuid
            .clone()
            .filter(|uuid| folders.iter().any(|f| &f.uuid == uuid));
        let id = Uuid::parse_str(&item.uuid).ok();
        let id = match id {
            Some(id) if !seen_ids.insert(id) => {
                repeated_uuids.push(item.uuid.clone());
                None
            },
            other => other,
        };
        planned.push(map_item(item, id, key, title, folder_uuid));
    }

    ImportPlan {
        items: planned,
        folders,
        skipped_trashed,
        repeated_uuids,
    }
}

fn map_item(
    item: &ParsedItem,
    id: Option<Uuid>,
    key: String,
    title: &str,
    folder_uuid: Option<String>,
) -> PlannedItem {
    let mut keys = KeyAllocator::default();
    for reserved in [NOTES_KEY, TYPE_KEY] {
        keys.used.insert(reserved.to_string());
    }
    let mut autofill = PlannedAutofill::default();
    let mut credentials = Vec::new();

    for field in &item.fields {
        if is_blank(&field.value) {
            continue;
        }
        let designation = field.designation.as_deref();
        let slot = match designation {
            Some("username") if autofill.username.is_none() => Some(USERNAME_KEY),
            Some("password") if autofill.password.is_none() => Some(PASSWORD_KEY),
            _ => None,
        };
        let name = if field.name.is_empty() {
            designation.unwrap_or("field")
        } else {
            field.name.as_str()
        };
        if let Some(slot_key) = slot {
            let kind = if slot_key == PASSWORD_KEY {
                FieldKind::Confidential(TextField::default())
            } else {
                FieldKind::Text(TextField::default())
            };
            let key = keys.allocate(slot_key);
            if slot_key == PASSWORD_KEY {
                autofill.password = Some(key.clone());
            } else {
                autofill.username = Some(key.clone());
            }
            credentials.push(PlannedCredential {
                key,
                title: name.to_string(),
                kind,
                value: field.text(),
                history: Vec::new(),
            });
            continue;
        }
        let kind = if field.field_type.as_deref() == Some("P") {
            FieldKind::Confidential(TextField::default())
        } else {
            FieldKind::Text(TextField::default())
        };
        push_value(
            &mut keys,
            &mut credentials,
            &mut autofill,
            name,
            &field.value,
            kind,
        );
    }

    if let Some(slot_key) = &autofill.password
        && let Some(credential) = credentials.iter_mut().find(|c| &c.key == slot_key)
    {
        credential.history = planned_history(item, &credential.value);
    }

    let mut sections = Vec::new();
    for section in &item.sections {
        let mut section_credentials = Vec::new();
        for field in &section.fields {
            let kind = section_field_kind(field.kind.as_deref(), &field.value);
            let value = date_value(&kind, &field.value);
            push_value(
                &mut keys,
                &mut section_credentials,
                &mut autofill,
                &field.label,
                &value,
                kind,
            );
        }
        if !section_credentials.is_empty() {
            let title = if section.title.is_empty() {
                UNTITLED_SECTION
            } else {
                section.title.as_str()
            };
            sections.push(PlannedSection {
                title: title.to_string(),
                credentials: section_credentials,
            });
        }
    }

    let mut type_credentials = Vec::new();
    for (extra_key, value) in &item.extra {
        push_secret_value(&mut keys, &mut type_credentials, extra_key, value);
    }
    if !type_credentials.is_empty() {
        sections.push(PlannedSection {
            title: type_section_title(&item.type_name),
            credentials: type_credentials,
        });
    }

    let files = item
        .attachments
        .iter()
        .map(|path| {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            PlannedFile {
                key: keys.allocate(&name),
                title: name.clone(),
                name,
                path: path.clone(),
            }
        })
        .collect();

    if let Some(notes) = &item.notes {
        credentials.push(PlannedCredential {
            key: NOTES_KEY.to_string(),
            title: "Notes".to_string(),
            kind: FieldKind::Text(TextField {
                multiline: Some(true),
            }),
            value: notes.clone(),
            history: Vec::new(),
        });
    }

    autofill.websites = websites(item);

    if !item.type_name.is_empty() {
        sections.push(PlannedSection {
            title: IMPORT_SECTION.to_string(),
            credentials: vec![PlannedCredential {
                key: TYPE_KEY.to_string(),
                title: "1Password type".to_string(),
                kind: FieldKind::Text(TextField::default()),
                value: item.type_name.clone(),
                history: Vec::new(),
            }],
        });
    }

    let category =
        (autofill.username.is_some() || autofill.password.is_some()).then_some(CATEGORY_LOGIN);

    PlannedItem {
        key,
        title: title.to_string(),
        uuid: item.uuid.clone(),
        id,
        category,
        created_at: item.created_at,
        folder_uuid,
        trashed: item.trashed,
        tags: item.tags.clone(),
        updated_at: item.updated_at,
        credentials,
        sections,
        files,
        autofill,
    }
}

/// Whether the mapper fills the autofill password slot of `item`. Password
/// history has no other place to go.
pub(super) fn has_password_slot(item: &ParsedItem) -> bool {
    item.fields
        .iter()
        .any(|f| f.designation.as_deref() == Some("password") && !is_blank(&f.value))
}

/// History entries of `item`, oldest first. An entry equal to the `current`
/// password is left out.
fn planned_history(item: &ParsedItem, current: &str) -> Vec<PlannedHistory> {
    let mut history: Vec<PlannedHistory> = item
        .password_history
        .iter()
        .filter(|entry| entry.value != current)
        .map(|entry| PlannedHistory {
            value: entry.value.clone(),
            time: entry.time,
        })
        .collect();
    history.sort_by_key(|entry| entry.time);
    history
}

/// Whether `text` is an http or https URL.
pub(super) fn is_web_url(text: &str) -> bool {
    text.starts_with("http://") || text.starts_with("https://")
}

/// Websites from `URLs`, then `location` if it is an http or https URL.
fn websites(item: &ParsedItem) -> Vec<Website> {
    let mut urls: Vec<&str> = item.urls.iter().map(|u| u.url.as_str()).collect();
    if let Some(location) = item.location.as_deref()
        && is_web_url(location)
    {
        urls.push(location);
    }
    let mut seen = HashSet::new();
    urls.into_iter()
        .filter(|url| seen.insert(*url))
        .map(|url| Website::new(url, MatchKind::Domain))
        .collect()
}

/// Credential kind for a section field `k` value. A value that does not fit
/// the kind imports as text.
fn section_field_kind(kind: Option<&str>, value: &Value) -> FieldKind {
    let text = FieldKind::Text(TextField::default());
    let kind = kind.map(str::to_ascii_lowercase);
    match kind.as_deref() {
        Some("concealed") => FieldKind::Confidential(TextField::default()),
        Some("email") if value.is_string() => FieldKind::Email,
        Some("url") if value.is_string() => FieldKind::Url,
        Some("phone") if value.is_string() => FieldKind::Phone,
        Some("date") if value.is_i64() || value.is_u64() => FieldKind::Date,
        _ => text,
    }
}

/// Date value as `YYYY-MM-DD` in UTC. 1Password writes a date as Unix
/// seconds. The vault does not define a date format, so this is an
/// assumption. Other kinds and out-of-range values pass through.
fn date_value(kind: &FieldKind, value: &Value) -> Value {
    if *kind != FieldKind::Date {
        return value.clone();
    }
    value
        .as_i64()
        .and_then(|secs| jiff::Timestamp::from_second(secs).ok())
        .map(|ts| ts.to_zoned(jiff::tz::TimeZone::UTC).date().to_string())
        .map_or_else(|| value.clone(), Value::String)
}

/// Add a credential for `value`, or several for an object. A string that is
/// an `otpauth://` URL becomes a TOTP credential, and the first one fills the
/// TOTP slot.
fn push_value(
    keys: &mut KeyAllocator,
    out: &mut Vec<PlannedCredential>,
    autofill: &mut PlannedAutofill,
    title: &str,
    value: &Value,
    kind: FieldKind,
) {
    if is_blank(value) {
        return;
    }
    let title = if title.trim().is_empty() {
        blank_label_title(value)
    } else {
        title
    };
    if let Value::Object(map) = value {
        let kind = kind_for_sub_value(&kind);
        for (sub_key, sub_value) in map {
            push_value(
                keys,
                out,
                autofill,
                &format!("{title} {sub_key}"),
                sub_value,
                kind.clone(),
            );
        }
        return;
    }
    let text = json_value_to_string(value.clone());
    let kind = if text.starts_with(OTP_PREFIX) {
        FieldKind::Totp
    } else {
        kind
    };
    let key = keys.allocate(title);
    if kind == FieldKind::Totp && autofill.totp.is_none() {
        autofill.totp = Some(key.clone());
    }
    out.push(PlannedCredential {
        key,
        title: title.to_string(),
        kind,
        value: text,
        history: Vec::new(),
    });
}

/// Title for a field with a blank label. 1Password 7 writes a one-time
/// password with no label.
fn blank_label_title(value: &Value) -> &'static str {
    match value.as_str() {
        Some(text) if text.starts_with(OTP_PREFIX) => "One-time password",
        _ => "Field",
    }
}

/// Add a concealed credential for a `secureContents` key that has no known
/// meaning. An object is split into one credential per sub-key.
fn push_secret_value(
    keys: &mut KeyAllocator,
    out: &mut Vec<PlannedCredential>,
    title: &str,
    value: &Value,
) {
    if is_blank(value) {
        return;
    }
    if let Value::Object(map) = value {
        for (sub_key, sub_value) in map {
            push_secret_value(keys, out, &format!("{title} {sub_key}"), sub_value);
        }
        return;
    }
    out.push(PlannedCredential {
        key: keys.allocate(title),
        title: title.to_string(),
        kind: FieldKind::Confidential(TextField::default()),
        value: json_value_to_string(value.clone()),
        history: Vec::new(),
    });
}

/// Kind of an object sub-value. Typed kinds that only fit a whole value
/// become text.
fn kind_for_sub_value(kind: &FieldKind) -> FieldKind {
    match kind {
        FieldKind::Confidential(_) => kind.clone(),
        _ => FieldKind::Text(TextField::default()),
    }
}

/// Section title for keys of an item type, such as `CreditCard` for
/// `wallet.financial.CreditCard`.
fn type_section_title(type_name: &str) -> String {
    match type_name.rsplit('.').next() {
        Some(last) if !last.is_empty() => last.to_string(),
        _ => "Other".to_string(),
    }
}

/// Hands out unique keys that pass vault key validation.
#[derive(Default)]
struct KeyAllocator {
    used: HashSet<String>,
}

impl KeyAllocator {
    /// Key for `text`, with a numeric suffix if it is already used.
    fn allocate(&mut self, text: &str) -> String {
        let base = slug(text);
        let mut key = base.clone();
        let mut n = 2;
        while !self.used.insert(key.clone()) {
            key = format!("{base}-{n}");
            n += 1;
        }
        key
    }
}

/// Lowercase ASCII key from `text`. Other characters become `-`. The result
/// starts with a letter, ends with a letter or digit, and has at least three
/// characters.
fn slug(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    let mut out = out.trim_end_matches('-').to_string();
    if out.is_empty() {
        return "item".to_string();
    }
    if !out.starts_with(|c: char| c.is_ascii_lowercase()) {
        out = format!("item-{out}");
    }
    if out.len() < 3 {
        out.push_str("-item");
    }
    out
}

#[cfg(test)]
mod tests {
    use std::fs;

    use indoc::indoc;

    use super::*;
    use crate::secrets::vaults::storage::handle::validate_key;
    use crate::secrets::vaults::vault_import::parse_1pif;

    /// Plan the records of a `.1pif` file given as text.
    fn plan_with(records: &str, options: MapOptions) -> ImportPlan {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("data.1pif"), records).unwrap();
        map_items(&parse_1pif(dir.path()).unwrap(), options)
    }

    fn plan(records: &str) -> ImportPlan {
        plan_with(records, MapOptions::default())
    }

    fn credential<'a>(credentials: &'a [PlannedCredential], key: &str) -> &'a PlannedCredential {
        credentials
            .iter()
            .find(|c| c.key == key)
            .unwrap_or_else(|| panic!("no credential {key}"))
    }

    fn section<'a>(item: &'a PlannedItem, title: &str) -> &'a PlannedSection {
        item.sections
            .iter()
            .find(|s| s.title == title)
            .unwrap_or_else(|| panic!("no section {title}"))
    }

    const LOGIN: &str = indoc! {r#"
        {"uuid":"L1","typeName":"webforms.WebForm","title":"GitHub","location":"https://github.com","createdAt":1400000000,"secureContents":{"URLs":[{"label":"website","url":"https://github.com/login"}],"fields":[{"name":"login","designation":"username","value":"me","type":"T"},{"name":"pass","designation":"password","value":"hunter2","type":"P"}]}}
    "#};

    #[test]
    fn login_fills_autofill_slots() {
        let plan = plan(LOGIN);
        let item = &plan.items[0];

        assert_eq!(item.key, "github");
        assert_eq!(item.category, Some(CATEGORY_LOGIN));
        assert_eq!(item.created_at, Some(1_400_000_000));
        assert_eq!(item.autofill.username.as_deref(), Some("username"));
        assert_eq!(item.autofill.password.as_deref(), Some("password"));
        let password = credential(&item.credentials, "password");
        assert_eq!(password.title, "pass");
        assert_eq!(password.value, "hunter2");
        assert_eq!(password.kind, FieldKind::Confidential(TextField::default()));
        let username = credential(&item.credentials, "username");
        assert_eq!(username.kind, FieldKind::Text(TextField::default()));
    }

    #[test]
    fn urls_and_location_become_websites() {
        let plan = plan(LOGIN);

        let urls: Vec<&str> = plan.items[0]
            .autofill
            .websites
            .iter()
            .map(|w| w.url.as_str())
            .collect();
        assert_eq!(urls, ["https://github.com/login", "https://github.com"]);
    }

    #[test]
    fn duplicate_location_not_repeated() {
        let plan = plan(indoc! {r#"
            {"uuid":"L2","typeName":"webforms.WebForm","title":"Site","location":"https://a.example","secureContents":{"URLs":[{"label":"website","url":"https://a.example"}]}}
        "#});

        assert_eq!(plan.items[0].autofill.websites.len(), 1);
    }

    #[test]
    fn non_web_location_not_a_website() {
        let plan = plan(indoc! {r#"
            {"uuid":"L3","typeName":"wallet.computer.Router","title":"Router","location":"192.168.1.1","secureContents":{}}
        "#});

        assert!(plan.items[0].autofill.websites.is_empty());
    }

    #[test]
    fn otpauth_value_becomes_totp_slot() {
        let plan = plan(indoc! {r#"
            {"uuid":"O1","typeName":"webforms.WebForm","title":"Site","secureContents":{"sections":[{"title":"Security","fields":[{"k":"concealed","t":"one-time password","v":"otpauth://totp/x?secret=abc"}]}]}}
        "#});
        let item = &plan.items[0];

        assert_eq!(item.autofill.totp.as_deref(), Some("one-time-password"));
        let totp = credential(&section(item, "Security").credentials, "one-time-password");
        assert_eq!(totp.kind, FieldKind::Totp);
        assert_eq!(totp.value, "otpauth://totp/x?secret=abc");
    }

    #[test]
    fn blank_label_totp_titled_one_time_password() {
        let plan = plan(indoc! {r#"
            {"uuid":"O2","typeName":"webforms.WebForm","title":"Site","secureContents":{"sections":[{"title":"","fields":[{"k":"concealed","n":"TOTP_1","t":"","v":"otpauth://totp/x?secret=abc"}]}]}}
        "#});
        let item = &plan.items[0];

        let totp = credential(
            &section(item, UNTITLED_SECTION).credentials,
            "one-time-password",
        );
        assert_eq!(totp.title, "One-time password");
        assert_eq!(totp.kind, FieldKind::Totp);
        assert_eq!(item.autofill.totp.as_deref(), Some("one-time-password"));
    }

    #[test]
    fn blank_label_other_field_titled_field() {
        let plan = plan(indoc! {r#"
            {"uuid":"O3","typeName":"securenotes.SecureNote","title":"N","secureContents":{"sections":[{"title":"S","fields":[{"k":"string","t":"","v":"x"}]}]}}
        "#});
        let creds = &section(&plan.items[0], "S").credentials;

        assert_eq!(credential(creds, "field").title, "Field");
        assert_eq!(credential(creds, "field").value, "x");
    }

    #[test]
    fn typed_section_fields_use_matching_kinds() {
        let plan = plan(indoc! {r#"
            {"uuid":"K1","typeName":"securenotes.SecureNote","title":"N","secureContents":{"sections":[{"title":"S","fields":[{"k":"email","t":"mail","v":"a@b.example"},{"k":"URL","t":"home","v":"https://b.example"},{"k":"phone","t":"tel","v":"555"},{"k":"date","t":"born","v":86400},{"k":"concealed","t":"pin","v":"1234"},{"k":"cctype","t":"card type","v":"visa"}]}]}}
        "#});
        let creds = &section(&plan.items[0], "S").credentials;

        assert_eq!(credential(creds, "mail").kind, FieldKind::Email);
        assert_eq!(credential(creds, "home").kind, FieldKind::Url);
        assert_eq!(credential(creds, "tel").kind, FieldKind::Phone);
        assert_eq!(credential(creds, "born").kind, FieldKind::Date);
        assert_eq!(credential(creds, "born").value, "1970-01-02");
        assert_eq!(
            credential(creds, "pin").kind,
            FieldKind::Confidential(TextField::default())
        );
        assert_eq!(
            credential(creds, "card-type").kind,
            FieldKind::Text(TextField::default())
        );
    }

    #[test]
    fn month_year_number_imports_as_text() {
        let plan = plan(indoc! {r#"
            {"uuid":"M1","typeName":"securenotes.SecureNote","title":"N","secureContents":{"sections":[{"title":"S","fields":[{"k":"monthYear","t":"expires","v":203012}]}]}}
        "#});
        let creds = &section(&plan.items[0], "S").credentials;

        let expires = credential(creds, "expires");
        assert_eq!(expires.kind, FieldKind::Text(TextField::default()));
        assert_eq!(expires.value, "203012");
    }

    #[test]
    fn address_object_split_per_sub_key() {
        let plan = plan(indoc! {r#"
            {"uuid":"A1","typeName":"identities.Identity","title":"Me","secureContents":{"sections":[{"title":"Address","fields":[{"k":"address","t":"home","v":{"street":"1 Main","city":"Town"}}]}]}}
        "#});
        let creds = &section(&plan.items[0], "Address").credentials;

        assert_eq!(credential(creds, "home-city").title, "home city");
        assert_eq!(credential(creds, "home-city").value, "Town");
        assert_eq!(credential(creds, "home-street").value, "1 Main");
    }

    #[test]
    fn untitled_section_gets_placeholder_title() {
        let plan = plan(indoc! {r#"
            {"uuid":"U1","typeName":"securenotes.SecureNote","title":"N","secureContents":{"sections":[{"title":"","fields":[{"k":"string","t":"loose","v":"x"}]}]}}
        "#});
        let item = &plan.items[0];

        assert_eq!(
            credential(&section(item, UNTITLED_SECTION).credentials, "loose").value,
            "x"
        );
        assert!(item.credentials.iter().all(|c| c.key != "loose"));
    }

    #[test]
    fn unread_secure_contents_keys_become_concealed_credentials() {
        let plan = plan(indoc! {r#"
            {"uuid":"C1","typeName":"wallet.financial.CreditCard","title":"Card","secureContents":{"ccnum":"4111","expiry_yy":2030,"flags":["a","b"],"billing":{"zip":"123"}}}
        "#});
        let creds = &section(&plan.items[0], "CreditCard").credentials;
        let concealed = FieldKind::Confidential(TextField::default());

        assert_eq!(credential(creds, "ccnum").kind, concealed);
        assert_eq!(credential(creds, "ccnum").title, "ccnum");
        assert_eq!(credential(creds, "expiry-yy").value, "2030");
        assert_eq!(credential(creds, "flags").value, r#"["a","b"]"#);
        assert_eq!(credential(creds, "billing-zip").title, "billing zip");
        assert_eq!(credential(creds, "billing-zip").kind, concealed);
    }

    #[test]
    fn attachments_become_planned_files() {
        let dir = tempfile::tempdir().unwrap();
        let record = r#"{"uuid":"ABC123ABC123ABC123ABC123ABC123AB","typeName":"securenotes.SecureNote","title":"N","secureContents":{}}"#;
        fs::write(dir.path().join("data.1pif"), record).unwrap();
        let folder = dir
            .path()
            .join("attachments")
            .join("ABC123ABC123ABC123ABC123ABC123AB");
        fs::create_dir_all(&folder).unwrap();
        fs::write(folder.join("a b.pdf"), "1").unwrap();
        fs::write(folder.join("a-b.pdf"), "2").unwrap();

        let plan = map_items(&parse_1pif(dir.path()).unwrap(), MapOptions::default());
        let files = &plan.items[0].files;

        assert_eq!(files.len(), 2);
        assert_eq!(files[0].name, "a b.pdf");
        assert_eq!(files[0].title, "a b.pdf");
        assert_eq!(files[0].key, "a-b-pdf");
        assert_eq!(files[0].path, folder.join("a b.pdf"));
        assert_eq!(files[1].key, "a-b-pdf-2");
    }

    fn history_of(credential: &PlannedCredential) -> Vec<(&str, i64)> {
        credential
            .history
            .iter()
            .map(|h| (h.value.as_str(), h.time))
            .collect()
    }

    #[test]
    fn password_history_not_a_credential() {
        let plan = plan(indoc! {r#"
            {"uuid":"H1","typeName":"webforms.WebForm","title":"Site","secureContents":{"passwordHistory":[{"value":"old","time":1}],"ccnum":"4111"}}
        "#});
        let item = &plan.items[0];

        let keys: Vec<&str> = section(item, "WebForm")
            .credentials
            .iter()
            .map(|c| c.key.as_str())
            .collect();
        assert_eq!(keys, ["ccnum"]);
    }

    #[test]
    fn history_attached_to_password_slot_oldest_first() {
        let plan = plan(indoc! {r#"
            {"uuid":"H2","typeName":"webforms.WebForm","title":"Site","secureContents":{"fields":[{"name":"login","designation":"username","value":"me","type":"T"},{"name":"pass","designation":"password","value":"current","type":"P"}],"passwordHistory":[{"value":"third","time":30},{"value":"first","time":10},{"value":"second","time":20}]}}
        "#});
        let item = &plan.items[0];

        let password = credential(&item.credentials, "password");
        assert_eq!(
            history_of(password),
            [("first", 10), ("second", 20), ("third", 30)]
        );
        let username = credential(&item.credentials, "username");
        assert!(username.history.is_empty());
    }

    #[test]
    fn history_entry_equal_to_current_skipped() {
        let plan = plan(indoc! {r#"
            {"uuid":"H3","typeName":"webforms.WebForm","title":"Site","secureContents":{"fields":[{"name":"pass","designation":"password","value":"current","type":"P"}],"passwordHistory":[{"value":"old","time":10},{"value":"current","time":20}]}}
        "#});

        let password = credential(&plan.items[0].credentials, "password");
        assert_eq!(history_of(password), [("old", 10)]);
    }

    #[test]
    fn history_on_password_item_attached() {
        let plan = plan(indoc! {r#"
            {"uuid":"H4","typeName":"passwords.Password","title":"Wifi","secureContents":{"password":"current","passwordHistory":[{"value":"old","time":10}]}}
        "#});

        let password = credential(&plan.items[0].credentials, "password");
        assert_eq!(history_of(password), [("old", 10)]);
    }

    #[test]
    fn history_without_password_slot_not_planned() {
        let plan = plan(indoc! {r#"
            {"uuid":"H5","typeName":"webforms.WebForm","title":"Site","secureContents":{"fields":[{"name":"login","designation":"username","value":"me","type":"T"}],"passwordHistory":[{"value":"old","time":10}]}}
        "#});
        let item = &plan.items[0];

        assert!(item.credentials.iter().all(|c| c.history.is_empty()));
    }

    #[test]
    fn import_section_holds_type_only() {
        let plan = plan(LOGIN);
        let creds = &section(&plan.items[0], IMPORT_SECTION).credentials;

        assert_eq!(creds.len(), 1);
        assert_eq!(credential(creds, TYPE_KEY).value, "webforms.WebForm");
    }

    #[test]
    fn record_uuid_becomes_item_id() {
        let plan = plan(indoc! {r#"
            {"uuid":"5930154CFAB244FB920D5189DA0FAB9C","typeName":"securenotes.SecureNote","title":"N","secureContents":{}}
        "#});

        let expected = Uuid::parse_str("5930154cfab244fb920d5189da0fab9c").unwrap();
        assert_eq!(plan.items[0].id, Some(expected));
        assert_eq!(plan.items[0].uuid, "5930154CFAB244FB920D5189DA0FAB9C");
        assert!(plan.repeated_uuids.is_empty());
    }

    #[test]
    fn uuid_that_is_not_a_uuid_gives_no_id() {
        let plan = plan(LOGIN);

        assert_eq!(plan.items[0].id, None);
        assert!(plan.repeated_uuids.is_empty());
    }

    #[test]
    fn repeated_uuid_keeps_first_id_and_is_reported() {
        let plan = plan(indoc! {r#"
            {"uuid":"5930154CFAB244FB920D5189DA0FAB9C","typeName":"securenotes.SecureNote","title":"First","secureContents":{}}
            {"uuid":"5930154cfab244fb920d5189da0fab9c","typeName":"securenotes.SecureNote","title":"Second","secureContents":{}}
        "#});

        assert!(plan.items[0].id.is_some());
        assert_eq!(plan.items[1].id, None);
        assert_eq!(plan.repeated_uuids, ["5930154cfab244fb920d5189da0fab9c"]);
    }

    #[test]
    fn notes_become_multiline_credential() {
        let plan = plan(indoc! {r#"
            {"uuid":"N1","typeName":"securenotes.SecureNote","title":"N","secureContents":{"notesPlain":"line one\nline two"}}
        "#});
        let notes = credential(&plan.items[0].credentials, "notes");

        assert_eq!(
            notes.kind,
            FieldKind::Text(TextField {
                multiline: Some(true)
            })
        );
        assert_eq!(notes.value, "line one\nline two");
        assert_eq!(plan.items[0].category, None);
    }

    #[test]
    fn colliding_item_titles_get_suffix() {
        let plan = plan(indoc! {r#"
            {"uuid":"D1","typeName":"securenotes.SecureNote","title":"Same","secureContents":{}}
            {"uuid":"D2","typeName":"securenotes.SecureNote","title":"Same","secureContents":{}}
            {"uuid":"D3","typeName":"securenotes.SecureNote","title":"same","secureContents":{}}
        "#});

        let keys: Vec<&str> = plan.items.iter().map(|i| i.key.as_str()).collect();
        assert_eq!(keys, ["same", "same-2", "same-3"]);
    }

    #[test]
    fn colliding_credential_titles_get_suffix() {
        let plan = plan(indoc! {r#"
            {"uuid":"D4","typeName":"securenotes.SecureNote","title":"N","secureContents":{"sections":[{"title":"S","fields":[{"k":"string","t":"Code","v":"1"},{"k":"string","t":"code","v":"2"},{"k":"string","t":"notes","v":"3"}]}]}}
        "#});
        let creds = &section(&plan.items[0], "S").credentials;

        let keys: Vec<&str> = creds.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(keys, ["code", "code-2", "notes-2"]);
    }

    #[test]
    fn generated_keys_pass_validation() {
        let titles = [
            "",
            "a",
            "1Password",
            "日本語",
            "  Spaced  Out ",
            "-x-",
            "a_b",
        ];
        let mut keys = KeyAllocator::default();
        for title in titles {
            let key = keys.allocate(title);
            assert!(validate_key(&key), "{title:?} gave {key:?}");
        }
    }

    #[test]
    fn folders_become_folders_and_items_refer_to_them() {
        let plan = plan(indoc! {r#"
            {"uuid":"F1","typeName":"system.folder.Regular","title":"Work","secureContents":{}}
            {"uuid":"F2","typeName":"system.folder.SmartFolder","title":"Smart","secureContents":{}}
            {"uuid":"I1","typeName":"securenotes.SecureNote","title":"In folder","folderUuid":"F1","secureContents":{}}
            {"uuid":"I2","typeName":"securenotes.SecureNote","title":"Unknown folder","folderUuid":"F9","secureContents":{}}
        "#});

        assert_eq!(
            plan.folders,
            [PlannedFolder {
                uuid: "F1".to_string(),
                title: "Work".to_string()
            }]
        );
        assert_eq!(plan.items.len(), 2);
        assert_eq!(plan.items[0].folder_uuid.as_deref(), Some("F1"));
        assert_eq!(plan.items[1].folder_uuid, None);
    }

    #[test]
    fn trashed_items_skipped_by_default() {
        let records = indoc! {r#"
            {"uuid":"X1","typeName":"securenotes.SecureNote","title":"Old","trashed":true,"secureContents":{}}
            {"uuid":"X2","typeName":"securenotes.SecureNote","title":"New","secureContents":{}}
        "#};

        let skipped = plan(records);
        assert_eq!(skipped.items.len(), 1);
        assert_eq!(skipped.skipped_trashed, 1);

        let included = plan_with(
            records,
            MapOptions {
                include_trashed: true,
            },
        );
        assert_eq!(included.items.len(), 2);
        assert!(included.items[0].trashed);
        assert_eq!(included.skipped_trashed, 0);
    }

    #[test]
    fn tags_and_updated_time_kept_for_report() {
        let plan = plan(indoc! {r#"
            {"uuid":"R1","typeName":"securenotes.SecureNote","title":"N","updatedAt":1500000000,"openContents":{"tags":["work"]},"secureContents":{}}
        "#});

        assert_eq!(plan.items[0].tags, ["work"]);
        assert_eq!(plan.items[0].updated_at, Some(1_500_000_000));
    }

    #[test]
    fn web_form_number_value_imports_as_text() {
        let plan = plan(indoc! {r#"
            {"uuid":"W1","typeName":"webforms.WebForm","title":"Site","secureContents":{"fields":[{"name":"pin","designation":"password","value":1234,"type":"P"},{"name":"remember","value":true,"type":"C"}]}}
        "#});
        let item = &plan.items[0];

        assert_eq!(credential(&item.credentials, "password").value, "1234");
        assert_eq!(credential(&item.credentials, "remember").value, "true");
    }

    #[test]
    fn empty_title_gets_placeholder() {
        let plan = plan(indoc! {r#"
            {"uuid":"E1","typeName":"securenotes.SecureNote","title":"","secureContents":{}}
        "#});

        assert_eq!(plan.items[0].title, "Untitled");
        assert_eq!(plan.items[0].key, "untitled");
    }
}
