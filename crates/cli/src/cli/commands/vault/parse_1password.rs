use std::path::PathBuf;

use axo_pass_core::secrets::vaults::vault_import::{ParsedItem, parse_1pif};
use clap::{Parser, ValueHint};
use clml::cprintln;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

#[derive(Parser, Debug)]
pub struct VaultParse1passwordCommand {
    /// Path to the `.1pif` export directory or its `data.1pif` file
    #[arg(value_hint = ValueHint::AnyPath)]
    path: PathBuf,

    /// Include items that 1Password marked as trashed
    #[arg(long)]
    include_trashed: bool,

    /// Print concealed values instead of masking them
    #[arg(long)]
    show_concealed: bool,
}

impl VaultParse1passwordCommand {
    pub fn execute(&self) -> Result<(), String> {
        let items = parse_1pif(&self.path).map_err(|e| format!("Failed to parse 1pif: {e}"))?;

        let mut shown = 0;
        let mut skipped_trashed = 0;
        for item in &items {
            if item.trashed && !self.include_trashed {
                skipped_trashed += 1;
                continue;
            }
            print_item(item, self.show_concealed);
            shown += 1;
        }

        cprintln!(
            "\n<green>{shown}</green> item(s) shown, <yellow>{skipped_trashed}</yellow> trashed skipped, {} total",
            items.len()
        );
        Ok(())
    }
}

const MASK: &str = "********";

/// `value`, or a mask if it is concealed and `show_concealed` is unset.
fn display(value: String, concealed: bool, show_concealed: bool) -> String {
    if concealed && !show_concealed {
        MASK.to_string()
    } else {
        value
    }
}

/// Whether a value is a one-time password URL, which holds a secret.
fn is_otp(value: &str) -> bool {
    value.starts_with("otpauth://")
}

fn print_item(item: &ParsedItem, show_concealed: bool) {
    let trashed = if item.trashed {
        " <red>(trashed)</red>"
    } else {
        ""
    };
    cprintln!("\n<blue,bold>{}</blue,bold>{trashed}", item.title);
    cprintln!("  <dim>type:</dim> {}", item.type_name);
    cprintln!("  <dim>uuid:</dim> {}", item.uuid);
    if let Some(location) = &item.location
        && !item.urls.iter().any(|u| &u.url == location)
    {
        cprintln!("  <dim>url:</dim>  {location}");
    }
    for url in &item.urls {
        let label = if url.label.is_empty() {
            String::new()
        } else {
            format!(" <dim>({})</dim>", url.label)
        };
        cprintln!("  <dim>url:</dim>  {}{label}", url.url);
    }
    if let Some(folder) = &item.folder_uuid {
        cprintln!("  <dim>folder:</dim> {folder}");
    }
    if !item.tags.is_empty() {
        cprintln!("  <dim>tags:</dim> {}", item.tags.join(", "));
    }
    if let Some(at) = item.created_at {
        cprintln!("  <dim>created:</dim> {}", format_time(at));
    }
    if let Some(at) = item.updated_at {
        cprintln!("  <dim>updated:</dim> {}", format_time(at));
    }

    for field in &item.fields {
        let designation = field
            .designation
            .as_deref()
            .map(|d| format!(" [{d}]"))
            .unwrap_or_default();
        let text = field.text();
        let concealed = field.field_type.as_deref() == Some("P")
            || field.designation.as_deref() == Some("password")
            || is_otp(&text);
        cprintln!(
            "  <cyan>{}</cyan>{designation}: {}",
            field.name,
            display(text, concealed, show_concealed)
        );
    }

    for section in &item.sections {
        let title = if section.title.is_empty() {
            "(section)"
        } else {
            section.title.as_str()
        };
        cprintln!("  <magenta>{title}</magenta>");
        for field in &section.fields {
            let kind = field
                .kind
                .as_deref()
                .map(|k| format!(" <{k}>"))
                .unwrap_or_default();
            let text = field.text();
            let concealed = field
                .kind
                .as_deref()
                .is_some_and(|k| k.eq_ignore_ascii_case("concealed"))
                || is_otp(&text);
            cprintln!(
                "    <cyan>{}</cyan>{kind}: {}",
                field.label,
                display(text, concealed, show_concealed)
            );
        }
    }

    for (key, value) in &item.extra {
        let value = match value {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        // The import conceals every one of these values.
        let value = display(value, true, show_concealed);
        cprintln!("  <yellow>{key}</yellow> <dim>(other)</dim>: {value}");
    }

    for path in &item.attachments {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        cprintln!("  <dim>attachment:</dim> {name}");
    }

    if let Some(notes) = &item.notes {
        cprintln!("  <dim>notes:</dim> {notes}");
    }
}

/// Unix seconds as an RFC 3339 time in UTC, followed by the seconds.
fn format_time(secs: i64) -> String {
    OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|t| t.format(&Rfc3339).ok())
        .map_or_else(|| secs.to_string(), |t| format!("{t} ({secs})"))
}
