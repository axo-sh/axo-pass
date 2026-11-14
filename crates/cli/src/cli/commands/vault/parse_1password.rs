use std::path::PathBuf;

use axo_pass_core::secrets::vaults::vault_import::{ParsedItem, parse_1pif};
use clap::{Parser, ValueHint};
use clml::cprintln;

#[derive(Parser, Debug)]
pub struct VaultParse1passwordCommand {
    /// Path to the `.1pif` export directory or its `data.1pif` file
    #[arg(value_hint = ValueHint::AnyPath)]
    path: PathBuf,

    /// Include items that 1Password marked as trashed
    #[arg(long)]
    include_trashed: bool,
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
            print_item(item);
            shown += 1;
        }

        cprintln!(
            "\n<green>{shown}</green> item(s) shown, <yellow>{skipped_trashed}</yellow> trashed skipped, {} total",
            items.len()
        );
        Ok(())
    }
}

fn print_item(item: &ParsedItem) {
    let trashed = if item.trashed {
        " <red>(trashed)</red>"
    } else {
        ""
    };
    cprintln!("\n<blue,bold>{}</blue,bold>{trashed}", item.title);
    cprintln!("  <dim>type:</dim> {}", item.type_name);
    cprintln!("  <dim>uuid:</dim> {}", item.uuid);
    if let Some(location) = &item.location {
        cprintln!("  <dim>url:</dim>  {location}");
    }

    for field in &item.fields {
        let designation = field
            .designation
            .as_deref()
            .map(|d| format!(" [{d}]"))
            .unwrap_or_default();
        cprintln!(
            "  <cyan>{}</cyan>{designation}: {}",
            field.name,
            field.value
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
            cprintln!("    <cyan>{}</cyan>{kind}: {}", field.label, field.value);
        }
    }

    if let Some(notes) = &item.notes {
        cprintln!("  <dim>notes:</dim> {notes}");
    }
}
