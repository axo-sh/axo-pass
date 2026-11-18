use std::path::Path;

use thiserror::Error;

pub mod apple_csv;
pub mod map;
pub mod naming;
pub mod onepif;
pub mod report;
pub mod write;

pub use apple_csv::{AppleCsvError, parse_apple_csv};
pub use map::{
    ImportPlan, MapOptions, PlannedAutofill, PlannedCredential, PlannedFile, PlannedFolder,
    PlannedHistory, PlannedItem, PlannedSection, map_items,
};
pub use onepif::{
    OnePifError, ParsedField, ParsedHistoryEntry, ParsedItem, ParsedSection, ParsedSectionField,
    ParsedUrl, parse_1pif,
};
pub use report::{Dropped, dropped_data};
pub use write::{
    FileFailure, FileValues, ImportSummary, StagedFiles, existing_item_ids, stage_plan_files,
    write_plan,
};

/// Error of reading an item export of any supported format.
#[derive(Debug, Error)]
pub enum ExportError {
    #[error(transparent)]
    OnePif(#[from] OnePifError),

    #[error(transparent)]
    AppleCsv(#[from] AppleCsvError),
}

/// Whether `path` is an Apple Passwords CSV export. That is a file with the
/// `.csv` extension.
pub fn is_apple_csv(path: &Path) -> bool {
    path.is_file()
        && path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("csv"))
}

/// Parse an item export. A `.csv` file is read as an Apple Passwords export,
/// anything else as a 1Password `.1pif` export.
pub fn parse_export<P: AsRef<Path>>(path: P) -> Result<Vec<ParsedItem>, ExportError> {
    let path = path.as_ref();
    if is_apple_csv(path) {
        Ok(parse_apple_csv(path)?)
    } else {
        Ok(parse_1pif(path)?)
    }
}
